use socks5_impl::{
    client,
    protocol::{Address, Reply, UserKey},
    server::{auth, ClientConnection, IncomingConnection, Server},
};
use std::{
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc},
};
use tokio::{
    io::{self},
    net::TcpStream,
    task::JoinHandle,
};
use url::Url;

pub async fn create_local_route(to_proxy: Url) -> anyhow::Result<ProxyRoute> {
    let listen_addr = "127.0.0.1:0".parse()?;
    create_route(listen_addr, to_proxy).await
}

pub async fn create_route(listen_addr: SocketAddr, to_proxy: Url) -> anyhow::Result<ProxyRoute> {
    let exiting_flag = Arc::new(AtomicBool::new(false));
    let auth = Arc::new(auth::NoAuth);

    let server = Server::bind(listen_addr, auth).await?;
    let listen_addr = server.local_addr()?;

    let handle = {
        let exiting_flag = exiting_flag.clone();
        tokio::spawn(async move {
            while let Ok((conn, _)) = server.accept().await {
                if exiting_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let next_proxy = to_proxy.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle(conn, Some(next_proxy)).await {
                        log::trace!("{err}");
                    }
                });
            }
        })
    };

    Ok(ProxyRoute {
        exiting_flag,
        handle,
        listen_addr,
    })
}

#[derive(Debug)]
pub struct ProxyRoute {
    exiting_flag: Arc<AtomicBool>,
    handle: JoinHandle<()>,
    listen_addr: SocketAddr,
}

impl ProxyRoute {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn listen_proxy_url(&self) -> Url {
        format!("socks5://{}", self.listen_addr).parse().unwrap()
    }

    pub fn close(&mut self) {
        self.exiting_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle.abort();
    }
}

impl Drop for ProxyRoute {
    fn drop(&mut self) {
        self.close();
    }
}

async fn handle<S>(conn: IncomingConnection<S>, next_proxy: Option<Url>) -> socks5_impl::Result<()>
where
    S: Send + Sync + 'static,
{
    let (conn, res) = conn.authenticate().await?;

    use as_any::AsAny;
    if let Some(res) = res.as_any().downcast_ref::<std::io::Result<bool>>() {
        let res = *res.as_ref().map_err(|err| err.to_string())?;
        if !res {
            log::info!("authentication failed");
            return Ok(());
        }
    }

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, _) => {
            let mut conn = associate
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            use Address::*;

            let target = match next_proxy {
                Some(next_proxy) => {
                    let next_proxy_addr = format!(
                        "{}:{}",
                        next_proxy.host_str().unwrap(),
                        next_proxy.port_or_known_default().unwrap()
                    );

                    let auth = match (next_proxy.username(), next_proxy.password()) {
                        (username, Some(password)) => Some(UserKey::new(username, password)),
                        (_, _) => None,
                    };

                    let mut next_proxy = TcpStream::connect(next_proxy_addr).await?;

                    let addr = client::connect(&mut next_proxy, addr, auth).await?;
                    log::trace!("connected: {addr}");
                    Ok(next_proxy)
                }
                None => match addr {
                    DomainAddress(domain, port) => TcpStream::connect((domain, port)).await,
                    SocketAddress(addr) => TcpStream::connect(addr).await,
                },
            };

            if let Ok(mut target) = target {
                let mut conn = connect
                    .reply(Reply::Succeeded, Address::unspecified())
                    .await?;
                log::trace!("{} -> {}", conn.peer_addr()?, target.peer_addr()?);
                io::copy_bidirectional(&mut target, &mut conn).await?;
            } else {
                let mut conn = connect
                    .reply(Reply::HostUnreachable, Address::unspecified())
                    .await?;
                conn.shutdown().await?;
            }
        }
    }

    Ok(())
}
