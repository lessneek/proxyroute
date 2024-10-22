use proxyroute::proxyroute;
use url::Url;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    println!("localroute");

    let mut route =
        proxyroute::create_local_route(Url::parse("socks5://user:passwd@127.0.0.2:1080").unwrap())
            .await?;

    println!(
        "Local route created: {}. Press enter to exit...",
        route.listen_proxy_url()
    );

    let mut input = String::new();

    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    route.close();

    Ok(())
}
