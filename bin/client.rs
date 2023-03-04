use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Host to listen on
    #[clap(long, default_value = "0.0.0.0:1080")]
    host: String,
    /// Server to connect to
    #[clap(long, short)]
    server: String,
    /// Private key
    #[clap(long)]
    private_key: String,
    /// Public key
    #[clap(long)]
    public_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    postcard::client::start_client(
        &args.host,
        &args.server,
        &args.private_key,
        &args.public_key,
    )
    .await?;

    Ok(())
}
