use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Host to listen on
    #[clap(long, default_value = "0.0.0.0:8080")]
    host: String,
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

    postcard::server::start_server(&args.host, &args.private_key, &args.public_key).await?;

    Ok(())
}
