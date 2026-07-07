#[tokio::main]
async fn main() -> anyhow::Result<()> {
    judo::cli::run().await
}
