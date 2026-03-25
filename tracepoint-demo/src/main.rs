use tracepoint_demo::infra::bootstrap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    bootstrap::run().await
}
