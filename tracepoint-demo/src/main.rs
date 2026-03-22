use tracepoint_demo::interface::app_builder;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    app_builder::run().await
}
