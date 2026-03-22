use crate::{
    interface::cli::CliArgs,
    usecase::{
        runtime_session,
        startup::{StartupResources, prepare},
    },
};

pub async fn run(args: CliArgs, resources: StartupResources) -> anyhow::Result<()> {
    let prepared = prepare(args, resources).await?;
    runtime_session::run(prepared).await
}
