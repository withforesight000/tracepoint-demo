use clap::Parser;

use crate::{
    gateway::ebpf::load_tracepoint_demo_ebpf,
    interface::{cli::CliArgs, docker, systemd},
    usecase::trace_selected_targets::{self, StartupResources},
};

pub async fn run() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let docker = docker::connect_if_needed(&args.container)?;
    let systemd_conn = systemd::connect_if_needed(&args.systemd_unit).await?;
    let ebpf = load_tracepoint_demo_ebpf()?;

    trace_selected_targets::run(
        args,
        StartupResources {
            ebpf,
            docker,
            systemd_conn,
        },
    )
    .await
}
