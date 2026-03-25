use clap::Parser;

use crate::{
    gateway::{ebpf::load_tracepoint_demo_ebpf, procfs::ProcfsCgroupPort},
    infra::{
        docker,
        presentation::{cli::CliArgs, output::ConsoleStatusReporter, wait::SignalAwareWaitPort},
        runtime_loop, startup, systemd,
    },
    usecase::policy::trace_selected_targets,
};

pub async fn run() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let container_runtime = docker::connect_if_needed(&args.container)?;
    let systemd_runtime = systemd::connect_if_needed(&args.systemd_unit).await?;
    let request = args.into_request();
    let ebpf = load_tracepoint_demo_ebpf()?;
    let cgroup_port = std::sync::Arc::new(ProcfsCgroupPort);
    let mut reporter = ConsoleStatusReporter;
    let mut wait_port = SignalAwareWaitPort;

    let mut prepared = startup::prepare_prepared_app(
        request,
        startup::StartupResources {
            ebpf,
            cgroup_port,
            container_runtime,
            systemd_runtime,
        },
        &mut reporter,
        &mut wait_port,
    )
    .await?;

    let (update_tx, mut update_rx) = tokio::sync::mpsc::unbounded_channel();
    let has_monitors =
        !trace_selected_targets::spawn_monitors(&prepared.state, &update_tx).is_empty();
    drop(update_tx);

    runtime_loop::run(
        &mut prepared.ebpf,
        &mut prepared.state,
        &mut update_rx,
        &prepared.tty_inputs,
        prepared.watch_children,
        &prepared.target_descriptions,
        has_monitors,
    )
    .await
}
