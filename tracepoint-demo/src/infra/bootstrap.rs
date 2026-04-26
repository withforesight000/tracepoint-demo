use clap::Parser;

use crate::{
    gateway::{ebpf::load_tracepoint_demo_ebpf, procfs::ProcfsCgroupPort},
    infra::{
        docker,
        presentation::{cli::CliArgs, output::ConsoleStatusReporter, wait::SignalAwareWaitPort},
        runtime_loop, runtime_monitors, startup, systemd,
    },
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

    // Use an unbounded channel here instead of `mpsc::channel(capacity)` because these updates
    // are small status notifications from container/systemd monitor tasks, not a high-volume data
    // stream.
    //
    // The monitor tasks send updates with synchronous `tx.send(...)` calls, so using a bounded
    // channel would force us to choose a capacity and decide what to do when the buffer fills
    // up. In this code path we do not want monitor tasks to block on channel backpressure or to
    // start dropping updates just because an arbitrary bound was hit.
    //
    // The runtime loop has a single consumer and is already responsible for processing these
    // updates in order, so an unbounded `mpsc` is the simplest fit.
    let (update_tx, mut update_rx) = tokio::sync::mpsc::unbounded_channel();
    let has_monitors = !runtime_monitors::spawn_monitors(
        prepared.container_runtime.as_deref(),
        &prepared.state.container_runtimes,
        prepared.systemd_runtime.as_deref(),
        &prepared.state.systemd_runtimes,
        &update_tx,
    )
    .is_empty();
    drop(update_tx);

    runtime_loop::run(
        &mut prepared.ebpf,
        &mut prepared.watch_pids,
        &mut prepared.state,
        &mut update_rx,
        runtime_loop::RuntimeLoopConfig {
            startup_watch_pid_groups: &prepared.startup_watch_pid_groups,
            watch_children: prepared.watch_children,
            all_container_processes: prepared.all_container_processes,
            all_systemd_processes: prepared.all_systemd_processes,
            has_monitors,
        },
    )
    .await
}
