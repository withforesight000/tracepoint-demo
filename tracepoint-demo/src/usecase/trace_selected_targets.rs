use tokio::sync::mpsc;

use aya::Ebpf;
use bollard::Docker;

use crate::{
    interface::{cli::CliArgs, runtime_loop},
    usecase::{
        support::{runtime_update::RuntimeUpdate, startup::prepare},
        watch_container, watch_systemd_unit,
    },
};

pub struct StartupResources {
    pub ebpf: Ebpf,
    pub docker: Option<Docker>,
    pub systemd_conn: Option<zbus::Connection>,
}

pub async fn run(args: CliArgs, resources: StartupResources) -> anyhow::Result<()> {
    let mut prepared = prepare(args, resources).await?;

    let (update_tx, mut update_rx) = mpsc::unbounded_channel::<RuntimeUpdate>();
    let mut monitor_handles = Vec::new();
    monitor_handles.extend(watch_container::spawn_monitors(
        &prepared.state.container_runtimes,
        &update_tx,
    ));
    monitor_handles.extend(watch_systemd_unit::spawn_monitors(
        &prepared.state.systemd_runtimes,
        &update_tx,
    ));
    drop(update_tx);

    runtime_loop::run(
        &mut prepared.ebpf,
        &mut prepared.state,
        &mut update_rx,
        &prepared.tty_inputs,
        prepared.watch_children,
        &prepared.target_descriptions,
        !monitor_handles.is_empty(),
    )
    .await
}
