use tokio::sync::mpsc;

use crate::usecase::{
    orchestration::state::AppState,
    policy::{watch_container, watch_systemd_unit},
    port::RuntimeUpdate,
};

pub struct TraceRequest {
    pub pids: Vec<u32>,
    pub tty_inputs: Vec<String>,
    pub containers: Vec<String>,
    pub all_container_processes: bool,
    pub systemd_units: Vec<String>,
    pub all_systemd_processes: bool,
    pub watch_children: bool,
}

pub fn spawn_monitors(
    state: &AppState,
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut monitor_handles = Vec::new();
    monitor_handles.extend(watch_container::spawn_monitors(
        &state.container_runtimes,
        update_tx,
    ));
    monitor_handles.extend(watch_systemd_unit::spawn_monitors(
        &state.systemd_runtimes,
        update_tx,
    ));
    monitor_handles
}
