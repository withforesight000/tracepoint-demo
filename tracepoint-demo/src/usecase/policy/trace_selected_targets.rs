use tokio::sync::mpsc;

use crate::usecase::{
    orchestration::state::AppState,
    policy::{
        watch_container::{self, ContainerRuntime},
        watch_systemd_unit::{self, SystemdRuntime},
    },
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
    spawn_monitors_for_runtimes(&state.container_runtimes, &state.systemd_runtimes, update_tx)
}

fn spawn_monitors_for_runtimes(
    container_runtimes: &[ContainerRuntime],
    systemd_runtimes: &[SystemdRuntime],
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut monitor_handles = Vec::new();
    monitor_handles.extend(watch_container::spawn_monitors(container_runtimes, update_tx));
    monitor_handles.extend(watch_systemd_unit::spawn_monitors(systemd_runtimes, update_tx));
    monitor_handles
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        gateway::procfs::ProcfsCgroupPort,
        usecase::port::{
            BoxFuture, ContainerRuntimePort, RuntimeUpdate, SystemdRuntimePort,
            SystemdUnitRuntimeStatus,
        },
    };

    struct FakeContainerRuntimePort;

    impl ContainerRuntimePort for FakeContainerRuntimePort {
        fn query_main_pid<'a>(
            &'a self,
            _name_or_id: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<Option<u32>>> {
            Box::pin(async { Ok(None) })
        }

        fn spawn_monitor(
            &self,
            _name_or_id: String,
            _tx: mpsc::UnboundedSender<RuntimeUpdate>,
            _index: usize,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async {})
        }
    }

    struct FakeSystemdRuntimePort;

    impl SystemdRuntimePort for FakeSystemdRuntimePort {
        fn current_status<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
            Box::pin(async { Ok(SystemdUnitRuntimeStatus::missing()) })
        }

        fn unit_pids<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<Vec<u32>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn spawn_monitor(
            &self,
            _unit_name: String,
            _tx: mpsc::UnboundedSender<RuntimeUpdate>,
            _index: usize,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async {})
        }
    }

    #[tokio::test]
    async fn spawn_monitors_for_runtimes_returns_empty_when_no_runtimes_exist() {
        let (tx, _rx) = mpsc::unbounded_channel();

        let handles = spawn_monitors_for_runtimes(&[], &[], &tx);

        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn spawn_monitors_for_runtimes_collects_container_and_systemd_handles() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let container_runtimes = vec![ContainerRuntime {
            cgroup_port: Arc::new(ProcfsCgroupPort),
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: true,
            all_processes: false,
            flags: 0x1,
            current_pid: Some(10),
        }];
        let systemd_runtimes = vec![SystemdRuntime {
            runtime: Arc::new(FakeSystemdRuntimePort),
            unit_name: "sshd.service".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x2,
            current_pid: Some(20),
            current_running: true,
        }];

        let handles = spawn_monitors_for_runtimes(&container_runtimes, &systemd_runtimes, &tx);

        assert_eq!(handles.len(), 2);
    }
}
