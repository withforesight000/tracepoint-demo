use tokio::sync::mpsc;

use crate::{
    gateway::{docker::DockerContainerRuntimeGateway, systemd::SystemdRuntimeGateway},
    usecase::{
        policy::{watch_container::ContainerRuntime, watch_systemd_unit::SystemdRuntime},
        port::RuntimeUpdate,
    },
};

pub trait ContainerMonitorSpawner {
    fn spawn_monitor(
        &self,
        name_or_id: String,
        all_processes: bool,
        tx: mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> tokio::task::JoinHandle<()>;
}

pub trait SystemdMonitorSpawner {
    fn spawn_monitor(
        &self,
        unit_name: String,
        tx: mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> tokio::task::JoinHandle<()>;
}

impl ContainerMonitorSpawner for DockerContainerRuntimeGateway {
    fn spawn_monitor(
        &self,
        name_or_id: String,
        all_processes: bool,
        tx: mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> tokio::task::JoinHandle<()> {
        DockerContainerRuntimeGateway::spawn_monitor(self, name_or_id, all_processes, tx, index)
    }
}

impl SystemdMonitorSpawner for SystemdRuntimeGateway {
    fn spawn_monitor(
        &self,
        unit_name: String,
        tx: mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> tokio::task::JoinHandle<()> {
        SystemdRuntimeGateway::spawn_monitor(self, unit_name, tx, index)
    }
}

pub fn spawn_monitors<C, S>(
    container_runtime: Option<&C>,
    container_runtimes: &[ContainerRuntime],
    systemd_runtime: Option<&S>,
    systemd_runtimes: &[SystemdRuntime],
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>>
where
    C: ContainerMonitorSpawner + ?Sized,
    S: SystemdMonitorSpawner + ?Sized,
{
    let mut monitor_handles = Vec::new();

    if let Some(container_runtime) = container_runtime {
        monitor_handles.extend(
            container_runtimes
                .iter()
                .enumerate()
                .map(|(index, runtime)| {
                    container_runtime.spawn_monitor(
                        runtime.name_or_id.clone(),
                        runtime.all_processes,
                        update_tx.clone(),
                        index,
                    )
                }),
        );
    }

    if let Some(systemd_runtime) = systemd_runtime {
        monitor_handles.extend(systemd_runtimes.iter().enumerate().map(|(index, runtime)| {
            systemd_runtime.spawn_monitor(runtime.unit_name.clone(), update_tx.clone(), index)
        }));
    }

    monitor_handles
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    struct FakeContainerSpawner {
        calls: Arc<Mutex<Vec<(String, bool, usize)>>>,
    }

    impl ContainerMonitorSpawner for FakeContainerSpawner {
        fn spawn_monitor(
            &self,
            name_or_id: String,
            all_processes: bool,
            _tx: mpsc::UnboundedSender<RuntimeUpdate>,
            index: usize,
        ) -> tokio::task::JoinHandle<()> {
            self.calls
                .lock()
                .unwrap()
                .push((name_or_id, all_processes, index));
            tokio::spawn(async {})
        }
    }

    #[derive(Default)]
    struct FakeSystemdSpawner {
        calls: Arc<Mutex<Vec<(String, usize)>>>,
    }

    impl SystemdMonitorSpawner for FakeSystemdSpawner {
        fn spawn_monitor(
            &self,
            unit_name: String,
            _tx: mpsc::UnboundedSender<RuntimeUpdate>,
            index: usize,
        ) -> tokio::task::JoinHandle<()> {
            self.calls.lock().unwrap().push((unit_name, index));
            tokio::spawn(async {})
        }
    }

    #[tokio::test]
    async fn spawn_monitors_collects_container_and_systemd_handles() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let container_runtime = FakeContainerSpawner::default();
        let systemd_runtime = FakeSystemdSpawner::default();

        let handles = spawn_monitors(
            Some(&container_runtime),
            &[ContainerRuntime {
                cgroup_port: Arc::new(crate::gateway::procfs::ProcfsCgroupPort),
                runtime: Arc::new(crate::test_support::NoopContainerRuntimePort),
                name_or_id: "web".to_string(),
                watch_children: true,
                all_processes: false,
                flags: 0x1,
                seeded_pids: Vec::new(),
                current_pid: Some(10),
            }],
            Some(&systemd_runtime),
            &[SystemdRuntime {
                runtime: Arc::new(crate::test_support::NoopSystemdRuntimePort),
                unit_name: "sshd.service".to_string(),
                watch_children: false,
                all_processes: false,
                seeded_pids: Vec::new(),
                flags: 0x2,
                current_pid: Some(20),
                current_running: true,
                current_active_state: Some("active".to_string()),
                current_sub_state: Some("running".to_string()),
            }],
            &tx,
        );

        assert_eq!(handles.len(), 2);
        assert_eq!(
            container_runtime.calls.lock().unwrap().clone(),
            vec![("web".to_string(), false, 0)]
        );
        assert_eq!(
            systemd_runtime.calls.lock().unwrap().clone(),
            vec![("sshd.service".to_string(), 0)]
        );
    }
}
