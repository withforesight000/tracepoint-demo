use aya::Ebpf;

use crate::gateway::ebpf::EbpfProcessSeedPort;
use crate::infra::presentation::runtime_update_dispatch::{
    RuntimeUpdateHandler, handle_runtime_update,
};
use crate::usecase::{
    orchestration::{
        state::AppState,
        watch_roots::{collect_watch_roots, sync_watch_pids},
    },
    policy::{
        watch_container::{ContainerRuntime, apply_container_runtime_update},
        watch_systemd_unit::{SystemdRuntime, apply_systemd_runtime_update},
    },
    port::{ProcessSeedPort, RuntimeUpdate, StatusReporter},
};

trait RuntimeUpdateBackend {
    fn container_runtime_mut(&mut self, index: usize) -> anyhow::Result<&mut ContainerRuntime>;

    fn systemd_runtime_mut(&mut self, index: usize) -> anyhow::Result<&mut SystemdRuntime>;

    fn refresh_watch_pids(&mut self) -> anyhow::Result<()>;
}

struct AppRuntimeUpdateBackend<'a> {
    state: &'a mut AppState,
}

impl RuntimeUpdateBackend for AppRuntimeUpdateBackend<'_> {
    fn container_runtime_mut(&mut self, index: usize) -> anyhow::Result<&mut ContainerRuntime> {
        self.state
            .container_runtimes
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("container runtime index {index} out of range"))
    }

    fn systemd_runtime_mut(&mut self, index: usize) -> anyhow::Result<&mut SystemdRuntime> {
        self.state
            .systemd_runtimes
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("systemd runtime index {index} out of range"))
    }

    fn refresh_watch_pids(&mut self) -> anyhow::Result<()> {
        let desired_roots = collect_watch_roots(
            &self.state.static_watch_roots,
            &self.state.container_runtimes,
            &self.state.systemd_runtimes,
        );
        sync_watch_pids(
            &mut self.state.watch_pids,
            &mut self.state.current_watch_roots,
            &desired_roots,
        )?;
        Ok(())
    }
}

struct StateRuntimeUpdateHandler<'a, TReporter: StatusReporter + ?Sized> {
    process_seed: &'a mut dyn ProcessSeedPort,
    backend: &'a mut dyn RuntimeUpdateBackend,
    reporter: &'a mut TReporter,
}

impl<TReporter: StatusReporter + ?Sized> RuntimeUpdateHandler
    for StateRuntimeUpdateHandler<'_, TReporter>
{
    async fn apply_container_pid(&mut self, index: usize, pid: Option<u32>) -> anyhow::Result<()> {
        let runtime = self.backend.container_runtime_mut(index)?;
        apply_container_runtime_update(self.process_seed, self.reporter, runtime, pid).await?;
        self.backend.refresh_watch_pids()
    }

    async fn apply_systemd_status(
        &mut self,
        index: usize,
        pid: Option<u32>,
        running: bool,
    ) -> anyhow::Result<()> {
        let runtime = self.backend.systemd_runtime_mut(index)?;
        apply_systemd_runtime_update(self.process_seed, self.reporter, runtime, pid, running)
            .await?;
        self.backend.refresh_watch_pids()
    }
}

pub async fn handle_runtime_update_with_state<TReporter: StatusReporter + ?Sized>(
    ebpf: &mut Ebpf,
    state: &mut AppState,
    maybe_update: Option<RuntimeUpdate>,
    reporter: &mut TReporter,
) -> anyhow::Result<bool> {
    let mut process_seed = EbpfProcessSeedPort::new(ebpf);
    let mut backend = AppRuntimeUpdateBackend { state };
    let mut handler = StateRuntimeUpdateHandler {
        process_seed: &mut process_seed,
        backend: &mut backend,
        reporter,
    };
    handle_runtime_update(&mut handler, maybe_update).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        gateway::procfs::ProcfsCgroupPort,
        usecase::{
            policy::{watch_container::ContainerRuntime, watch_systemd_unit::SystemdRuntime},
            port::{
                BoxFuture, ContainerRuntimePort, RuntimeUpdate, SystemdRuntimePort,
                SystemdUnitRuntimeStatus,
            },
        },
    };

    #[derive(Default)]
    struct FakeProcessSeedPort {
        direct_calls: Vec<(Vec<u32>, u32)>,
    }

    impl ProcessSeedPort for FakeProcessSeedPort {
        fn seed_from_task_iter(
            &mut self,
            _pid_roots: &[u32],
            _tty_filters: &std::collections::HashSet<String>,
            _watch_flags: u32,
        ) -> anyhow::Result<Vec<u32>> {
            Ok(Vec::new())
        }

        fn seed_direct(&mut self, pids: &[u32], flags: u32) -> anyhow::Result<()> {
            self.direct_calls.push((pids.to_vec(), flags));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeReporter {
        warnings: Vec<String>,
    }

    impl StatusReporter for FakeReporter {
        fn info(&mut self, _message: String) {}

        fn warn(&mut self, message: String) {
            self.warnings.push(message);
        }
    }

    struct FakeBackend {
        container_runtimes: Vec<ContainerRuntime>,
        systemd_runtimes: Vec<SystemdRuntime>,
        refresh_count: usize,
        refresh_error: Option<&'static str>,
    }

    impl RuntimeUpdateBackend for FakeBackend {
        fn container_runtime_mut(&mut self, index: usize) -> anyhow::Result<&mut ContainerRuntime> {
            self.container_runtimes
                .get_mut(index)
                .ok_or_else(|| anyhow::anyhow!("container runtime index {index} out of range"))
        }

        fn systemd_runtime_mut(&mut self, index: usize) -> anyhow::Result<&mut SystemdRuntime> {
            self.systemd_runtimes
                .get_mut(index)
                .ok_or_else(|| anyhow::anyhow!("systemd runtime index {index} out of range"))
        }

        fn refresh_watch_pids(&mut self) -> anyhow::Result<()> {
            if let Some(message) = self.refresh_error {
                return Err(anyhow::anyhow!(message));
            }
            self.refresh_count += 1;
            Ok(())
        }
    }

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
            _tx: tokio::sync::mpsc::UnboundedSender<RuntimeUpdate>,
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
            _tx: tokio::sync::mpsc::UnboundedSender<RuntimeUpdate>,
            _index: usize,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async {})
        }
    }

    fn container_runtime(current_pid: Option<u32>) -> ContainerRuntime {
        ContainerRuntime {
            cgroup_port: Arc::new(ProcfsCgroupPort),
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x3,
            current_pid,
        }
    }

    fn systemd_runtime(current_pid: Option<u32>, current_running: bool) -> SystemdRuntime {
        SystemdRuntime {
            runtime: Arc::new(FakeSystemdRuntimePort),
            unit_name: "svc.service".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x7,
            current_pid,
            current_running,
        }
    }

    #[tokio::test]
    async fn state_runtime_update_handler_applies_container_pid_and_refreshes() {
        let mut process_seed = FakeProcessSeedPort::default();
        let mut backend = FakeBackend {
            container_runtimes: vec![container_runtime(None)],
            systemd_runtimes: Vec::new(),
            refresh_count: 0,
            refresh_error: None,
        };
        let mut reporter = FakeReporter::default();
        let mut handler = StateRuntimeUpdateHandler {
            process_seed: &mut process_seed,
            backend: &mut backend,
            reporter: &mut reporter,
        };

        let keep_running = handle_runtime_update(
            &mut handler,
            Some(RuntimeUpdate::ContainerPid {
                index: 0,
                pid: Some(41),
            }),
        )
        .await
        .unwrap();

        assert!(keep_running);
        assert_eq!(backend.container_runtimes[0].current_pid, Some(41));
        assert_eq!(process_seed.direct_calls, vec![(vec![41], 0x3)]);
        assert_eq!(backend.refresh_count, 1);
    }

    #[tokio::test]
    async fn state_runtime_update_handler_applies_systemd_status_and_refreshes() {
        let mut process_seed = FakeProcessSeedPort::default();
        let mut backend = FakeBackend {
            container_runtimes: Vec::new(),
            systemd_runtimes: vec![systemd_runtime(None, false)],
            refresh_count: 0,
            refresh_error: None,
        };
        let mut reporter = FakeReporter::default();
        let mut handler = StateRuntimeUpdateHandler {
            process_seed: &mut process_seed,
            backend: &mut backend,
            reporter: &mut reporter,
        };

        let keep_running = handle_runtime_update(
            &mut handler,
            Some(RuntimeUpdate::SystemdStatus {
                index: 0,
                pid: Some(77),
                running: true,
            }),
        )
        .await
        .unwrap();

        assert!(keep_running);
        assert_eq!(backend.systemd_runtimes[0].current_pid, Some(77));
        assert!(backend.systemd_runtimes[0].current_running);
        assert_eq!(process_seed.direct_calls, vec![(vec![77], 0x7)]);
        assert_eq!(backend.refresh_count, 1);
    }

    #[tokio::test]
    async fn state_runtime_update_handler_reports_out_of_range_container_index() {
        let mut process_seed = FakeProcessSeedPort::default();
        let mut backend = FakeBackend {
            container_runtimes: Vec::new(),
            systemd_runtimes: Vec::new(),
            refresh_count: 0,
            refresh_error: None,
        };
        let mut reporter = FakeReporter::default();
        let mut handler = StateRuntimeUpdateHandler {
            process_seed: &mut process_seed,
            backend: &mut backend,
            reporter: &mut reporter,
        };

        let err = handle_runtime_update(
            &mut handler,
            Some(RuntimeUpdate::ContainerPid {
                index: 1,
                pid: Some(9),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "container runtime index 1 out of range");
        assert_eq!(backend.refresh_count, 0);
    }

}
