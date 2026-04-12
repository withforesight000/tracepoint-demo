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
    async fn apply_container_pid(
        &mut self,
        index: usize,
        pid: Option<u32>,
        force_refresh: bool,
        extra_pids: Vec<u32>,
    ) -> anyhow::Result<()> {
        let runtime = self.backend.container_runtime_mut(index)?;
        apply_container_runtime_update(
            self.process_seed,
            self.reporter,
            runtime,
            pid,
            force_refresh,
            &extra_pids,
        )
        .await?;
        self.backend.refresh_watch_pids()
    }

    async fn apply_systemd_status(
        &mut self,
        index: usize,
        pid: Option<u32>,
        running: bool,
        active_state: Option<String>,
        sub_state: Option<String>,
    ) -> anyhow::Result<()> {
        let runtime = self.backend.systemd_runtime_mut(index)?;
        apply_systemd_runtime_update(
            self.process_seed,
            self.reporter,
            runtime,
            pid,
            running,
            active_state,
            sub_state,
        )
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
        test_support::{
            MockProcessSeedPort, MockStatusReporter, NoopContainerRuntimePort,
            NoopSystemdRuntimePort,
        },
        usecase::{
            policy::{watch_container::ContainerRuntime, watch_systemd_unit::SystemdRuntime},
            port::RuntimeUpdate,
        },
    };

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

    fn container_runtime(current_pid: Option<u32>) -> ContainerRuntime {
        ContainerRuntime {
            cgroup_port: Arc::new(ProcfsCgroupPort),
            runtime: Arc::new(NoopContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x3,
            seeded_pids: current_pid.into_iter().collect(),
            current_pid,
        }
    }

    fn systemd_runtime(current_pid: Option<u32>, current_running: bool) -> SystemdRuntime {
        SystemdRuntime {
            runtime: Arc::new(NoopSystemdRuntimePort),
            unit_name: "svc.service".to_string(),
            watch_children: false,
            all_processes: false,
            seeded_pids: Vec::new(),
            flags: 0x7,
            current_pid,
            current_running,
            current_active_state: current_running.then(|| "active".to_string()),
            current_sub_state: current_running.then(|| "running".to_string()),
        }
    }

    #[tokio::test]
    async fn state_runtime_update_handler_applies_container_pid_and_refreshes() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [41] && *flags == 0x3)
            .returning(|_, _| Ok(()));
        let mut backend = FakeBackend {
            container_runtimes: vec![container_runtime(None)],
            systemd_runtimes: Vec::new(),
            refresh_count: 0,
            refresh_error: None,
        };
        let mut reporter = MockStatusReporter::new();
        reporter
            .expect_info()
            .times(1)
            .withf(|message| {
                message == "container web changed: state not-running -> running, pid none -> 41"
            })
            .return_const(());
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
                force_refresh: false,
                extra_pids: Vec::new(),
            }),
        )
        .await
        .unwrap();

        assert!(keep_running);
        assert_eq!(backend.container_runtimes[0].current_pid, Some(41));
        assert_eq!(backend.refresh_count, 1);
    }

    #[tokio::test]
    async fn state_runtime_update_handler_applies_systemd_status_and_refreshes() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [77] && *flags == 0x7)
            .returning(|_, _| Ok(()));
        let mut backend = FakeBackend {
            container_runtimes: Vec::new(),
            systemd_runtimes: vec![systemd_runtime(None, false)],
            refresh_count: 0,
            refresh_error: None,
        };
        let mut reporter = MockStatusReporter::new();
        reporter
            .expect_info()
            .times(1)
            .withf(|message| {
                message
                    == "systemd unit svc.service changed: state missing -> active/running, MainPID none -> 77"
            })
            .return_const(());
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
                active_state: Some("active".to_string()),
                sub_state: Some("running".to_string()),
            }),
        )
        .await
        .unwrap();

        assert!(keep_running);
        assert_eq!(backend.systemd_runtimes[0].current_pid, Some(77));
        assert!(backend.systemd_runtimes[0].current_running);
        assert_eq!(backend.refresh_count, 1);
    }

    #[tokio::test]
    async fn state_runtime_update_handler_reports_out_of_range_container_index() {
        let mut process_seed = MockProcessSeedPort::new();
        let mut backend = FakeBackend {
            container_runtimes: Vec::new(),
            systemd_runtimes: Vec::new(),
            refresh_count: 0,
            refresh_error: None,
        };
        let mut reporter = MockStatusReporter::new();
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
                force_refresh: false,
                extra_pids: Vec::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "container runtime index 1 out of range");
        assert_eq!(backend.refresh_count, 0);
    }
}
