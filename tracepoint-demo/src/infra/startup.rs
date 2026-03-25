use std::collections::{HashMap as StdHashMap, HashSet};

use aya::Ebpf;

use tracepoint_demo_common::{PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

use crate::{
    gateway::ebpf::{EbpfProcessSeedPort, build_watch_pids},
    usecase::{
        orchestration::{
            startup_prepare::{StartupPrepareBackend, StartupPrepareInputs, prepare_runtime_plan},
            startup_runtime,
            state::{AppState, PreparedApp},
            tty::normalize_tty_name,
            watch_roots::collect_watch_roots,
        },
        policy::{
            trace_selected_targets::TraceRequest, watch_container::ContainerRuntime,
            watch_systemd_unit::SystemdRuntime,
        },
        port::{
            SharedCgroupPort, SharedContainerRuntimePort, SharedSystemdRuntimePort, StatusReporter,
            WaitPort,
        },
    },
};

pub struct StartupResources {
    pub ebpf: Ebpf,
    pub cgroup_port: SharedCgroupPort,
    pub container_runtime: Option<SharedContainerRuntimePort>,
    pub systemd_runtime: Option<SharedSystemdRuntimePort>,
}

struct StartupPrepareAdapter<'a, TReporter: StatusReporter + ?Sized, TWait: WaitPort + ?Sized> {
    ebpf: &'a mut Ebpf,
    cgroup_port: &'a SharedCgroupPort,
    container_runtime: Option<&'a SharedContainerRuntimePort>,
    systemd_runtime: Option<&'a SharedSystemdRuntimePort>,
    reporter: &'a mut TReporter,
    wait_port: &'a mut TWait,
}

impl<TReporter: StatusReporter + ?Sized, TWait: WaitPort + ?Sized> StartupPrepareBackend
    for StartupPrepareAdapter<'_, TReporter, TWait>
{
    type ContainerRuntime = ContainerRuntime;
    type SystemdRuntime = SystemdRuntime;

    async fn collect_static_watch_roots(
        &mut self,
        pids: &[u32],
        tty_filters: &HashSet<String>,
        tty_inputs: &[String],
        watch_flags: u32,
        has_runtime_targets: bool,
    ) -> anyhow::Result<StdHashMap<u32, u32>> {
        let mut process_seed = EbpfProcessSeedPort::new(self.ebpf);
        startup_runtime::collect_static_watch_roots(
            &mut process_seed,
            pids,
            tty_filters,
            tty_inputs,
            watch_flags,
            has_runtime_targets,
            &mut *self.reporter,
            &mut *self.wait_port,
        )
        .await
    }

    async fn initialize_container_runtimes(
        &mut self,
        containers: &[String],
        watch_children: bool,
        all_container_processes: bool,
    ) -> anyhow::Result<Vec<Self::ContainerRuntime>> {
        let mut process_seed = EbpfProcessSeedPort::new(self.ebpf);
        startup_runtime::initialize_container_runtimes(
            &mut process_seed,
            self.cgroup_port,
            &mut *self.reporter,
            self.container_runtime
                .expect("container runtime should be available when initialization runs"),
            containers,
            watch_children,
            all_container_processes,
        )
        .await
    }

    async fn initialize_systemd_runtimes(
        &mut self,
        systemd_units: &[String],
        watch_children: bool,
        all_systemd_processes: bool,
    ) -> anyhow::Result<Vec<Self::SystemdRuntime>> {
        let mut process_seed = EbpfProcessSeedPort::new(self.ebpf);
        startup_runtime::initialize_systemd_runtimes(
            &mut process_seed,
            &mut *self.reporter,
            &mut *self.wait_port,
            self.systemd_runtime
                .expect("systemd runtime should be available when initialization runs"),
            systemd_units,
            watch_children,
            all_systemd_processes,
        )
        .await
    }

    fn collect_watch_roots(
        &self,
        static_watch_roots: &StdHashMap<u32, u32>,
        container_runtimes: &[Self::ContainerRuntime],
        systemd_runtimes: &[Self::SystemdRuntime],
    ) -> StdHashMap<u32, u32> {
        collect_watch_roots(static_watch_roots, container_runtimes, systemd_runtimes)
    }

    fn collect_target_descriptions(
        &self,
        container_runtimes: &[Self::ContainerRuntime],
        systemd_runtimes: &[Self::SystemdRuntime],
        all_container_processes: bool,
        all_systemd_processes: bool,
    ) -> Vec<String> {
        collect_target_descriptions(
            container_runtimes,
            systemd_runtimes,
            all_container_processes,
            all_systemd_processes,
        )
    }
}

fn collect_target_descriptions(
    container_runtimes: &[ContainerRuntime],
    systemd_runtimes: &[SystemdRuntime],
    all_container_processes: bool,
    all_systemd_processes: bool,
) -> Vec<String> {
    let mut target_descriptions = Vec::new();
    if !container_runtimes.is_empty() {
        let container_list = container_runtimes
            .iter()
            .map(|runtime| runtime.name_or_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if all_container_processes {
            target_descriptions.push(format!("containers=[{}] seed=all-procs", container_list));
        } else {
            target_descriptions.push(format!("containers=[{}]", container_list));
        }
    }
    if !systemd_runtimes.is_empty() {
        let unit_list = systemd_runtimes
            .iter()
            .map(|runtime| runtime.unit_name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if all_systemd_processes {
            target_descriptions.push(format!("systemd-units=[{}] seed=all-procs", unit_list));
        } else {
            target_descriptions.push(format!("systemd-units=[{}]", unit_list));
        }
    }
    target_descriptions
}

pub async fn prepare_prepared_app<TReporter: StatusReporter + ?Sized, TWait: WaitPort + ?Sized>(
    request: TraceRequest,
    resources: StartupResources,
    reporter: &mut TReporter,
    wait_port: &mut TWait,
) -> anyhow::Result<PreparedApp> {
    let TraceRequest {
        pids,
        tty_inputs,
        containers,
        all_container_processes,
        systemd_units,
        all_systemd_processes,
        watch_children,
    } = request;

    let mut tty_filters = HashSet::new();
    for tty in &tty_inputs {
        let normalized = normalize_tty_name(tty);
        if !normalized.is_empty() {
            tty_filters.insert(normalized);
        }
    }

    let StartupResources {
        ebpf,
        cgroup_port,
        container_runtime,
        systemd_runtime,
    } = resources;
    let mut ebpf = ebpf;
    let container_runtime_available = container_runtime.is_some();
    let systemd_runtime_available = systemd_runtime.is_some();

    let watch_flags = PROC_FLAG_WATCH_SELF
        | if watch_children {
            PROC_FLAG_WATCH_CHILDREN
        } else {
            0
        };
    let mut prepare_adapter = StartupPrepareAdapter {
        ebpf: &mut ebpf,
        cgroup_port: &cgroup_port,
        container_runtime: container_runtime.as_ref(),
        systemd_runtime: systemd_runtime.as_ref(),
        reporter,
        wait_port,
    };
    let plan = prepare_runtime_plan(
        &mut prepare_adapter,
        StartupPrepareInputs {
            pids: &pids,
            tty_inputs: &tty_inputs,
            tty_filters: &tty_filters,
            containers: &containers,
            systemd_units: &systemd_units,
            watch_children,
            all_container_processes,
            all_systemd_processes,
            watch_flags,
            container_runtime_available,
            systemd_runtime_available,
        },
    )
    .await?;

    let watch_pids = build_watch_pids(&mut ebpf, &plan.current_watch_roots)?;

    let state = AppState {
        static_watch_roots: plan.static_watch_roots,
        current_watch_roots: plan.current_watch_roots,
        watch_pids,
        container_runtimes: plan.container_runtimes,
        systemd_runtimes: plan.systemd_runtimes,
    };

    Ok(PreparedApp {
        ebpf,
        state,
        tty_inputs,
        watch_children,
        target_descriptions: plan.target_descriptions,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::usecase::port::{
        BoxFuture, ContainerRuntimePort, RuntimeUpdate, SystemdRuntimePort,
        SystemdUnitRuntimeStatus,
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

        fn unit_pids<'a>(&'a self, _unit_name: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<u32>>> {
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

    #[test]
    fn collect_target_descriptions_empty_when_no_runtimes() {
        let desc = collect_target_descriptions(&[], &[], false, false);
        assert!(desc.is_empty());
    }

    #[test]
    fn collect_target_descriptions_includes_container_and_systemd_entries() {
        let container = ContainerRuntime {
            cgroup_port: Arc::new(crate::gateway::procfs::ProcfsCgroupPort),
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "ctr".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 1,
            current_pid: Some(1),
        };
        let systemd_runtime = SystemdRuntime {
            runtime: Arc::new(FakeSystemdRuntimePort),
            unit_name: "svc".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 2,
            current_pid: Some(2),
            current_running: true,
        };

        let desc = collect_target_descriptions(&[container], &[systemd_runtime], false, false);
        assert!(desc.iter().any(|s| s.contains("containers")));
        assert!(desc.iter().any(|s| s.contains("systemd-units")));
    }

    #[test]
    fn collect_target_descriptions_marks_all_container_processes() {
        let container = ContainerRuntime {
            cgroup_port: Arc::new(crate::gateway::procfs::ProcfsCgroupPort),
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "ctr".to_string(),
            watch_children: true,
            all_processes: true,
            flags: 1,
            current_pid: Some(1),
        };

        let desc = collect_target_descriptions(&[container], &[], true, false);

        assert_eq!(desc, vec!["containers=[ctr] seed=all-procs".to_string()]);
    }

    #[test]
    fn collect_target_descriptions_marks_all_systemd_processes() {
        let systemd_runtime = SystemdRuntime {
            runtime: Arc::new(FakeSystemdRuntimePort),
            unit_name: "svc".to_string(),
            watch_children: false,
            all_processes: true,
            flags: 2,
            current_pid: Some(2),
            current_running: true,
        };

        let desc = collect_target_descriptions(&[], &[systemd_runtime], false, true);

        assert_eq!(desc, vec!["systemd-units=[svc] seed=all-procs".to_string()]);
    }
}
