use std::{
    collections::{HashMap as StdHashMap, HashSet},
    sync::Arc,
};

use aya::Ebpf;

use tracepoint_demo_common::{PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

use crate::{
    gateway::{
        docker::DockerContainerRuntimeGateway,
        ebpf::{EbpfProcessSeedPort, build_watch_pids},
        systemd::SystemdRuntimeGateway,
    },
    usecase::{
        orchestration::{
            startup_prepare::{StartupPrepareBackend, StartupPrepareInputs, prepare_runtime_plan},
            startup_runtime,
            state::{AppState, StartupWatchPidGroup},
            tty::normalize_tty_name,
            watch_roots::collect_watch_roots,
        },
        policy::{
            trace_selected_targets::TraceRequest, watch_container::ContainerRuntime,
            watch_systemd_unit::SystemdRuntime,
        },
        port::{
            ProcessSeedPort, SharedCgroupPort, SharedContainerRuntimePort,
            SharedSystemdRuntimePort, StatusReporter, WaitPort,
        },
    },
};

pub struct StartupResources {
    pub ebpf: Ebpf,
    pub cgroup_port: Arc<crate::gateway::procfs::ProcfsCgroupPort>,
    pub container_runtime: Option<Arc<DockerContainerRuntimeGateway>>,
    pub systemd_runtime: Option<Arc<SystemdRuntimeGateway>>,
}

pub struct PreparedApp {
    pub ebpf: Ebpf,
    pub watch_pids: aya::maps::hash_map::HashMap<aya::maps::MapData, u32, u32>,
    pub state: AppState,
    pub startup_watch_pid_groups: Vec<StartupWatchPidGroup>,
    pub watch_children: bool,
    pub all_container_processes: bool,
    pub all_systemd_processes: bool,
    pub container_runtime: Option<Arc<DockerContainerRuntimeGateway>>,
    pub systemd_runtime: Option<Arc<SystemdRuntimeGateway>>,
}

struct StartupPrepareAdapter<'a, TReporter: StatusReporter + ?Sized, TWait: WaitPort + ?Sized> {
    ebpf: &'a mut Ebpf,
    cgroup_port: SharedCgroupPort,
    container_runtime: Option<SharedContainerRuntimePort>,
    systemd_runtime: Option<SharedSystemdRuntimePort>,
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
            startup_runtime::StaticWatchRootsSpec {
                pids,
                tty_filters,
                tty_inputs,
                watch_flags,
                has_runtime_targets,
            },
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
        let runtime = self
            .container_runtime
            .as_ref()
            .expect("container runtime should be available when initialization runs");
        startup_runtime::initialize_container_runtimes(
            &mut process_seed,
            &self.cgroup_port,
            &mut *self.reporter,
            runtime,
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
        let runtime = self
            .systemd_runtime
            .as_ref()
            .expect("systemd runtime should be available when initialization runs");
        startup_runtime::initialize_systemd_runtimes(
            &mut process_seed,
            &mut *self.reporter,
            &mut *self.wait_port,
            runtime,
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
}

fn normalize_sorted_unique_pids(mut pids: Vec<u32>) -> Vec<u32> {
    pids.sort_unstable();
    pids.dedup();
    pids
}

fn collect_tty_watch_pid_groups(
    process_seed: &mut dyn ProcessSeedPort,
    tty_inputs: &[String],
    watch_flags: u32,
) -> anyhow::Result<Vec<StartupWatchPidGroup>> {
    let mut tty_groups = Vec::new();
    let mut seen_tty_filters = HashSet::new();

    for tty in tty_inputs {
        let normalized = normalize_tty_name(tty);
        if normalized.is_empty() || !seen_tty_filters.insert(normalized.clone()) {
            continue;
        }

        let tty_filters = HashSet::from([normalized]);
        let roots = process_seed.seed_from_task_iter(&[], &tty_filters, watch_flags)?;
        if roots.is_empty() {
            continue;
        }

        tty_groups.push(StartupWatchPidGroup::simple(
            format!("tty:{tty}"),
            normalize_sorted_unique_pids(roots),
        ));
    }

    Ok(tty_groups)
}

pub fn collect_startup_watch_pid_groups(
    pids: &[u32],
    tty_groups: &[StartupWatchPidGroup],
    container_runtimes: &[ContainerRuntime],
    systemd_runtimes: &[SystemdRuntime],
) -> Vec<StartupWatchPidGroup> {
    let mut groups = Vec::new();

    if !pids.is_empty() {
        groups.push(StartupWatchPidGroup::simple(
            "pid",
            normalize_sorted_unique_pids(pids.to_vec()),
        ));
    }

    groups.extend(tty_groups.iter().cloned());

    for runtime in container_runtimes {
        if runtime.current_pid.is_some() || !runtime.seeded_pids.is_empty() {
            groups.push(StartupWatchPidGroup::runtime(
                format!("container:{}", runtime.name_or_id),
                runtime.current_pid,
                runtime.seeded_pids.clone(),
            ));
        }
    }

    for runtime in systemd_runtimes {
        if runtime.current_pid.is_some() || !runtime.seeded_pids.is_empty() {
            groups.push(StartupWatchPidGroup::runtime(
                format!("systemd:{}", runtime.unit_name),
                runtime.current_pid,
                runtime.seeded_pids.clone(),
            ));
        }
    }

    groups
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
    let cgroup_port: SharedCgroupPort = cgroup_port;
    let container_runtime_for_prepare: Option<SharedContainerRuntimePort> =
        container_runtime.as_ref().map(|runtime| {
            let runtime: SharedContainerRuntimePort = runtime.clone();
            runtime
        });
    let systemd_runtime_for_prepare: Option<SharedSystemdRuntimePort> =
        systemd_runtime.as_ref().map(|runtime| {
            let runtime: SharedSystemdRuntimePort = runtime.clone();
            runtime
        });

    let watch_flags = PROC_FLAG_WATCH_SELF
        | if watch_children {
            PROC_FLAG_WATCH_CHILDREN
        } else {
            0
        };
    let mut prepare_adapter = StartupPrepareAdapter {
        ebpf: &mut ebpf,
        cgroup_port,
        container_runtime: container_runtime_for_prepare,
        systemd_runtime: systemd_runtime_for_prepare,
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
    let tty_watch_pid_groups = {
        let mut process_seed = EbpfProcessSeedPort::new(&mut ebpf);
        collect_tty_watch_pid_groups(&mut process_seed, &tty_inputs, watch_flags)?
    };
    let startup_watch_pid_groups = collect_startup_watch_pid_groups(
        &pids,
        &tty_watch_pid_groups,
        &plan.container_runtimes,
        &plan.systemd_runtimes,
    );

    let watch_pids = build_watch_pids(&mut ebpf, &plan.current_watch_roots)?;

    let state = AppState {
        static_watch_roots: plan.static_watch_roots,
        current_watch_roots: plan.current_watch_roots,
        container_runtimes: plan.container_runtimes,
        systemd_runtimes: plan.systemd_runtimes,
    };

    Ok(PreparedApp {
        ebpf,
        watch_pids,
        state,
        startup_watch_pid_groups,
        watch_children,
        all_container_processes,
        all_systemd_processes,
        container_runtime,
        systemd_runtime,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{NoopContainerRuntimePort, NoopSystemdRuntimePort};

    #[test]
    fn collect_startup_watch_pid_groups_orders_pid_tty_container_and_systemd_segments() {
        let container = ContainerRuntime {
            cgroup_port: Arc::new(crate::gateway::procfs::ProcfsCgroupPort),
            runtime: Arc::new(NoopContainerRuntimePort),
            name_or_id: "ctr".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 1,
            seeded_pids: vec![40, 10, 10],
            current_pid: Some(10),
        };
        let systemd_runtime = SystemdRuntime {
            runtime: Arc::new(NoopSystemdRuntimePort),
            unit_name: "svc".to_string(),
            watch_children: false,
            all_processes: false,
            seeded_pids: vec![21, 20],
            flags: 2,
            current_pid: Some(20),
            current_running: true,
            current_active_state: Some("active".to_string()),
            current_sub_state: Some("running".to_string()),
        };
        let tty_group = StartupWatchPidGroup::simple("tty:/dev/pts/3", vec![33, 34]);

        let groups = collect_startup_watch_pid_groups(
            &[7, 7],
            &[tty_group],
            &[container],
            &[systemd_runtime],
        );

        assert_eq!(
            groups,
            vec![
                StartupWatchPidGroup::simple("pid", vec![7]),
                StartupWatchPidGroup::simple("tty:/dev/pts/3", vec![33, 34]),
                StartupWatchPidGroup::runtime("container:ctr", Some(10), vec![40, 10, 10]),
                StartupWatchPidGroup::runtime("systemd:svc", Some(20), vec![21, 20]),
            ]
        );
    }

    #[test]
    fn collect_startup_watch_pid_groups_skips_empty_runtime_groups() {
        let container = ContainerRuntime {
            cgroup_port: Arc::new(crate::gateway::procfs::ProcfsCgroupPort),
            runtime: Arc::new(NoopContainerRuntimePort),
            name_or_id: "ctr".to_string(),
            watch_children: true,
            all_processes: true,
            flags: 1,
            seeded_pids: Vec::new(),
            current_pid: None,
        };
        let systemd_runtime = SystemdRuntime {
            runtime: Arc::new(NoopSystemdRuntimePort),
            unit_name: "svc".to_string(),
            watch_children: true,
            all_processes: true,
            seeded_pids: Vec::new(),
            flags: 2,
            current_pid: None,
            current_running: true,
            current_active_state: Some("active".to_string()),
            current_sub_state: Some("running".to_string()),
        };

        let groups = collect_startup_watch_pid_groups(&[], &[], &[container], &[systemd_runtime]);

        assert!(groups.is_empty());
    }
}
