mod support;

use std::{collections::HashMap, sync::Arc};

use tracepoint_demo::integration::{
    ContainerRuntime, RuntimeUpdate, RuntimeUpdateHandler, SharedCgroupPort,
    SharedContainerRuntimePort, SharedSystemdRuntimePort, StartupPrepareBackend,
    StartupPrepareInputs, SystemdRuntime, SystemdUnitRuntimeStatus, collect_target_descriptions,
    collect_watch_roots, handle_runtime_update, initialize_container_runtimes,
    initialize_systemd_runtimes, prepare_runtime_plan, sync_watch_pids,
};
use tracepoint_demo_common::{PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

use support::{
    RecordingProcessSeed, RecordingStatusReporter, RecordingWatchPidStore, ScriptedCgroupPort,
    ScriptedContainerRuntimePort, ScriptedSystemdRuntimePort, ScriptedWaitPort, WatchOp,
    container_runtime, running_status, systemd_runtime,
};

fn watch_flags(watch_children: bool) -> u32 {
    PROC_FLAG_WATCH_SELF
        | if watch_children {
            PROC_FLAG_WATCH_CHILDREN
        } else {
            0
        }
}

struct TestStartupBackend {
    process_seed: RecordingProcessSeed,
    reporter: RecordingStatusReporter,
    wait_port: ScriptedWaitPort,
    cgroup_port: Arc<ScriptedCgroupPort>,
    container_runtime: Arc<ScriptedContainerRuntimePort>,
    systemd_runtime: Arc<ScriptedSystemdRuntimePort>,
}

impl StartupPrepareBackend for TestStartupBackend {
    type ContainerRuntime = ContainerRuntime;
    type SystemdRuntime = SystemdRuntime;

    async fn collect_static_watch_roots(
        &mut self,
        pids: &[u32],
        tty_filters: &std::collections::HashSet<String>,
        tty_inputs: &[String],
        watch_flags: u32,
        has_runtime_targets: bool,
    ) -> anyhow::Result<HashMap<u32, u32>> {
        tracepoint_demo::integration::collect_static_watch_roots(
            &mut self.process_seed,
            tracepoint_demo::integration::StaticWatchRootsSpec {
                pids,
                tty_filters,
                tty_inputs,
                watch_flags,
                has_runtime_targets,
            },
            &mut self.reporter,
            &mut self.wait_port,
        )
        .await
    }

    async fn initialize_container_runtimes(
        &mut self,
        containers: &[String],
        watch_children: bool,
        all_container_processes: bool,
    ) -> anyhow::Result<Vec<Self::ContainerRuntime>> {
        let cgroup_port: SharedCgroupPort = self.cgroup_port.clone();
        let container_runtime: SharedContainerRuntimePort = self.container_runtime.clone();
        initialize_container_runtimes(
            &mut self.process_seed,
            &cgroup_port,
            &mut self.reporter,
            &container_runtime,
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
        let systemd_runtime: SharedSystemdRuntimePort = self.systemd_runtime.clone();
        initialize_systemd_runtimes(
            &mut self.process_seed,
            &mut self.reporter,
            &mut self.wait_port,
            &systemd_runtime,
            systemd_units,
            watch_children,
            all_systemd_processes,
        )
        .await
    }

    fn collect_watch_roots(
        &self,
        static_watch_roots: &HashMap<u32, u32>,
        container_runtimes: &[Self::ContainerRuntime],
        systemd_runtimes: &[Self::SystemdRuntime],
    ) -> HashMap<u32, u32> {
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

struct RuntimeUpdateHarness {
    process_seed: RecordingProcessSeed,
    reporter: RecordingStatusReporter,
    watch_store: RecordingWatchPidStore,
    static_watch_roots: HashMap<u32, u32>,
    current_watch_roots: HashMap<u32, u32>,
    container_runtimes: Vec<ContainerRuntime>,
    systemd_runtimes: Vec<SystemdRuntime>,
}

impl RuntimeUpdateHarness {
    fn refresh_watch_pids(&mut self) -> anyhow::Result<()> {
        let desired = collect_watch_roots(
            &self.static_watch_roots,
            &self.container_runtimes,
            &self.systemd_runtimes,
        );
        sync_watch_pids(
            &mut self.watch_store,
            &mut self.current_watch_roots,
            &desired,
        )
    }
}

impl RuntimeUpdateHandler for RuntimeUpdateHarness {
    async fn apply_container_pid(
        &mut self,
        index: usize,
        pid: Option<u32>,
        force_refresh: bool,
        extra_pids: Vec<u32>,
    ) -> anyhow::Result<()> {
        let runtime = self
            .container_runtimes
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("container runtime index {index} out of range"))?;
        tracepoint_demo::integration::apply_container_runtime_update(
            &mut self.process_seed,
            &mut self.reporter,
            runtime,
            pid,
            force_refresh,
            &extra_pids,
        )
        .await?;
        self.refresh_watch_pids()
    }

    async fn apply_systemd_status(
        &mut self,
        index: usize,
        pid: Option<u32>,
        running: bool,
        active_state: Option<String>,
        sub_state: Option<String>,
    ) -> anyhow::Result<()> {
        let runtime = self
            .systemd_runtimes
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("systemd runtime index {index} out of range"))?;
        tracepoint_demo::integration::apply_systemd_runtime_update(
            &mut self.process_seed,
            &mut self.reporter,
            runtime,
            pid,
            running,
            active_state,
            sub_state,
        )
        .await?;
        self.refresh_watch_pids()
    }
}

#[tokio::test]
async fn prepare_runtime_plan_retries_for_pid_targets_until_one_matches() {
    let mut process_seed = RecordingProcessSeed::default();
    process_seed.push_task_iter_result(Ok(Vec::new()));
    process_seed.push_task_iter_result(Ok(Vec::new()));
    process_seed.push_task_iter_result(Ok(Vec::new()));
    process_seed.push_task_iter_result(Ok(vec![41]));

    let mut backend = TestStartupBackend {
        process_seed,
        reporter: RecordingStatusReporter::default(),
        wait_port: {
            let mut wait_port = ScriptedWaitPort::default();
            wait_port.push_result(Ok(()));
            wait_port.push_result(Ok(()));
            wait_port
        },
        cgroup_port: Arc::new(ScriptedCgroupPort::default()),
        container_runtime: Arc::new(ScriptedContainerRuntimePort::default()),
        systemd_runtime: Arc::new(ScriptedSystemdRuntimePort::default()),
    };

    let pids = [41];
    let tty_filters = std::collections::HashSet::new();
    let tty_inputs: Vec<String> = Vec::new();
    let containers: Vec<String> = Vec::new();
    let systemd_units: Vec<String> = Vec::new();

    let plan = prepare_runtime_plan(
        &mut backend,
        StartupPrepareInputs {
            pids: &pids,
            tty_inputs: &tty_inputs,
            tty_filters: &tty_filters,
            containers: &containers,
            systemd_units: &systemd_units,
            watch_children: true,
            all_container_processes: false,
            all_systemd_processes: false,
            watch_flags: watch_flags(true),
            container_runtime_available: false,
            systemd_runtime_available: false,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        plan.static_watch_roots,
        HashMap::from([(41, watch_flags(true))])
    );
    assert_eq!(
        plan.current_watch_roots,
        HashMap::from([(41, watch_flags(true))])
    );
    assert!(plan.container_runtimes.is_empty());
    assert!(plan.systemd_runtimes.is_empty());
    assert_eq!(backend.reporter.warns.len(), 1);
    assert_eq!(backend.wait_port.calls.len(), 2);
    assert_eq!(backend.process_seed.task_iter_calls.len(), 4);
    assert_eq!(backend.process_seed.task_iter_calls[0].pid_roots, vec![41]);
}

#[tokio::test]
async fn prepare_runtime_plan_initializes_runtime_targets_and_descriptions() {
    let mut process_seed = RecordingProcessSeed::default();
    process_seed.push_task_iter_result(Ok(vec![11]));
    process_seed.push_direct_result(Ok(()));
    process_seed.push_direct_result(Ok(()));

    let cgroup_port = Arc::new(ScriptedCgroupPort::default());
    cgroup_port.push_read_cgroup_v2_path_result(Ok("/sys/fs/cgroup/web".to_string()));
    cgroup_port.push_read_cgroup_procs_result(Ok(vec![21, 22]));

    let container_runtime = Arc::new(ScriptedContainerRuntimePort::default());
    container_runtime.push_query_main_pid_result(Ok(Some(21)));

    let systemd_runtime = Arc::new(ScriptedSystemdRuntimePort::default());
    systemd_runtime.push_current_status_result(Ok(running_status(31)));
    systemd_runtime.push_unit_pids_result(Ok(vec![31, 32]));

    let mut backend = TestStartupBackend {
        process_seed,
        reporter: RecordingStatusReporter::default(),
        wait_port: ScriptedWaitPort::default(),
        cgroup_port,
        container_runtime,
        systemd_runtime,
    };

    let pids = [11];
    let tty_filters = std::collections::HashSet::new();
    let tty_inputs: Vec<String> = Vec::new();
    let containers = vec!["web".to_string()];
    let systemd_units = vec!["demo.service".to_string()];

    let plan = prepare_runtime_plan(
        &mut backend,
        StartupPrepareInputs {
            pids: &pids,
            tty_inputs: &tty_inputs,
            tty_filters: &tty_filters,
            containers: &containers,
            systemd_units: &systemd_units,
            watch_children: false,
            all_container_processes: true,
            all_systemd_processes: true,
            watch_flags: watch_flags(false),
            container_runtime_available: true,
            systemd_runtime_available: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        plan.static_watch_roots,
        HashMap::from([(11, watch_flags(false))])
    );
    assert_eq!(
        plan.current_watch_roots,
        HashMap::from([
            (11, watch_flags(false)),
            (21, watch_flags(true)),
            (31, watch_flags(true)),
        ])
    );
    assert_eq!(plan.container_runtimes.len(), 1);
    assert_eq!(plan.systemd_runtimes.len(), 1);
    assert_eq!(
        plan.target_descriptions,
        vec![
            "containers=[web] seed=all-procs".to_string(),
            "systemd-units=[demo.service] seed=all-procs".to_string(),
        ]
    );
    assert_eq!(
        backend.process_seed.task_iter_calls,
        vec![support::SeedFromTaskIterCall {
            pid_roots: vec![11],
            tty_filters: std::collections::BTreeSet::new(),
            watch_flags: watch_flags(false),
        }]
    );
    assert_eq!(
        backend.process_seed.direct_calls,
        vec![
            support::SeedDirectCall {
                pids: vec![21, 22],
                flags: watch_flags(true),
            },
            support::SeedDirectCall {
                pids: vec![31, 32],
                flags: watch_flags(true),
            },
        ]
    );
    assert_eq!(
        backend
            .cgroup_port
            .read_cgroup_v2_path_calls
            .lock()
            .unwrap()
            .as_slice(),
        &[21]
    );
    assert_eq!(
        backend
            .cgroup_port
            .read_cgroup_procs_calls
            .lock()
            .unwrap()
            .as_slice(),
        &["/sys/fs/cgroup/web".to_string()]
    );
    assert_eq!(
        backend
            .container_runtime
            .query_main_pid_calls
            .lock()
            .unwrap()
            .as_slice(),
        &["web".to_string()]
    );
    assert_eq!(
        backend
            .systemd_runtime
            .current_status_calls
            .lock()
            .unwrap()
            .as_slice(),
        &["demo.service".to_string()]
    );
    assert_eq!(
        backend
            .systemd_runtime
            .unit_pids_calls
            .lock()
            .unwrap()
            .as_slice(),
        &["demo.service".to_string()]
    );
}

#[tokio::test]
async fn prepare_runtime_plan_seeds_systemd_main_pid_even_when_unit_is_inactive() {
    let mut process_seed = RecordingProcessSeed::default();
    process_seed.push_direct_result(Ok(()));

    let systemd_runtime = Arc::new(ScriptedSystemdRuntimePort::default());
    systemd_runtime.push_current_status_result(Ok(SystemdUnitRuntimeStatus {
        exists: true,
        active_state: Some("inactive".to_string()),
        sub_state: Some("dead".to_string()),
        main_pid: Some(91),
    }));

    let mut backend = TestStartupBackend {
        process_seed,
        reporter: RecordingStatusReporter::default(),
        wait_port: ScriptedWaitPort::default(),
        cgroup_port: Arc::new(ScriptedCgroupPort::default()),
        container_runtime: Arc::new(ScriptedContainerRuntimePort::default()),
        systemd_runtime,
    };

    let pids: [u32; 0] = [];
    let tty_filters = std::collections::HashSet::new();
    let tty_inputs: Vec<String> = Vec::new();
    let containers: Vec<String> = Vec::new();
    let systemd_units = vec!["demo.service".to_string()];

    let plan = prepare_runtime_plan(
        &mut backend,
        StartupPrepareInputs {
            pids: &pids,
            tty_inputs: &tty_inputs,
            tty_filters: &tty_filters,
            containers: &containers,
            systemd_units: &systemd_units,
            watch_children: false,
            all_container_processes: false,
            all_systemd_processes: false,
            watch_flags: watch_flags(false),
            container_runtime_available: false,
            systemd_runtime_available: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(plan.systemd_runtimes.len(), 1);
    assert_eq!(plan.systemd_runtimes[0].current_pid, Some(91));
    assert!(!plan.systemd_runtimes[0].current_running);
    assert_eq!(plan.systemd_runtimes[0].seeded_pids, vec![91]);
    assert_eq!(
        plan.current_watch_roots,
        HashMap::from([(91, watch_flags(false))])
    );
    assert_eq!(
        plan.target_descriptions,
        vec!["systemd-units=[demo.service]".to_string()]
    );
    assert_eq!(
        backend.process_seed.direct_calls,
        vec![support::SeedDirectCall {
            pids: vec![91],
            flags: watch_flags(false),
        }]
    );
    assert!(backend.process_seed.task_iter_calls.is_empty());
}

#[tokio::test]
async fn prepare_runtime_plan_keeps_active_exited_systemd_unit_without_seeding() {
    let process_seed = RecordingProcessSeed::default();

    let systemd_runtime = Arc::new(ScriptedSystemdRuntimePort::default());
    systemd_runtime.push_current_status_result(Ok(SystemdUnitRuntimeStatus {
        exists: true,
        active_state: Some("active".to_string()),
        sub_state: Some("exited".to_string()),
        main_pid: None,
    }));

    let mut backend = TestStartupBackend {
        process_seed,
        reporter: RecordingStatusReporter::default(),
        wait_port: ScriptedWaitPort::default(),
        cgroup_port: Arc::new(ScriptedCgroupPort::default()),
        container_runtime: Arc::new(ScriptedContainerRuntimePort::default()),
        systemd_runtime,
    };

    let pids: [u32; 0] = [];
    let tty_filters = std::collections::HashSet::new();
    let tty_inputs: Vec<String> = Vec::new();
    let containers: Vec<String> = Vec::new();
    let systemd_units = vec!["oneshot.service".to_string()];

    let plan = prepare_runtime_plan(
        &mut backend,
        StartupPrepareInputs {
            pids: &pids,
            tty_inputs: &tty_inputs,
            tty_filters: &tty_filters,
            containers: &containers,
            systemd_units: &systemd_units,
            watch_children: false,
            all_container_processes: false,
            all_systemd_processes: false,
            watch_flags: watch_flags(false),
            container_runtime_available: false,
            systemd_runtime_available: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(plan.systemd_runtimes.len(), 1);
    assert_eq!(plan.systemd_runtimes[0].current_pid, None);
    assert!(plan.systemd_runtimes[0].current_running);
    assert!(plan.systemd_runtimes[0].seeded_pids.is_empty());
    assert_eq!(
        plan.target_descriptions,
        vec!["systemd-units=[oneshot.service]".to_string()]
    );
    assert!(backend.process_seed.task_iter_calls.is_empty());
    assert!(backend.process_seed.direct_calls.is_empty());
}

#[tokio::test]
async fn prepare_runtime_plan_seeds_all_systemd_processes_even_without_main_pid() {
    let mut process_seed = RecordingProcessSeed::default();
    process_seed.push_direct_result(Ok(()));

    let systemd_runtime = Arc::new(ScriptedSystemdRuntimePort::default());
    systemd_runtime.push_current_status_result(Ok(SystemdUnitRuntimeStatus {
        exists: true,
        active_state: Some("active".to_string()),
        sub_state: Some("running".to_string()),
        main_pid: None,
    }));
    systemd_runtime.push_unit_pids_result(Ok(vec![31, 32]));

    let mut backend = TestStartupBackend {
        process_seed,
        reporter: RecordingStatusReporter::default(),
        wait_port: ScriptedWaitPort::default(),
        cgroup_port: Arc::new(ScriptedCgroupPort::default()),
        container_runtime: Arc::new(ScriptedContainerRuntimePort::default()),
        systemd_runtime,
    };

    let pids: [u32; 0] = [];
    let tty_filters = std::collections::HashSet::new();
    let tty_inputs: Vec<String> = Vec::new();
    let containers: Vec<String> = Vec::new();
    let systemd_units = vec!["demo.service".to_string()];

    let plan = prepare_runtime_plan(
        &mut backend,
        StartupPrepareInputs {
            pids: &pids,
            tty_inputs: &tty_inputs,
            tty_filters: &tty_filters,
            containers: &containers,
            systemd_units: &systemd_units,
            watch_children: false,
            all_container_processes: false,
            all_systemd_processes: true,
            watch_flags: watch_flags(false),
            container_runtime_available: false,
            systemd_runtime_available: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(plan.systemd_runtimes.len(), 1);
    assert_eq!(plan.systemd_runtimes[0].current_pid, None);
    assert!(plan.systemd_runtimes[0].current_running);
    assert!(plan.systemd_runtimes[0].watch_children);
    assert_eq!(plan.systemd_runtimes[0].seeded_pids, vec![31, 32]);
    assert!(plan.current_watch_roots.is_empty());
    assert_eq!(
        plan.target_descriptions,
        vec!["systemd-units=[demo.service] seed=all-procs".to_string()]
    );
    assert_eq!(
        backend.process_seed.direct_calls,
        vec![support::SeedDirectCall {
            pids: vec![31, 32],
            flags: watch_flags(true),
        }]
    );
    assert!(backend.process_seed.task_iter_calls.is_empty());
}

#[tokio::test]
async fn handle_runtime_update_reseeds_container_pid_changes_and_refreshes_watch_roots() {
    let cgroup_port = Arc::new(ScriptedCgroupPort::default());
    let container_runtime_port = Arc::new(ScriptedContainerRuntimePort::default());

    let container_runtime = container_runtime(
        "web",
        true,
        false,
        watch_flags(true),
        Some(20),
        cgroup_port.clone(),
        container_runtime_port.clone(),
    );

    let mut backend = RuntimeUpdateHarness {
        process_seed: {
            let mut process_seed = RecordingProcessSeed::default();
            process_seed.push_direct_result(Ok(()));
            process_seed.push_task_iter_result(Ok(vec![21]));
            process_seed
        },
        reporter: RecordingStatusReporter::default(),
        watch_store: RecordingWatchPidStore::from_roots([
            (10, watch_flags(false)),
            (20, watch_flags(true)),
        ]),
        static_watch_roots: HashMap::from([(10, watch_flags(false))]),
        current_watch_roots: HashMap::from([(10, watch_flags(false)), (20, watch_flags(true))]),
        container_runtimes: vec![container_runtime],
        systemd_runtimes: vec![],
    };

    let keep_running = handle_runtime_update(
        &mut backend,
        Some(RuntimeUpdate::ContainerPid {
            index: 0,
            pid: Some(21),
            force_refresh: false,
            extra_pids: vec![99],
        }),
    )
    .await
    .unwrap();

    assert!(keep_running);
    assert_eq!(backend.container_runtimes[0].current_pid, Some(21));
    assert_eq!(
        backend.process_seed.direct_calls,
        vec![support::SeedDirectCall {
            pids: vec![99],
            flags: watch_flags(true),
        }]
    );
    assert_eq!(
        backend.process_seed.task_iter_calls,
        vec![support::SeedFromTaskIterCall {
            pid_roots: vec![21],
            tty_filters: std::collections::BTreeSet::new(),
            watch_flags: watch_flags(true),
        }]
    );
    assert_eq!(
        backend.current_watch_roots,
        HashMap::from([(10, watch_flags(false)), (21, watch_flags(true))])
    );
    assert_eq!(
        backend.watch_store.current,
        HashMap::from([(10, watch_flags(false)), (21, watch_flags(true))])
    );
    assert_eq!(
        backend.watch_store.ops,
        vec![WatchOp::Remove(20), WatchOp::Upsert(21, watch_flags(true))]
    );
    assert!(backend.reporter.warns.is_empty());
}

#[tokio::test]
async fn handle_runtime_update_reseeds_container_pid_even_when_it_is_unchanged_and_forced() {
    let cgroup_port = Arc::new(ScriptedCgroupPort::default());
    let container_runtime_port = Arc::new(ScriptedContainerRuntimePort::default());

    let container_runtime = container_runtime(
        "web",
        true,
        false,
        watch_flags(true),
        Some(21),
        cgroup_port.clone(),
        container_runtime_port.clone(),
    );

    let mut backend = RuntimeUpdateHarness {
        process_seed: {
            let mut process_seed = RecordingProcessSeed::default();
            process_seed.push_task_iter_result(Ok(vec![21]));
            process_seed
        },
        reporter: RecordingStatusReporter::default(),
        watch_store: RecordingWatchPidStore::from_roots([
            (10, watch_flags(false)),
            (21, watch_flags(true)),
        ]),
        static_watch_roots: HashMap::from([(10, watch_flags(false))]),
        current_watch_roots: HashMap::from([(10, watch_flags(false)), (21, watch_flags(true))]),
        container_runtimes: vec![container_runtime],
        systemd_runtimes: vec![],
    };

    let keep_running = handle_runtime_update(
        &mut backend,
        Some(RuntimeUpdate::ContainerPid {
            index: 0,
            pid: Some(21),
            force_refresh: true,
            extra_pids: Vec::new(),
        }),
    )
    .await
    .unwrap();

    assert!(keep_running);
    assert_eq!(
        backend.process_seed.task_iter_calls,
        vec![support::SeedFromTaskIterCall {
            pid_roots: vec![21],
            tty_filters: std::collections::BTreeSet::new(),
            watch_flags: watch_flags(true),
        }]
    );
    assert!(backend.process_seed.direct_calls.is_empty());
    assert_eq!(
        backend.watch_store.current,
        HashMap::from([(10, watch_flags(false)), (21, watch_flags(true))])
    );
    assert!(backend.watch_store.ops.is_empty());
}

#[tokio::test]
async fn handle_runtime_update_clears_and_reseeds_systemd_roots() {
    let systemd_runtime_port = Arc::new(ScriptedSystemdRuntimePort::default());
    systemd_runtime_port.push_unit_pids_result(Ok(vec![40, 41]));

    let systemd_runtime = systemd_runtime(
        "demo.service",
        false,
        true,
        watch_flags(true),
        Some(30),
        true,
        vec![30],
        systemd_runtime_port.clone(),
    );

    let mut backend = RuntimeUpdateHarness {
        process_seed: {
            let mut process_seed = RecordingProcessSeed::default();
            process_seed.push_direct_result(Ok(()));
            process_seed
        },
        reporter: RecordingStatusReporter::default(),
        watch_store: RecordingWatchPidStore::from_roots([
            (10, watch_flags(false)),
            (30, watch_flags(true)),
        ]),
        static_watch_roots: HashMap::from([(10, watch_flags(false))]),
        current_watch_roots: HashMap::from([(10, watch_flags(false)), (30, watch_flags(true))]),
        container_runtimes: vec![],
        systemd_runtimes: vec![systemd_runtime],
    };

    let keep_running = handle_runtime_update(
        &mut backend,
        Some(RuntimeUpdate::SystemdStatus {
            index: 0,
            pid: None,
            running: false,
            active_state: None,
            sub_state: None,
        }),
    )
    .await
    .unwrap();
    assert!(keep_running);
    assert!(backend.systemd_runtimes[0].seeded_pids.is_empty());
    assert!(!backend.systemd_runtimes[0].current_running);
    assert_eq!(
        backend.watch_store.current,
        HashMap::from([(10, watch_flags(false))])
    );
    assert_eq!(backend.watch_store.ops, vec![WatchOp::Remove(30)]);

    let keep_running = handle_runtime_update(
        &mut backend,
        Some(RuntimeUpdate::SystemdStatus {
            index: 0,
            pid: Some(40),
            running: true,
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
        }),
    )
    .await
    .unwrap();
    assert!(keep_running);
    assert_eq!(backend.systemd_runtimes[0].seeded_pids, vec![40, 41]);
    assert_eq!(backend.systemd_runtimes[0].current_pid, Some(40));
    assert!(backend.systemd_runtimes[0].current_running);
    assert_eq!(
        backend.process_seed.direct_calls,
        vec![support::SeedDirectCall {
            pids: vec![40, 41],
            flags: watch_flags(true),
        }]
    );
    assert_eq!(
        backend.watch_store.current,
        HashMap::from([(10, watch_flags(false)), (40, watch_flags(true))])
    );
    assert_eq!(
        backend.watch_store.ops,
        vec![WatchOp::Remove(30), WatchOp::Upsert(40, watch_flags(true))]
    );
}

#[tokio::test]
async fn handle_runtime_update_seeds_systemd_main_pid_before_unit_reports_running() {
    let systemd_runtime_port = Arc::new(ScriptedSystemdRuntimePort::default());
    systemd_runtime_port.push_unit_pids_result(Ok(vec![550233, 550292]));

    let systemd_runtime = systemd_runtime(
        "ollama.service",
        false,
        true,
        watch_flags(true),
        None,
        false,
        vec![],
        systemd_runtime_port.clone(),
    );

    let mut backend = RuntimeUpdateHarness {
        process_seed: {
            let mut process_seed = RecordingProcessSeed::default();
            process_seed.push_direct_result(Ok(()));
            process_seed
        },
        reporter: RecordingStatusReporter::default(),
        watch_store: RecordingWatchPidStore::from_roots([(10, watch_flags(false))]),
        static_watch_roots: HashMap::from([(10, watch_flags(false))]),
        current_watch_roots: HashMap::from([(10, watch_flags(false))]),
        container_runtimes: vec![],
        systemd_runtimes: vec![systemd_runtime],
    };

    let keep_running = handle_runtime_update(
        &mut backend,
        Some(RuntimeUpdate::SystemdStatus {
            index: 0,
            pid: Some(550233),
            running: false,
            active_state: Some("inactive".to_string()),
            sub_state: Some("dead".to_string()),
        }),
    )
    .await
    .unwrap();

    assert!(keep_running);
    assert_eq!(backend.systemd_runtimes[0].current_pid, Some(550233));
    assert!(!backend.systemd_runtimes[0].current_running);
    assert_eq!(
        backend.systemd_runtimes[0].seeded_pids,
        vec![550233, 550292]
    );
    assert_eq!(
        backend.process_seed.direct_calls,
        vec![support::SeedDirectCall {
            pids: vec![550233, 550292],
            flags: watch_flags(true),
        }]
    );
    assert_eq!(
        backend.watch_store.current,
        HashMap::from([(10, watch_flags(false)), (550233, watch_flags(true))])
    );
    assert_eq!(
        backend.watch_store.ops,
        vec![WatchOp::Upsert(550233, watch_flags(true))]
    );
}
