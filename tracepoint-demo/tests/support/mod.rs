use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::Mutex,
    time::Duration,
};

use tokio::task::JoinHandle;

use tracepoint_demo::integration::{
    BoxFuture, CgroupPort, ContainerRuntime, ContainerRuntimePort, ProcessSeedPort, RuntimeUpdate,
    SharedCgroupPort, SharedContainerRuntimePort, SharedSystemdRuntimePort, StatusReporter,
    SystemdRuntime, SystemdRuntimePort, SystemdUnitRuntimeStatus, WaitPort, WatchPidStore,
};

pub fn boxed_future<T: Send + 'static>(
    value: T,
) -> Pin<Box<dyn Future<Output = T> + Send + 'static>> {
    Box::pin(async move { value })
}

pub fn spawn_noop_handle() -> JoinHandle<()> {
    tokio::spawn(async {})
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedFromTaskIterCall {
    pub pid_roots: Vec<u32>,
    pub tty_filters: BTreeSet<String>,
    pub watch_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedDirectCall {
    pub pids: Vec<u32>,
    pub flags: u32,
}

#[derive(Default)]
pub struct RecordingProcessSeed {
    pub task_iter_calls: Vec<SeedFromTaskIterCall>,
    pub direct_calls: Vec<SeedDirectCall>,
    pub task_iter_results: VecDeque<anyhow::Result<Vec<u32>>>,
    pub direct_results: VecDeque<anyhow::Result<()>>,
}

impl RecordingProcessSeed {
    pub fn push_task_iter_result(&mut self, result: anyhow::Result<Vec<u32>>) {
        self.task_iter_results.push_back(result);
    }

    pub fn push_direct_result(&mut self, result: anyhow::Result<()>) {
        self.direct_results.push_back(result);
    }
}

impl ProcessSeedPort for RecordingProcessSeed {
    fn seed_from_task_iter(
        &mut self,
        pid_roots: &[u32],
        tty_filters: &HashSet<String>,
        watch_flags: u32,
    ) -> anyhow::Result<Vec<u32>> {
        self.task_iter_calls.push(SeedFromTaskIterCall {
            pid_roots: pid_roots.to_vec(),
            tty_filters: tty_filters.iter().cloned().collect(),
            watch_flags,
        });
        self.task_iter_results
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected seed_from_task_iter call for {pid_roots:?}"))
    }

    fn seed_direct(&mut self, pids: &[u32], flags: u32) -> anyhow::Result<()> {
        self.direct_calls.push(SeedDirectCall {
            pids: pids.to_vec(),
            flags,
        });
        self.direct_results
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected seed_direct call for {pids:?}"))
    }
}

#[derive(Default)]
pub struct RecordingStatusReporter {
    pub infos: Vec<String>,
    pub warns: Vec<String>,
}

impl StatusReporter for RecordingStatusReporter {
    fn info(&mut self, message: String) {
        self.infos.push(message);
    }

    fn warn(&mut self, message: String) {
        self.warns.push(message);
    }
}

#[derive(Default)]
pub struct ScriptedWaitPort {
    pub calls: Vec<(Duration, String)>,
    pub results: VecDeque<anyhow::Result<()>>,
}

impl ScriptedWaitPort {
    pub fn push_result(&mut self, result: anyhow::Result<()>) {
        self.results.push_back(result);
    }
}

impl WaitPort for ScriptedWaitPort {
    fn wait<'a>(
        &'a mut self,
        duration: Duration,
        interrupted_message: String,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        self.calls.push((duration, interrupted_message));
        let result = self
            .results
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected wait call"));
        boxed_future(result)
    }
}

pub struct ScriptedCgroupPort {
    pub read_cgroup_v2_path_calls: Mutex<Vec<u32>>,
    pub read_cgroup_procs_calls: Mutex<Vec<String>>,
    pub read_cgroup_v2_path_results: Mutex<VecDeque<anyhow::Result<String>>>,
    pub read_cgroup_procs_results: Mutex<VecDeque<anyhow::Result<Vec<u32>>>>,
}

impl ScriptedCgroupPort {
    pub fn new() -> Self {
        Self {
            read_cgroup_v2_path_calls: Mutex::new(Vec::new()),
            read_cgroup_procs_calls: Mutex::new(Vec::new()),
            read_cgroup_v2_path_results: Mutex::new(VecDeque::new()),
            read_cgroup_procs_results: Mutex::new(VecDeque::new()),
        }
    }

    pub fn push_read_cgroup_v2_path_result(&self, result: anyhow::Result<String>) {
        self.read_cgroup_v2_path_results
            .lock()
            .unwrap()
            .push_back(result);
    }

    pub fn push_read_cgroup_procs_result(&self, result: anyhow::Result<Vec<u32>>) {
        self.read_cgroup_procs_results
            .lock()
            .unwrap()
            .push_back(result);
    }
}

impl Default for ScriptedCgroupPort {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupPort for ScriptedCgroupPort {
    fn read_cgroup_v2_path(&self, pid: u32) -> anyhow::Result<String> {
        self.read_cgroup_v2_path_calls.lock().unwrap().push(pid);
        self.read_cgroup_v2_path_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected read_cgroup_v2_path call for pid {pid}"))
    }

    fn read_cgroup_procs(&self, path: &str) -> anyhow::Result<Vec<u32>> {
        self.read_cgroup_procs_calls
            .lock()
            .unwrap()
            .push(path.to_string());
        self.read_cgroup_procs_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected read_cgroup_procs call for path {path}"))
    }
}

pub struct ScriptedContainerRuntimePort {
    pub query_main_pid_calls: Mutex<Vec<String>>,
    pub spawn_monitor_calls: Mutex<Vec<(String, bool, usize)>>,
    pub query_main_pid_results: Mutex<VecDeque<anyhow::Result<Option<u32>>>>,
}

impl ScriptedContainerRuntimePort {
    pub fn new() -> Self {
        Self {
            query_main_pid_calls: Mutex::new(Vec::new()),
            spawn_monitor_calls: Mutex::new(Vec::new()),
            query_main_pid_results: Mutex::new(VecDeque::new()),
        }
    }

    pub fn push_query_main_pid_result(&self, result: anyhow::Result<Option<u32>>) {
        self.query_main_pid_results
            .lock()
            .unwrap()
            .push_back(result);
    }
}

impl Default for ScriptedContainerRuntimePort {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerRuntimePort for ScriptedContainerRuntimePort {
    fn query_main_pid<'a>(
        &'a self,
        name_or_id: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<Option<u32>>> {
        self.query_main_pid_calls
            .lock()
            .unwrap()
            .push(name_or_id.to_string());
        let result = self
            .query_main_pid_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected query_main_pid call for {name_or_id}"));
        boxed_future(result)
    }

    fn spawn_monitor(
        &self,
        name_or_id: String,
        all_processes: bool,
        _tx: tokio::sync::mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> JoinHandle<()> {
        self.spawn_monitor_calls
            .lock()
            .unwrap()
            .push((name_or_id, all_processes, index));
        spawn_noop_handle()
    }
}

pub struct ScriptedSystemdRuntimePort {
    pub current_status_calls: Mutex<Vec<String>>,
    pub unit_pids_calls: Mutex<Vec<String>>,
    pub spawn_monitor_calls: Mutex<Vec<(String, usize)>>,
    pub current_status_results: Mutex<VecDeque<anyhow::Result<SystemdUnitRuntimeStatus>>>,
    pub unit_pids_results: Mutex<VecDeque<anyhow::Result<Vec<u32>>>>,
}

impl ScriptedSystemdRuntimePort {
    pub fn new() -> Self {
        Self {
            current_status_calls: Mutex::new(Vec::new()),
            unit_pids_calls: Mutex::new(Vec::new()),
            spawn_monitor_calls: Mutex::new(Vec::new()),
            current_status_results: Mutex::new(VecDeque::new()),
            unit_pids_results: Mutex::new(VecDeque::new()),
        }
    }

    pub fn push_current_status_result(&self, result: anyhow::Result<SystemdUnitRuntimeStatus>) {
        self.current_status_results
            .lock()
            .unwrap()
            .push_back(result);
    }

    pub fn push_unit_pids_result(&self, result: anyhow::Result<Vec<u32>>) {
        self.unit_pids_results.lock().unwrap().push_back(result);
    }
}

impl Default for ScriptedSystemdRuntimePort {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemdRuntimePort for ScriptedSystemdRuntimePort {
    fn current_status<'a>(
        &'a self,
        unit_name: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
        self.current_status_calls
            .lock()
            .unwrap()
            .push(unit_name.to_string());
        let result = self
            .current_status_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected current_status call for {unit_name}"));
        boxed_future(result)
    }

    fn unit_pids<'a>(&'a self, unit_name: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<u32>>> {
        self.unit_pids_calls
            .lock()
            .unwrap()
            .push(unit_name.to_string());
        let result = self
            .unit_pids_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected unit_pids call for {unit_name}"));
        boxed_future(result)
    }

    fn spawn_monitor(
        &self,
        unit_name: String,
        _tx: tokio::sync::mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> JoinHandle<()> {
        self.spawn_monitor_calls
            .lock()
            .unwrap()
            .push((unit_name, index));
        spawn_noop_handle()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchOp {
    Remove(u32),
    Upsert(u32, u32),
}

#[derive(Default)]
pub struct RecordingWatchPidStore {
    pub current: HashMap<u32, u32>,
    pub ops: Vec<WatchOp>,
}

impl RecordingWatchPidStore {
    pub fn from_roots<I>(roots: I) -> Self
    where
        I: IntoIterator<Item = (u32, u32)>,
    {
        Self {
            current: roots.into_iter().collect(),
            ops: Vec::new(),
        }
    }
}

impl WatchPidStore for RecordingWatchPidStore {
    fn remove_watch_pid(&mut self, pid: u32) -> anyhow::Result<()> {
        self.ops.push(WatchOp::Remove(pid));
        self.current.remove(&pid);
        Ok(())
    }

    fn upsert_watch_pid(&mut self, pid: u32, flags: u32) -> anyhow::Result<()> {
        self.ops.push(WatchOp::Upsert(pid, flags));
        self.current.insert(pid, flags);
        Ok(())
    }
}

pub fn container_runtime(
    name_or_id: &str,
    watch_children: bool,
    all_processes: bool,
    flags: u32,
    current_pid: Option<u32>,
    cgroup_port: SharedCgroupPort,
    runtime: SharedContainerRuntimePort,
) -> ContainerRuntime {
    ContainerRuntime {
        cgroup_port,
        runtime,
        name_or_id: name_or_id.to_string(),
        watch_children,
        all_processes,
        flags,
        seeded_pids: current_pid.into_iter().collect(),
        current_pid,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn systemd_runtime(
    unit_name: &str,
    watch_children: bool,
    all_processes: bool,
    flags: u32,
    current_pid: Option<u32>,
    current_running: bool,
    seeded_pids: Vec<u32>,
    runtime: SharedSystemdRuntimePort,
) -> SystemdRuntime {
    let (current_active_state, current_sub_state) = if current_running {
        (Some("active".to_string()), Some("running".to_string()))
    } else {
        (Some("inactive".to_string()), Some("dead".to_string()))
    };

    SystemdRuntime {
        runtime,
        unit_name: unit_name.to_string(),
        watch_children,
        all_processes,
        seeded_pids,
        flags,
        current_pid,
        current_running,
        current_active_state,
        current_sub_state,
    }
}

pub fn running_status(main_pid: u32) -> SystemdUnitRuntimeStatus {
    SystemdUnitRuntimeStatus {
        exists: true,
        active_state: Some("active".to_string()),
        sub_state: Some("running".to_string()),
        main_pid: Some(main_pid),
    }
}
