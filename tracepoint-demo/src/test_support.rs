use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::Mutex,
};

use mockall::mock;
use tokio::sync::mpsc;

use crate::usecase::port::{ContainerRuntimePort, RuntimeUpdate, SystemdRuntimePort, SystemdUnitRuntimeStatus};

pub fn boxed_future<T: Send + 'static>(value: T) -> Pin<Box<dyn Future<Output = T> + Send + 'static>> {
    Box::pin(async move { value })
}

pub fn spawn_noop_handle() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}

mock! {
    pub ProcessSeedPort {}

    impl crate::usecase::port::ProcessSeedPort for ProcessSeedPort {
        fn seed_from_task_iter(
            &mut self,
            pid_roots: &[u32],
            tty_filters: &HashSet<String>,
            watch_flags: u32,
        ) -> anyhow::Result<Vec<u32>>;

        fn seed_direct(&mut self, pids: &[u32], flags: u32) -> anyhow::Result<()>;
    }
}

mock! {
    pub CgroupPort {}

    impl crate::usecase::port::CgroupPort for CgroupPort {
        fn read_cgroup_v2_path(&self, pid: u32) -> anyhow::Result<String>;

        fn read_cgroup_procs(&self, path: &str) -> anyhow::Result<Vec<u32>>;
    }
}

mock! {
    pub StatusReporter {}

    impl crate::usecase::port::StatusReporter for StatusReporter {
        fn info(&mut self, message: String);

        fn warn(&mut self, message: String);
    }
}

pub struct NoopContainerRuntimePort;

impl ContainerRuntimePort for NoopContainerRuntimePort {
    fn query_main_pid<'a>(
        &'a self,
        _name_or_id: &'a str,
    ) -> crate::usecase::port::BoxFuture<'a, anyhow::Result<Option<u32>>> {
        boxed_future(Ok(None))
    }

    fn spawn_monitor(
        &self,
        _name_or_id: String,
        _tx: mpsc::UnboundedSender<RuntimeUpdate>,
        _index: usize,
    ) -> tokio::task::JoinHandle<()> {
        spawn_noop_handle()
    }
}

pub struct QueuedContainerRuntimePort {
    pids: Mutex<VecDeque<anyhow::Result<Option<u32>>>>,
}

impl QueuedContainerRuntimePort {
    pub fn new(pids: Vec<anyhow::Result<Option<u32>>>) -> Self {
        Self {
            pids: Mutex::new(pids.into()),
        }
    }
}

impl ContainerRuntimePort for QueuedContainerRuntimePort {
    fn query_main_pid<'a>(
        &'a self,
        _name_or_id: &'a str,
    ) -> crate::usecase::port::BoxFuture<'a, anyhow::Result<Option<u32>>> {
        let next = self.pids.lock().unwrap().pop_front().unwrap_or(Ok(None));
        boxed_future(next)
    }

    fn spawn_monitor(
        &self,
        _name_or_id: String,
        _tx: mpsc::UnboundedSender<RuntimeUpdate>,
        _index: usize,
    ) -> tokio::task::JoinHandle<()> {
        spawn_noop_handle()
    }
}

pub struct NoopSystemdRuntimePort;

impl SystemdRuntimePort for NoopSystemdRuntimePort {
    fn current_status<'a>(
        &'a self,
        _unit_name: &'a str,
    ) -> crate::usecase::port::BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
        boxed_future(Ok(SystemdUnitRuntimeStatus::missing()))
    }

    fn unit_pids<'a>(
        &'a self,
        _unit_name: &'a str,
    ) -> crate::usecase::port::BoxFuture<'a, anyhow::Result<Vec<u32>>> {
        boxed_future(Ok(Vec::new()))
    }

    fn spawn_monitor(
        &self,
        _unit_name: String,
        _tx: mpsc::UnboundedSender<RuntimeUpdate>,
        _index: usize,
    ) -> tokio::task::JoinHandle<()> {
        spawn_noop_handle()
    }
}

pub struct QueuedSystemdRuntimePort {
    statuses: Mutex<VecDeque<anyhow::Result<SystemdUnitRuntimeStatus>>>,
    unit_pids_result: Mutex<anyhow::Result<Vec<u32>>>,
}

impl QueuedSystemdRuntimePort {
    pub fn with_statuses(statuses: Vec<anyhow::Result<SystemdUnitRuntimeStatus>>) -> Self {
        Self {
            statuses: Mutex::new(statuses.into()),
            unit_pids_result: Mutex::new(Ok(Vec::new())),
        }
    }

    pub fn with_unit_pids_result(result: anyhow::Result<Vec<u32>>) -> Self {
        Self {
            statuses: Mutex::new(VecDeque::from([Ok(SystemdUnitRuntimeStatus::missing())])),
            unit_pids_result: Mutex::new(result),
        }
    }
}

impl SystemdRuntimePort for QueuedSystemdRuntimePort {
    fn current_status<'a>(
        &'a self,
        _unit_name: &'a str,
    ) -> crate::usecase::port::BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
        let next = self
            .statuses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(SystemdUnitRuntimeStatus::missing()));
        boxed_future(next)
    }

    fn unit_pids<'a>(
        &'a self,
        _unit_name: &'a str,
    ) -> crate::usecase::port::BoxFuture<'a, anyhow::Result<Vec<u32>>> {
        let result = match &*self.unit_pids_result.lock().unwrap() {
            Ok(pids) => Ok(pids.clone()),
            Err(err) => Err(anyhow::anyhow!(err.to_string())),
        };
        boxed_future(result)
    }

    fn spawn_monitor(
        &self,
        _unit_name: String,
        _tx: mpsc::UnboundedSender<RuntimeUpdate>,
        _index: usize,
    ) -> tokio::task::JoinHandle<()> {
        spawn_noop_handle()
    }
}

mock! {
    pub WaitPort {}

    impl crate::usecase::port::WaitPort for WaitPort {
        fn wait<'a>(
            &'a mut self,
            duration: std::time::Duration,
            interrupted_message: String,
        ) -> crate::usecase::port::BoxFuture<'a, anyhow::Result<()>>;
    }
}
