use std::collections::HashSet;

use tokio::sync::mpsc;

use crate::usecase::port::{
    CgroupPort, ProcessSeedPort, RuntimeUpdate, SharedCgroupPort, SharedContainerRuntimePort,
    StatusReporter,
};

pub struct ContainerRuntime {
    pub cgroup_port: SharedCgroupPort,
    pub runtime: SharedContainerRuntimePort,
    pub name_or_id: String,
    pub watch_children: bool,
    pub all_processes: bool,
    pub flags: u32,
    pub current_pid: Option<u32>,
}

pub async fn seed_container_processes<TReporter: StatusReporter + ?Sized>(
    process_seed: &mut dyn ProcessSeedPort,
    cgroup_port: &dyn CgroupPort,
    reporter: &mut TReporter,
    name_or_id: &str,
    main_pid: u32,
    container_flags: u32,
    container_watch_children: bool,
    all_container_processes: bool,
) -> anyhow::Result<()> {
    if all_container_processes {
        match cgroup_port
            .read_cgroup_v2_path(main_pid)
            .and_then(|path| cgroup_port.read_cgroup_procs(&path))
        {
            Ok(pids) => process_seed.seed_direct(&pids, container_flags)?,
            Err(err) => {
                reporter.warn(format!(
                    "Failed to read cgroup.procs for container {} (pid {}): {}. Falling back to task iterator seed.",
                    name_or_id, main_pid, err
                ));
                let empty_tty_filters = HashSet::new();
                let _ =
                    process_seed.seed_from_task_iter(&[main_pid], &empty_tty_filters, container_flags)?;
            }
        }
        return Ok(());
    }

    if container_watch_children {
        let empty_tty_filters = HashSet::new();
        let _ = process_seed.seed_from_task_iter(&[main_pid], &empty_tty_filters, container_flags)?;
    } else {
        process_seed.seed_direct(&[main_pid], container_flags)?;
    }

    Ok(())
}

pub async fn apply_container_runtime_update<TReporter: StatusReporter + ?Sized>(
    process_seed: &mut dyn ProcessSeedPort,
    reporter: &mut TReporter,
    runtime: &mut ContainerRuntime,
    next_pid: Option<u32>,
) -> anyhow::Result<()> {
    if runtime.current_pid == next_pid {
        return Ok(());
    }

    if let Some(pid) = next_pid {
        seed_container_processes(
            process_seed,
            runtime.cgroup_port.as_ref(),
            reporter,
            &runtime.name_or_id,
            pid,
            runtime.flags,
            runtime.watch_children,
            runtime.all_processes,
        )
        .await?;
    }

    runtime.current_pid = next_pid;
    Ok(())
}

pub fn spawn_monitors(
    container_runtimes: &[ContainerRuntime],
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    container_runtimes
        .iter()
        .enumerate()
        .map(|(index, runtime)| {
            runtime
                .runtime
                .spawn_monitor(runtime.name_or_id.clone(), update_tx.clone(), index)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::{Arc, Mutex}};

    use super::*;
    use crate::usecase::port::{BoxFuture, ContainerRuntimePort, RuntimeUpdate};

    struct FakeProcessSeedPort {
        direct_calls: Mutex<Vec<(Vec<u32>, u32)>>,
        task_iter_calls: Mutex<Vec<(Vec<u32>, HashSet<String>, u32)>>,
        task_iter_result: Mutex<anyhow::Result<Vec<u32>>>,
        direct_result: Mutex<anyhow::Result<()>>,
    }

    impl FakeProcessSeedPort {
        fn with_results(task_iter_result: anyhow::Result<Vec<u32>>, direct_result: anyhow::Result<()>) -> Self {
            Self {
                direct_calls: Mutex::new(Vec::new()),
                task_iter_calls: Mutex::new(Vec::new()),
                task_iter_result: Mutex::new(task_iter_result),
                direct_result: Mutex::new(direct_result),
            }
        }
    }

    impl Default for FakeProcessSeedPort {
        fn default() -> Self {
            Self::with_results(Ok(Vec::new()), Ok(()))
        }
    }

    impl ProcessSeedPort for FakeProcessSeedPort {
        fn seed_from_task_iter(
            &mut self,
            pid_roots: &[u32],
            tty_filters: &HashSet<String>,
            watch_flags: u32,
        ) -> anyhow::Result<Vec<u32>> {
            self.task_iter_calls.lock().unwrap().push((
                pid_roots.to_vec(),
                tty_filters.clone(),
                watch_flags,
            ));
            match &*self.task_iter_result.lock().unwrap() {
                Ok(roots) => Ok(roots.clone()),
                Err(err) => Err(anyhow::anyhow!(err.to_string())),
            }
        }

        fn seed_direct(&mut self, pids: &[u32], flags: u32) -> anyhow::Result<()> {
            self.direct_calls.lock().unwrap().push((pids.to_vec(), flags));
            match &*self.direct_result.lock().unwrap() {
                Ok(()) => Ok(()),
                Err(err) => Err(anyhow::anyhow!(err.to_string())),
            }
        }
    }

    struct FakeCgroupPort {
        path_result: Mutex<anyhow::Result<String>>,
        procs_result: Mutex<anyhow::Result<Vec<u32>>>,
    }

    impl FakeCgroupPort {
        fn with_results(path_result: anyhow::Result<String>, procs_result: anyhow::Result<Vec<u32>>) -> Self {
            Self {
                path_result: Mutex::new(path_result),
                procs_result: Mutex::new(procs_result),
            }
        }
    }

    impl Default for FakeCgroupPort {
        fn default() -> Self {
            Self::with_results(Ok("/demo".to_string()), Ok(Vec::new()))
        }
    }

    impl CgroupPort for FakeCgroupPort {
        fn read_cgroup_v2_path(&self, _pid: u32) -> anyhow::Result<String> {
            match &*self.path_result.lock().unwrap() {
                Ok(path) => Ok(path.clone()),
                Err(err) => Err(anyhow::anyhow!(err.to_string())),
            }
        }

        fn read_cgroup_procs(&self, _path: &str) -> anyhow::Result<Vec<u32>> {
            match &*self.procs_result.lock().unwrap() {
                Ok(pids) => Ok(pids.clone()),
                Err(err) => Err(anyhow::anyhow!(err.to_string())),
            }
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

    #[tokio::test]
    async fn spawn_monitors_empty_returns_empty() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let handles = spawn_monitors(&[], &tx);
        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn spawn_monitors_non_empty_returns_handles() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let runtime = ContainerRuntime {
            cgroup_port: Arc::new(FakeCgroupPort::default()),
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "dummy".to_string(),
            watch_children: true,
            all_processes: false,
            flags: 0,
            current_pid: None,
        };

        let handles = spawn_monitors(&[runtime], &tx);
        assert_eq!(handles.len(), 1);
    }

    #[tokio::test]
    async fn seed_container_processes_uses_direct_seed_for_all_processes_when_cgroup_lookup_succeeds() {
        let mut process_seed = FakeProcessSeedPort::with_results(Ok(Vec::new()), Ok(()));
        let cgroup_port = FakeCgroupPort::with_results(Ok("/demo".to_string()), Ok(vec![11, 22]));
        let mut reporter = FakeReporter::default();

        seed_container_processes(
            &mut process_seed,
            &cgroup_port,
            &mut reporter,
            "web",
            99,
            0x4,
            true,
            true,
        )
        .await
        .unwrap();

        assert_eq!(process_seed.direct_calls.lock().unwrap().clone(), vec![(vec![11, 22], 0x4)]);
        assert!(process_seed.task_iter_calls.lock().unwrap().is_empty());
        assert!(reporter.warnings.is_empty());
    }

    #[tokio::test]
    async fn seed_container_processes_falls_back_to_task_iter_when_cgroup_lookup_fails() {
        let mut process_seed = FakeProcessSeedPort::with_results(Ok(vec![99]), Ok(()));
        let cgroup_port = FakeCgroupPort::with_results(
            Err(anyhow::anyhow!("missing cgroup path")),
            Ok(Vec::new()),
        );
        let mut reporter = FakeReporter::default();

        seed_container_processes(
            &mut process_seed,
            &cgroup_port,
            &mut reporter,
            "web",
            99,
            0x8,
            true,
            true,
        )
        .await
        .unwrap();

        assert!(process_seed.direct_calls.lock().unwrap().is_empty());
        assert_eq!(process_seed.task_iter_calls.lock().unwrap().len(), 1);
        assert_eq!(reporter.warnings.len(), 1);
        assert!(reporter.warnings[0].contains("Falling back to task iterator seed"));
    }

    #[tokio::test]
    async fn apply_container_runtime_update_short_circuits_when_pid_is_unchanged() {
        let mut process_seed = FakeProcessSeedPort::default();
        let mut runtime = ContainerRuntime {
            cgroup_port: Arc::new(FakeCgroupPort::default()),
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x2,
            current_pid: Some(42),
        };
        let mut reporter = FakeReporter::default();

        apply_container_runtime_update(&mut process_seed, &mut reporter, &mut runtime, Some(42))
            .await
            .unwrap();

        assert!(process_seed.direct_calls.lock().unwrap().is_empty());
        assert!(process_seed.task_iter_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn seed_container_processes_uses_task_iter_when_watching_children() {
        let mut process_seed = FakeProcessSeedPort::with_results(Ok(vec![42]), Ok(()));
        let cgroup_port = FakeCgroupPort::default();
        let mut reporter = FakeReporter::default();

        seed_container_processes(
            &mut process_seed,
            &cgroup_port,
            &mut reporter,
            "web",
            42,
            0x2,
            true,
            false,
        )
        .await
        .unwrap();

        assert!(process_seed.direct_calls.lock().unwrap().is_empty());
        assert_eq!(process_seed.task_iter_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apply_container_runtime_update_updates_current_pid_after_successful_seed() {
        let mut process_seed = FakeProcessSeedPort::with_results(Ok(Vec::new()), Ok(()));
        let mut runtime = ContainerRuntime {
            cgroup_port: Arc::new(FakeCgroupPort::default()),
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x2,
            current_pid: None,
        };
        let mut reporter = FakeReporter::default();

        apply_container_runtime_update(&mut process_seed, &mut reporter, &mut runtime, Some(77))
            .await
            .unwrap();

        assert_eq!(runtime.current_pid, Some(77));
        assert_eq!(process_seed.direct_calls.lock().unwrap().clone(), vec![(vec![77], 0x2)]);
    }
}
