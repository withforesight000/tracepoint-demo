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
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::test_support::{
        MockCgroupPort, MockProcessSeedPort, MockStatusReporter, NoopContainerRuntimePort,
    };

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
            cgroup_port: Arc::new(MockCgroupPort::new()),
            runtime: Arc::new(NoopContainerRuntimePort),
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
        let mut process_seed = MockProcessSeedPort::new();
        let mut cgroup_port = MockCgroupPort::new();
        let mut reporter = MockStatusReporter::new();

        cgroup_port
            .expect_read_cgroup_v2_path()
            .times(1)
            .withf(|pid| *pid == 99)
            .return_once(|_| Ok("/demo".to_string()));
        cgroup_port
            .expect_read_cgroup_procs()
            .times(1)
            .withf(|path| path == "/demo")
            .return_once(|_| Ok(vec![11, 22]));
        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [11, 22] && *flags == 0x4)
            .return_once(|_, _| Ok(()));

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
    }

    #[tokio::test]
    async fn seed_container_processes_falls_back_to_task_iter_when_cgroup_lookup_fails() {
        let mut process_seed = MockProcessSeedPort::new();
        let mut cgroup_port = MockCgroupPort::new();
        let mut reporter = MockStatusReporter::new();
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let warnings_for_expectation = Arc::clone(&warnings);

        cgroup_port
            .expect_read_cgroup_v2_path()
            .times(1)
            .withf(|pid| *pid == 99)
            .return_once(|_| Err(anyhow::anyhow!("missing cgroup path")));
        reporter
            .expect_warn()
            .times(1)
            .withf(|message| message.contains("Falling back to task iterator seed"))
            .returning(move |message| {
                warnings_for_expectation.lock().unwrap().push(message);
            });
        process_seed
            .expect_seed_from_task_iter()
            .times(1)
            .withf(|pid_roots, tty_filters, watch_flags| {
                pid_roots == [99] && tty_filters.is_empty() && *watch_flags == 0x8
            })
            .return_once(|_, _, _| Ok(vec![99]));

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

        assert_eq!(warnings.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apply_container_runtime_update_short_circuits_when_pid_is_unchanged() {
        let mut process_seed = MockProcessSeedPort::new();
        let mut runtime = ContainerRuntime {
            cgroup_port: Arc::new(MockCgroupPort::new()),
            runtime: Arc::new(NoopContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x2,
            current_pid: Some(42),
        };
        let mut reporter = MockStatusReporter::new();

        apply_container_runtime_update(&mut process_seed, &mut reporter, &mut runtime, Some(42))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn seed_container_processes_uses_task_iter_when_watching_children() {
        let mut process_seed = MockProcessSeedPort::new();
        let cgroup_port = MockCgroupPort::new();
        let mut reporter = MockStatusReporter::new();

        process_seed
            .expect_seed_from_task_iter()
            .times(1)
            .withf(|pid_roots, tty_filters, watch_flags| {
                pid_roots == [42] && tty_filters.is_empty() && *watch_flags == 0x2
            })
            .return_once(|_, _, _| Ok(vec![42]));

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
    }

    #[tokio::test]
    async fn apply_container_runtime_update_updates_current_pid_after_successful_seed() {
        let mut process_seed = MockProcessSeedPort::new();
        let mut runtime = ContainerRuntime {
            cgroup_port: Arc::new(MockCgroupPort::new()),
            runtime: Arc::new(NoopContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x2,
            current_pid: None,
        };
        let mut reporter = MockStatusReporter::new();

        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [77] && *flags == 0x2)
            .return_once(|_, _| Ok(()));

        apply_container_runtime_update(&mut process_seed, &mut reporter, &mut runtime, Some(77))
            .await
            .unwrap();

        assert_eq!(runtime.current_pid, Some(77));
    }
}
