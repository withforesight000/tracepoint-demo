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
    pub seeded_pids: Vec<u32>,
    pub current_pid: Option<u32>,
}

pub struct ContainerSeedSpec<'a> {
    pub name_or_id: &'a str,
    pub main_pid: u32,
    pub flags: u32,
    pub watch_children: bool,
    pub all_processes: bool,
}

pub(crate) async fn seed_container_processes<TReporter: StatusReporter + ?Sized>(
    process_seed: &mut dyn ProcessSeedPort,
    reporter: &mut TReporter,
    cgroup_port: &dyn CgroupPort,
    spec: ContainerSeedSpec<'_>,
) -> anyhow::Result<Vec<u32>> {
    if spec.all_processes {
        match cgroup_port
            .read_cgroup_v2_path(spec.main_pid)
            .and_then(|path| cgroup_port.read_cgroup_procs(&path))
        {
            Ok(pids) => {
                process_seed.seed_direct(&pids, spec.flags)?;
                return Ok(pids);
            }
            Err(err) => {
                reporter.warn(format!(
                    "Failed to read cgroup.procs for container {} (pid {}): {}. Falling back to task iterator seed.",
                    spec.name_or_id, spec.main_pid, err
                ));
                let empty_tty_filters = HashSet::new();
                return process_seed.seed_from_task_iter(
                    &[spec.main_pid],
                    &empty_tty_filters,
                    spec.flags,
                );
            }
        }
    }

    if spec.watch_children {
        let empty_tty_filters = HashSet::new();
        return process_seed.seed_from_task_iter(&[spec.main_pid], &empty_tty_filters, spec.flags);
    } else {
        process_seed.seed_direct(&[spec.main_pid], spec.flags)?;
        return Ok(vec![spec.main_pid]);
    }
}

pub async fn apply_container_runtime_update<TReporter: StatusReporter + ?Sized>(
    process_seed: &mut dyn ProcessSeedPort,
    reporter: &mut TReporter,
    runtime: &mut ContainerRuntime,
    next_pid: Option<u32>,
    force_refresh: bool,
    extra_pids: &[u32],
) -> anyhow::Result<()> {
    if !force_refresh && runtime.current_pid == next_pid {
        log::debug!(
            "container {} update skipped: pid unchanged at {:?}",
            runtime.name_or_id,
            next_pid
        );
        return Ok(());
    }

    if let Some(pid) = next_pid {
        log::debug!(
            "container {} seeding pid {:?} (all_processes={}, watch_children={}, force_refresh={})",
            runtime.name_or_id,
            pid,
            runtime.all_processes,
            runtime.watch_children,
            force_refresh
        );
        if !extra_pids.is_empty() {
            log::debug!(
                "container {} seeding extra pid(s) {:?}",
                runtime.name_or_id,
                extra_pids
            );
            process_seed.seed_direct(extra_pids, runtime.flags)?;
        }
        let mut seeded_pids = seed_container_processes(
            process_seed,
            reporter,
            runtime.cgroup_port.as_ref(),
            ContainerSeedSpec {
                name_or_id: &runtime.name_or_id,
                main_pid: pid,
                flags: runtime.flags,
                watch_children: runtime.watch_children,
                all_processes: runtime.all_processes,
            },
        )
        .await?;
        seeded_pids.extend_from_slice(extra_pids);
        seeded_pids.sort_unstable();
        seeded_pids.dedup();
        runtime.seeded_pids = seeded_pids;
    } else {
        runtime.seeded_pids.clear();
    }

    runtime.current_pid = next_pid;
    log::debug!(
        "container {} current pid updated to {:?}",
        runtime.name_or_id,
        runtime.current_pid
    );
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
            runtime.runtime.spawn_monitor(
                runtime.name_or_id.clone(),
                runtime.all_processes,
                update_tx.clone(),
                index,
            )
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
            seeded_pids: Vec::new(),
            current_pid: None,
        };

        let handles = spawn_monitors(&[runtime], &tx);
        assert_eq!(handles.len(), 1);
    }

    #[tokio::test]
    async fn seed_container_processes_uses_direct_seed_for_all_processes_when_cgroup_lookup_succeeds()
     {
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
            &mut reporter,
            &cgroup_port,
            ContainerSeedSpec {
                name_or_id: "web",
                main_pid: 99,
                flags: 0x4,
                watch_children: true,
                all_processes: true,
            },
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
            &mut reporter,
            &cgroup_port,
            ContainerSeedSpec {
                name_or_id: "web",
                main_pid: 99,
                flags: 0x8,
                watch_children: true,
                all_processes: true,
            },
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
            seeded_pids: vec![42],
            current_pid: Some(42),
        };
        let mut reporter = MockStatusReporter::new();

        apply_container_runtime_update(
            &mut process_seed,
            &mut reporter,
            &mut runtime,
            Some(42),
            false,
            &[],
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn apply_container_runtime_update_forces_refresh_when_requested() {
        let mut process_seed = MockProcessSeedPort::new();
        let mut cgroup_port = MockCgroupPort::new();
        cgroup_port
            .expect_read_cgroup_v2_path()
            .times(1)
            .withf(|pid| *pid == 42)
            .return_once(|_| Ok("/demo".to_string()));
        cgroup_port
            .expect_read_cgroup_procs()
            .times(1)
            .withf(|path| path == "/demo")
            .return_once(|_| Ok(vec![42, 99]));
        let mut runtime = ContainerRuntime {
            cgroup_port: Arc::new(cgroup_port),
            runtime: Arc::new(NoopContainerRuntimePort),
            name_or_id: "web".to_string(),
            watch_children: false,
            all_processes: true,
            flags: 0x2,
            seeded_pids: Vec::new(),
            current_pid: Some(42),
        };
        let mut reporter = MockStatusReporter::new();

        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [42, 99] && *flags == 0x2)
            .return_once(|_, _| Ok(()));

        apply_container_runtime_update(
            &mut process_seed,
            &mut reporter,
            &mut runtime,
            Some(42),
            true,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(runtime.current_pid, Some(42));
        assert_eq!(runtime.seeded_pids, vec![42, 99]);
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
            &mut reporter,
            &cgroup_port,
            ContainerSeedSpec {
                name_or_id: "web",
                main_pid: 42,
                flags: 0x2,
                watch_children: true,
                all_processes: false,
            },
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
            seeded_pids: Vec::new(),
            current_pid: None,
        };
        let mut reporter = MockStatusReporter::new();

        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [77] && *flags == 0x2)
            .return_once(|_, _| Ok(()));

        apply_container_runtime_update(
            &mut process_seed,
            &mut reporter,
            &mut runtime,
            Some(77),
            false,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(runtime.current_pid, Some(77));
        assert_eq!(runtime.seeded_pids, vec![77]);
    }
}
