use std::collections::{HashMap as StdHashMap, HashSet};

use tracepoint_demo_common::{PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

use crate::usecase::{
    orchestration::watch_roots::add_watch_root,
    policy::{
        watch_container::{ContainerRuntime, ContainerSeedSpec, seed_container_processes},
        watch_pid_or_tty::wait_pid_or_tty_targets,
        watch_systemd_unit::{SystemdRuntime, SystemdSeedSpec, seed_systemd_unit_processes},
    },
    port::{
        ProcessSeedPort, SharedCgroupPort, SharedContainerRuntimePort, SharedSystemdRuntimePort,
        StatusReporter, WaitPort,
    },
};

pub struct StaticWatchRootsSpec<'a> {
    pub pids: &'a [u32],
    pub tty_filters: &'a HashSet<String>,
    pub tty_inputs: &'a [String],
    pub watch_flags: u32,
    pub has_runtime_targets: bool,
}

pub async fn collect_static_watch_roots<
    TReporter: StatusReporter + ?Sized,
    TWait: WaitPort + ?Sized,
>(
    process_seed: &mut dyn ProcessSeedPort,
    spec: StaticWatchRootsSpec<'_>,
    reporter: &mut TReporter,
    wait_port: &mut TWait,
) -> anyhow::Result<StdHashMap<u32, u32>> {
    let mut static_watch_roots = StdHashMap::new();

    if spec.pids.is_empty() && spec.tty_filters.is_empty() {
        return Ok(static_watch_roots);
    }

    let roots = process_seed.seed_from_task_iter(spec.pids, spec.tty_filters, spec.watch_flags)?;
    for pid in roots {
        add_watch_root(&mut static_watch_roots, pid, spec.watch_flags);
    }

    if static_watch_roots.is_empty() && !spec.has_runtime_targets {
        let roots = wait_pid_or_tty_targets(
            process_seed,
            spec.pids,
            spec.tty_filters,
            spec.tty_inputs,
            spec.watch_flags,
            reporter,
            wait_port,
        )
        .await?;
        for pid in roots {
            add_watch_root(&mut static_watch_roots, pid, spec.watch_flags);
        }
    }

    Ok(static_watch_roots)
}

pub async fn initialize_container_runtimes<TReporter: StatusReporter + ?Sized>(
    process_seed: &mut dyn ProcessSeedPort,
    cgroup_port: &SharedCgroupPort,
    reporter: &mut TReporter,
    runtime: &SharedContainerRuntimePort,
    containers: &[String],
    watch_children: bool,
    all_container_processes: bool,
) -> anyhow::Result<Vec<ContainerRuntime>> {
    let mut container_runtimes = Vec::new();
    if containers.is_empty() {
        return Ok(container_runtimes);
    }

    for container_name in containers {
        let container_watch_children = if all_container_processes {
            true
        } else {
            watch_children
        };
        let container_flags = PROC_FLAG_WATCH_SELF
            | if container_watch_children {
                PROC_FLAG_WATCH_CHILDREN
            } else {
                0
            };

        let current_pid = runtime.query_main_pid(container_name).await?;
        let seeded_pids = if let Some(main_pid) = current_pid {
            seed_container_processes(
                process_seed,
                reporter,
                cgroup_port.as_ref(),
                ContainerSeedSpec {
                    name_or_id: container_name,
                    main_pid,
                    flags: container_flags,
                    watch_children: container_watch_children,
                    all_processes: all_container_processes,
                },
            )
            .await?
        } else {
            Vec::new()
        };

        container_runtimes.push(ContainerRuntime {
            cgroup_port: cgroup_port.clone(),
            runtime: runtime.clone(),
            name_or_id: container_name.clone(),
            watch_children: container_watch_children,
            all_processes: all_container_processes,
            flags: container_flags,
            seeded_pids,
            current_pid,
        });
    }

    Ok(container_runtimes)
}

pub async fn initialize_systemd_runtimes<
    TReporter: StatusReporter + ?Sized,
    TWait: WaitPort + ?Sized,
>(
    process_seed: &mut dyn ProcessSeedPort,
    reporter: &mut TReporter,
    _wait_port: &mut TWait,
    runtime: &SharedSystemdRuntimePort,
    systemd_units: &[String],
    watch_children: bool,
    all_systemd_processes: bool,
) -> anyhow::Result<Vec<SystemdRuntime>> {
    let mut systemd_runtimes = Vec::new();
    if systemd_units.is_empty() {
        return Ok(systemd_runtimes);
    }

    for unit_name in systemd_units {
        let unit_watch_children = if all_systemd_processes {
            true
        } else {
            watch_children
        };
        let unit_flags = PROC_FLAG_WATCH_SELF
            | if unit_watch_children {
                PROC_FLAG_WATCH_CHILDREN
            } else {
                0
            };

        let status = runtime.current_status(unit_name).await?;
        let current_running = status.is_running();
        let seeded_pids = if status.main_pid.is_some() || (current_running && all_systemd_processes)
        {
            seed_systemd_unit_processes(
                process_seed,
                reporter,
                runtime.as_ref(),
                SystemdSeedSpec {
                    unit_name,
                    main_pid: status.main_pid,
                    flags: unit_flags,
                    watch_children: unit_watch_children,
                    all_processes: all_systemd_processes,
                },
            )
            .await?
        } else {
            Vec::new()
        };

        systemd_runtimes.push(SystemdRuntime {
            runtime: runtime.clone(),
            unit_name: unit_name.clone(),
            watch_children: unit_watch_children,
            all_processes: all_systemd_processes,
            seeded_pids,
            flags: unit_flags,
            current_pid: status.main_pid,
            current_running,
            current_active_state: status.active_state.clone(),
            current_sub_state: status.sub_state.clone(),
        });
    }

    Ok(systemd_runtimes)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::test_support::{
        MockCgroupPort, MockProcessSeedPort, MockStatusReporter, MockWaitPort,
        QueuedContainerRuntimePort, QueuedSystemdRuntimePort, boxed_future,
    };
    use crate::usecase::port::SystemdUnitRuntimeStatus;

    #[tokio::test]
    async fn collect_static_watch_roots_returns_empty_without_inputs() {
        let mut process_seed = MockProcessSeedPort::new();
        let mut reporter = MockStatusReporter::new();
        let mut wait_port = MockWaitPort::new();

        let roots = collect_static_watch_roots(
            &mut process_seed,
            StaticWatchRootsSpec {
                pids: &[],
                tty_filters: &HashSet::new(),
                tty_inputs: &[],
                watch_flags: 0x1,
                has_runtime_targets: false,
            },
            &mut reporter,
            &mut wait_port,
        )
        .await
        .unwrap();

        assert!(roots.is_empty());
    }

    #[tokio::test]
    async fn collect_static_watch_roots_waits_when_no_runtime_targets_and_first_seed_is_empty() {
        let results = Arc::new(Mutex::new(VecDeque::from([
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(vec![41]),
        ])));
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_from_task_iter()
            .times(3)
            .returning({
                let results = Arc::clone(&results);
                move |pid_roots, tty_filters, watch_flags| {
                    assert_eq!(pid_roots, [41]);
                    assert!(tty_filters.is_empty());
                    assert_eq!(watch_flags, 0x2);
                    results.lock().unwrap().pop_front().unwrap()
                }
            });
        let mut reporter = MockStatusReporter::new();
        reporter.expect_warn().times(1).return_const(());
        let mut wait_port = MockWaitPort::new();
        wait_port
            .expect_wait()
            .times(1)
            .returning(|_, _| boxed_future(Ok(())));

        let roots = collect_static_watch_roots(
            &mut process_seed,
            StaticWatchRootsSpec {
                pids: &[41],
                tty_filters: &HashSet::new(),
                tty_inputs: &["pts/1".to_string()],
                watch_flags: 0x2,
                has_runtime_targets: false,
            },
            &mut reporter,
            &mut wait_port,
        )
        .await
        .unwrap();

        assert_eq!(roots, StdHashMap::from([(41, 0x2)]));
    }

    #[tokio::test]
    async fn initialize_container_runtimes_forces_watch_children_for_all_processes() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| {
                pids == [50, 51] && *flags == (PROC_FLAG_WATCH_SELF | PROC_FLAG_WATCH_CHILDREN)
            })
            .returning(|_, _| Ok(()));
        let mut cgroup_port = MockCgroupPort::new();
        cgroup_port
            .expect_read_cgroup_v2_path()
            .times(1)
            .withf(|pid| *pid == 50)
            .returning(|_| Ok("/demo".to_string()));
        cgroup_port
            .expect_read_cgroup_procs()
            .times(1)
            .withf(|path| path == "/demo")
            .returning(|_| Ok(vec![50, 51]));
        let cgroup_port: SharedCgroupPort = Arc::new(cgroup_port);
        let runtime: SharedContainerRuntimePort =
            Arc::new(QueuedContainerRuntimePort::new(vec![Ok(Some(50))]));
        let mut reporter = MockStatusReporter::new();

        let runtimes = initialize_container_runtimes(
            &mut process_seed,
            &cgroup_port,
            &mut reporter,
            &runtime,
            &["web".to_string()],
            false,
            true,
        )
        .await
        .unwrap();

        assert_eq!(runtimes.len(), 1);
        assert!(runtimes[0].watch_children);
        assert!(runtimes[0].all_processes);
        assert_eq!(runtimes[0].current_pid, Some(50));
    }

    #[tokio::test]
    async fn initialize_container_runtimes_skips_seed_when_runtime_has_no_pid() {
        let mut process_seed = MockProcessSeedPort::new();
        let cgroup_port: SharedCgroupPort = Arc::new(MockCgroupPort::new());
        let runtime: SharedContainerRuntimePort =
            Arc::new(QueuedContainerRuntimePort::new(vec![Ok(None)]));
        let mut reporter = MockStatusReporter::new();

        let runtimes = initialize_container_runtimes(
            &mut process_seed,
            &cgroup_port,
            &mut reporter,
            &runtime,
            &["web".to_string()],
            true,
            false,
        )
        .await
        .unwrap();

        assert_eq!(runtimes[0].current_pid, None);
    }

    #[tokio::test]
    async fn initialize_systemd_runtimes_keeps_inactive_unit_without_waiting() {
        let mut process_seed = MockProcessSeedPort::new();
        let runtime: SharedSystemdRuntimePort = Arc::new(QueuedSystemdRuntimePort::with_statuses(
            vec![Ok(SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("inactive".to_string()),
                sub_state: Some("dead".to_string()),
                main_pid: None,
            })],
        ));
        let mut reporter = MockStatusReporter::new();
        let mut wait_port = MockWaitPort::new();

        let runtimes = initialize_systemd_runtimes(
            &mut process_seed,
            &mut reporter,
            &mut wait_port,
            &runtime,
            &["sshd.service".to_string()],
            false,
            false,
        )
        .await
        .unwrap();

        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].current_pid, None);
        assert!(!runtimes[0].current_running);
    }

    #[tokio::test]
    async fn initialize_systemd_runtimes_seeds_main_pid_even_before_running() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [80] && *flags == PROC_FLAG_WATCH_SELF)
            .returning(|_, _| Ok(()));
        let runtime: SharedSystemdRuntimePort = Arc::new(QueuedSystemdRuntimePort::with_statuses(
            vec![Ok(SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("activating".to_string()),
                sub_state: Some("start".to_string()),
                main_pid: Some(80),
            })],
        ));
        let mut reporter = MockStatusReporter::new();
        let mut wait_port = MockWaitPort::new();

        let runtimes = initialize_systemd_runtimes(
            &mut process_seed,
            &mut reporter,
            &mut wait_port,
            &runtime,
            &["sshd.service".to_string()],
            false,
            false,
        )
        .await
        .unwrap();

        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].current_pid, Some(80));
        assert!(!runtimes[0].current_running);
        assert_eq!(runtimes[0].seeded_pids, vec![80]);
    }

    #[tokio::test]
    async fn initialize_systemd_runtimes_keeps_missing_unit_stopped_without_seeding() {
        let mut process_seed = MockProcessSeedPort::new();
        let runtime: SharedSystemdRuntimePort = Arc::new(QueuedSystemdRuntimePort::with_statuses(
            vec![Ok(SystemdUnitRuntimeStatus::missing())],
        ));
        let mut reporter = MockStatusReporter::new();
        let mut wait_port = MockWaitPort::new();

        let runtimes = initialize_systemd_runtimes(
            &mut process_seed,
            &mut reporter,
            &mut wait_port,
            &runtime,
            &["missing.service".to_string()],
            true,
            false,
        )
        .await
        .unwrap();

        assert_eq!(runtimes.len(), 1);
        assert!(!runtimes[0].current_running);
        assert_eq!(runtimes[0].current_pid, None);
    }
}
