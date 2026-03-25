use std::collections::{HashMap as StdHashMap, HashSet};

use tracepoint_demo_common::{PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

use crate::usecase::{
    orchestration::watch_roots::add_watch_root,
    policy::{
        watch_container::{ContainerRuntime, seed_container_processes},
        watch_pid_or_tty::wait_pid_or_tty_targets,
        watch_systemd_unit::{
            SystemdRuntime, SystemdSeedSpec, seed_systemd_unit_processes,
            wait_systemd_unit_running,
        },
    },
    port::{
        ProcessSeedPort, SharedCgroupPort, SharedContainerRuntimePort, SharedSystemdRuntimePort,
        StatusReporter, WaitPort,
    },
};

pub(crate) async fn collect_static_watch_roots<
    TReporter: StatusReporter + ?Sized,
    TWait: WaitPort + ?Sized,
>(
    process_seed: &mut dyn ProcessSeedPort,
    pids: &[u32],
    tty_filters: &HashSet<String>,
    tty_inputs: &[String],
    watch_flags: u32,
    has_runtime_targets: bool,
    reporter: &mut TReporter,
    wait_port: &mut TWait,
) -> anyhow::Result<StdHashMap<u32, u32>> {
    let mut static_watch_roots = StdHashMap::new();

    if pids.is_empty() && tty_filters.is_empty() {
        return Ok(static_watch_roots);
    }

    let roots = process_seed.seed_from_task_iter(pids, tty_filters, watch_flags)?;
    for pid in roots {
        add_watch_root(&mut static_watch_roots, pid, watch_flags);
    }

    if static_watch_roots.is_empty() && !has_runtime_targets {
        let roots = wait_pid_or_tty_targets(
            process_seed,
            pids,
            tty_filters,
            tty_inputs,
            watch_flags,
            reporter,
            wait_port,
        )
        .await?;
        for pid in roots {
            add_watch_root(&mut static_watch_roots, pid, watch_flags);
        }
    }

    Ok(static_watch_roots)
}

pub(crate) async fn initialize_container_runtimes<TReporter: StatusReporter + ?Sized>(
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
        if let Some(main_pid) = current_pid {
            seed_container_processes(
                process_seed,
                cgroup_port.as_ref(),
                reporter,
                container_name,
                main_pid,
                container_flags,
                container_watch_children,
                all_container_processes,
            )
            .await?;
        }

        container_runtimes.push(ContainerRuntime {
            cgroup_port: cgroup_port.clone(),
            runtime: runtime.clone(),
            name_or_id: container_name.clone(),
            watch_children: container_watch_children,
            all_processes: all_container_processes,
            flags: container_flags,
            current_pid,
        });
    }

    Ok(container_runtimes)
}

pub(crate) async fn initialize_systemd_runtimes<
    TReporter: StatusReporter + ?Sized,
    TWait: WaitPort + ?Sized,
>(
    process_seed: &mut dyn ProcessSeedPort,
    reporter: &mut TReporter,
    wait_port: &mut TWait,
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
        let status = if status.exists && !status.is_running() {
            wait_systemd_unit_running(runtime.as_ref(), reporter, wait_port, unit_name).await?
        } else {
            status
        };

        let current_running = status.is_running();
        if current_running {
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
            .await?;
        }

        systemd_runtimes.push(SystemdRuntime {
            runtime: runtime.clone(),
            unit_name: unit_name.clone(),
            watch_children: unit_watch_children,
            all_processes: all_systemd_processes,
            flags: unit_flags,
            current_pid: status.main_pid,
            current_running,
        });
    }

    Ok(systemd_runtimes)
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::{Arc, Mutex}};

    use super::*;
    use crate::usecase::port::{
        BoxFuture, ContainerRuntimePort, RuntimeUpdate, SystemdRuntimePort,
        SystemdUnitRuntimeStatus,
    };

    struct FakeProcessSeedPort {
        results: VecDeque<anyhow::Result<Vec<u32>>>,
        direct_calls: Vec<(Vec<u32>, u32)>,
        task_iter_calls: Vec<(Vec<u32>, HashSet<String>, u32)>,
    }

    impl FakeProcessSeedPort {
        fn with_results(results: Vec<anyhow::Result<Vec<u32>>>) -> Self {
            Self {
                results: results.into(),
                direct_calls: Vec::new(),
                task_iter_calls: Vec::new(),
            }
        }
    }

    impl Default for FakeProcessSeedPort {
        fn default() -> Self {
            Self::with_results(vec![Ok(Vec::new())])
        }
    }

    impl ProcessSeedPort for FakeProcessSeedPort {
        fn seed_from_task_iter(
            &mut self,
            pid_roots: &[u32],
            tty_filters: &HashSet<String>,
            watch_flags: u32,
        ) -> anyhow::Result<Vec<u32>> {
            self.task_iter_calls
                .push((pid_roots.to_vec(), tty_filters.clone(), watch_flags));
            self.results
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()))
        }

        fn seed_direct(&mut self, pids: &[u32], flags: u32) -> anyhow::Result<()> {
            self.direct_calls.push((pids.to_vec(), flags));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeReporter {
        warnings: Vec<String>,
        infos: Vec<String>,
    }

    impl StatusReporter for FakeReporter {
        fn info(&mut self, message: String) {
            self.infos.push(message);
        }

        fn warn(&mut self, message: String) {
            self.warnings.push(message);
        }
    }

    #[derive(Default)]
    struct FakeWaitPort {
        calls: Vec<String>,
    }

    impl WaitPort for FakeWaitPort {
        fn wait<'a>(
            &'a mut self,
            _duration: std::time::Duration,
            interrupted_message: String,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                self.calls.push(interrupted_message);
                Ok(())
            })
        }
    }

    struct FakeCgroupPort {
        procs: Vec<u32>,
    }

    impl crate::usecase::port::CgroupPort for FakeCgroupPort {
        fn read_cgroup_v2_path(&self, _pid: u32) -> anyhow::Result<String> {
            Ok("/demo".to_string())
        }

        fn read_cgroup_procs(&self, _path: &str) -> anyhow::Result<Vec<u32>> {
            Ok(self.procs.clone())
        }
    }

    struct FakeContainerRuntimePort {
        pids: Mutex<VecDeque<anyhow::Result<Option<u32>>>>,
    }

    impl FakeContainerRuntimePort {
        fn new(pids: Vec<anyhow::Result<Option<u32>>>) -> Self {
            Self {
                pids: Mutex::new(pids.into()),
            }
        }
    }

    impl ContainerRuntimePort for FakeContainerRuntimePort {
        fn query_main_pid<'a>(
            &'a self,
            _name_or_id: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<Option<u32>>> {
            Box::pin(async move {
                self.pids
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Ok(None))
            })
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

    #[derive(Clone)]
    struct FakeSystemdRuntimePort {
        statuses: Arc<Mutex<VecDeque<anyhow::Result<SystemdUnitRuntimeStatus>>>>,
    }

    impl FakeSystemdRuntimePort {
        fn new(statuses: Vec<anyhow::Result<SystemdUnitRuntimeStatus>>) -> Self {
            Self {
                statuses: Arc::new(Mutex::new(statuses.into())),
            }
        }
    }

    impl SystemdRuntimePort for FakeSystemdRuntimePort {
        fn current_status<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
            Box::pin(async move {
                self.statuses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Ok(SystemdUnitRuntimeStatus::missing()))
            })
        }

        fn unit_pids<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<Vec<u32>>> {
            Box::pin(async { Ok(vec![11, 22]) })
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

    #[tokio::test]
    async fn collect_static_watch_roots_returns_empty_without_inputs() {
        let mut process_seed = FakeProcessSeedPort::default();
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

        let roots = collect_static_watch_roots(
            &mut process_seed,
            &[],
            &HashSet::new(),
            &[],
            0x1,
            false,
            &mut reporter,
            &mut wait_port,
        )
        .await
        .unwrap();

        assert!(roots.is_empty());
        assert!(process_seed.task_iter_calls.is_empty());
    }

    #[tokio::test]
    async fn collect_static_watch_roots_waits_when_no_runtime_targets_and_first_seed_is_empty() {
        let mut process_seed =
            FakeProcessSeedPort::with_results(vec![Ok(Vec::new()), Ok(Vec::new()), Ok(vec![41])]);
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

        let roots = collect_static_watch_roots(
            &mut process_seed,
            &[41],
            &HashSet::new(),
            &["pts/1".to_string()],
            0x2,
            false,
            &mut reporter,
            &mut wait_port,
        )
        .await
        .unwrap();

        assert_eq!(roots, StdHashMap::from([(41, 0x2)]));
        assert_eq!(wait_port.calls.len(), 1);
        assert_eq!(reporter.warnings.len(), 1);
    }

    #[tokio::test]
    async fn initialize_container_runtimes_forces_watch_children_for_all_processes() {
        let mut process_seed = FakeProcessSeedPort::default();
        let cgroup_port: SharedCgroupPort = Arc::new(FakeCgroupPort { procs: vec![50, 51] });
        let runtime: SharedContainerRuntimePort = Arc::new(FakeContainerRuntimePort::new(vec![Ok(Some(50))]));
        let mut reporter = FakeReporter::default();

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
        assert_eq!(
            process_seed.direct_calls,
            vec![(vec![50, 51], PROC_FLAG_WATCH_SELF | PROC_FLAG_WATCH_CHILDREN)]
        );
    }

    #[tokio::test]
    async fn initialize_container_runtimes_skips_seed_when_runtime_has_no_pid() {
        let mut process_seed = FakeProcessSeedPort::default();
        let cgroup_port: SharedCgroupPort = Arc::new(FakeCgroupPort { procs: vec![99] });
        let runtime: SharedContainerRuntimePort = Arc::new(FakeContainerRuntimePort::new(vec![Ok(None)]));
        let mut reporter = FakeReporter::default();

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
        assert!(process_seed.direct_calls.is_empty());
        assert!(process_seed.task_iter_calls.is_empty());
    }

    #[tokio::test]
    async fn initialize_systemd_runtimes_waits_for_running_unit_and_seeds_main_pid() {
        let mut process_seed = FakeProcessSeedPort::default();
        let runtime: SharedSystemdRuntimePort = Arc::new(FakeSystemdRuntimePort::new(vec![
            Ok(SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("inactive".to_string()),
                sub_state: Some("dead".to_string()),
                main_pid: None,
            }),
            Ok(SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("inactive".to_string()),
                sub_state: Some("dead".to_string()),
                main_pid: None,
            }),
            Ok(SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("active".to_string()),
                sub_state: Some("running".to_string()),
                main_pid: Some(80),
            }),
        ]));
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

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
        assert!(runtimes[0].current_running);
        assert_eq!(process_seed.direct_calls, vec![(vec![80], PROC_FLAG_WATCH_SELF)]);
        assert_eq!(wait_port.calls.len(), 1);
    }

    #[tokio::test]
    async fn initialize_systemd_runtimes_keeps_missing_unit_stopped_without_seeding() {
        let mut process_seed = FakeProcessSeedPort::default();
        let runtime: SharedSystemdRuntimePort = Arc::new(FakeSystemdRuntimePort::new(vec![Ok(
            SystemdUnitRuntimeStatus::missing(),
        )]));
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

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
        assert!(process_seed.direct_calls.is_empty());
        assert!(process_seed.task_iter_calls.is_empty());
    }
}
