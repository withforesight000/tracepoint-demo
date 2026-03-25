use std::collections::HashSet;

use std::time::Duration;
use tokio::sync::mpsc;

use crate::usecase::port::{
    ProcessSeedPort, RuntimeUpdate, SharedSystemdRuntimePort, StatusReporter, SystemdRuntimePort,
    SystemdUnitRuntimeStatus, WaitPort,
};

pub struct SystemdRuntime {
    pub runtime: SharedSystemdRuntimePort,
    pub unit_name: String,
    pub watch_children: bool,
    pub all_processes: bool,
    pub flags: u32,
    pub current_pid: Option<u32>,
    pub current_running: bool,
}

pub(crate) struct SystemdSeedSpec<'a> {
    pub unit_name: &'a str,
    pub main_pid: Option<u32>,
    pub flags: u32,
    pub watch_children: bool,
    pub all_processes: bool,
}

pub async fn wait_systemd_unit_running<
    TReporter: StatusReporter + ?Sized,
    TWait: WaitPort + ?Sized,
>(
    runtime: &dyn SystemdRuntimePort,
    reporter: &mut TReporter,
    wait_port: &mut TWait,
    unit_name: &str,
) -> anyhow::Result<SystemdUnitRuntimeStatus> {
    let mut last_notice = String::new();

    loop {
        let status = runtime.current_status(unit_name).await?;
        if status.is_running() {
            return Ok(status);
        }

        let notice = if !status.exists {
            format!("Waiting for systemd unit {unit_name} to exist...")
        } else {
            format!(
                "Waiting for systemd unit {unit_name} to start (state={} substate={})...",
                status.active_state.as_deref().unwrap_or("unknown"),
                status.sub_state.as_deref().unwrap_or("unknown"),
            )
        };

        if notice != last_notice {
            reporter.info(notice.clone());
            last_notice = notice;
        }

        wait_port
            .wait(
                Duration::from_secs(1),
                format!("Interrupted while waiting for systemd unit {unit_name} state to change."),
            )
            .await?;
    }
}

pub(crate) async fn seed_systemd_unit_processes<TReporter: StatusReporter + ?Sized>(
    process_seed: &mut dyn ProcessSeedPort,
    reporter: &mut TReporter,
    runtime: &dyn SystemdRuntimePort,
    spec: SystemdSeedSpec<'_>,
) -> anyhow::Result<()> {
    if spec.all_processes {
        match runtime.unit_pids(spec.unit_name).await {
            Ok(pids) => process_seed.seed_direct(&pids, spec.flags)?,
            Err(err) => {
                let main_pid = spec.main_pid.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Failed to get all processes for systemd unit {}: {}. No MainPID is available for fallback.",
                        spec.unit_name, err
                    )
                })?;
                reporter.warn(format!(
                    "Failed to get all processes for systemd unit {}: {}. Falling back to task iterator seed.",
                    spec.unit_name, err
                ));
                let empty_tty_filters = HashSet::new();
                let _ = process_seed.seed_from_task_iter(
                    &[main_pid],
                    &empty_tty_filters,
                    spec.flags,
                )?;
            }
        }
        return Ok(());
    }

    let main_pid = spec.main_pid.ok_or_else(|| {
        anyhow::anyhow!(
            "systemd unit {} has no MainPID while active. Use --all-systemd-processes for units without MainPID.",
            spec.unit_name
        )
    })?;

    if spec.watch_children {
        let empty_tty_filters = HashSet::new();
        let _ = process_seed.seed_from_task_iter(&[main_pid], &empty_tty_filters, spec.flags)?;
    } else {
        process_seed.seed_direct(&[main_pid], spec.flags)?;
    }

    Ok(())
}

pub async fn apply_systemd_runtime_update<TReporter: StatusReporter + ?Sized>(
    process_seed: &mut dyn ProcessSeedPort,
    reporter: &mut TReporter,
    runtime: &mut SystemdRuntime,
    next_pid: Option<u32>,
    running: bool,
) -> anyhow::Result<()> {
    if runtime.current_pid == next_pid && runtime.current_running == running {
        return Ok(());
    }

    if running && (runtime.all_processes || next_pid.is_some()) {
        seed_systemd_unit_processes(
            process_seed,
            reporter,
            runtime.runtime.as_ref(),
            SystemdSeedSpec {
                unit_name: &runtime.unit_name,
                main_pid: next_pid,
                flags: runtime.flags,
                watch_children: runtime.watch_children,
                all_processes: runtime.all_processes,
            },
        )
        .await?;
    }

    runtime.current_pid = next_pid;
    runtime.current_running = running;
    Ok(())
}

pub fn spawn_monitors(
    systemd_runtimes: &[SystemdRuntime],
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    systemd_runtimes
        .iter()
        .enumerate()
        .map(|(index, runtime)| {
            runtime
                .runtime
                .spawn_monitor(runtime.unit_name.clone(), update_tx.clone(), index)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashSet, VecDeque},
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::usecase::port::BoxFuture;

    struct FakeProcessSeedPort {
        direct_calls: Mutex<Vec<(Vec<u32>, u32)>>,
        task_iter_calls: Mutex<Vec<(Vec<u32>, HashSet<String>, u32)>>,
        task_iter_result: Mutex<anyhow::Result<Vec<u32>>>,
        direct_result: Mutex<anyhow::Result<()>>,
    }

    impl FakeProcessSeedPort {
        fn with_results(
            task_iter_result: anyhow::Result<Vec<u32>>,
            direct_result: anyhow::Result<()>,
        ) -> Self {
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
            self.direct_calls
                .lock()
                .unwrap()
                .push((pids.to_vec(), flags));
            match &*self.direct_result.lock().unwrap() {
                Ok(()) => Ok(()),
                Err(err) => Err(anyhow::anyhow!(err.to_string())),
            }
        }
    }

    #[derive(Clone, Default)]
    struct FakeSystemdRuntimePort {
        statuses: Arc<Mutex<VecDeque<SystemdUnitRuntimeStatus>>>,
    }

    impl FakeSystemdRuntimePort {
        fn new(statuses: Vec<SystemdUnitRuntimeStatus>) -> Self {
            Self {
                statuses: Arc::new(Mutex::new(statuses.into_iter().collect())),
            }
        }
    }

    impl SystemdRuntimePort for FakeSystemdRuntimePort {
        fn current_status<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
            Box::pin(async move {
                let mut statuses = self.statuses.lock().expect("status queue should be usable");
                if let Some(status) = statuses.pop_front() {
                    Ok(status)
                } else if let Some(status) = statuses.back() {
                    Ok(status.clone())
                } else {
                    Err(anyhow::anyhow!("status queue is empty"))
                }
            })
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

    #[derive(Default)]
    struct FakeReporter {
        info_messages: Vec<String>,
        warn_messages: Vec<String>,
    }

    impl StatusReporter for FakeReporter {
        fn info(&mut self, message: String) {
            self.info_messages.push(message);
        }

        fn warn(&mut self, message: String) {
            self.warn_messages.push(message);
        }
    }

    #[derive(Default)]
    struct FakeWaitPort {
        calls: Vec<(Duration, String)>,
        fail_on_call: Option<usize>,
    }

    impl WaitPort for FakeWaitPort {
        fn wait<'a>(
            &'a mut self,
            duration: Duration,
            interrupted_message: String,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                self.calls.push((duration, interrupted_message));
                if self
                    .fail_on_call
                    .map(|fail_on_call| self.calls.len() >= fail_on_call)
                    .unwrap_or(false)
                {
                    return Err(anyhow::anyhow!("wait interrupted"));
                }

                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn spawn_monitors_empty_returns_empty() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let handles = spawn_monitors(&[], &tx);
        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn wait_systemd_unit_running_returns_immediately_when_running() {
        let runtime = FakeSystemdRuntimePort::new(vec![SystemdUnitRuntimeStatus {
            exists: true,
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            main_pid: Some(123),
        }]);
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

        let status =
            wait_systemd_unit_running(&runtime, &mut reporter, &mut wait_port, "demo.service")
                .await
                .unwrap();

        assert_eq!(status.main_pid, Some(123));
        assert!(reporter.info_messages.is_empty());
        assert!(wait_port.calls.is_empty());
    }

    #[tokio::test]
    async fn wait_systemd_unit_running_announces_once_until_running() {
        let runtime = FakeSystemdRuntimePort::new(vec![
            SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("inactive".to_string()),
                sub_state: Some("dead".to_string()),
                main_pid: None,
            },
            SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("inactive".to_string()),
                sub_state: Some("dead".to_string()),
                main_pid: None,
            },
            SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("reloading".to_string()),
                sub_state: Some("running".to_string()),
                main_pid: Some(456),
            },
        ]);
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

        let status =
            wait_systemd_unit_running(&runtime, &mut reporter, &mut wait_port, "demo.service")
                .await
                .unwrap();

        assert_eq!(status.main_pid, Some(456));
        assert_eq!(reporter.info_messages.len(), 1);
        assert!(
            reporter.info_messages[0].contains("Waiting for systemd unit demo.service to start")
        );
        assert_eq!(wait_port.calls.len(), 2);
    }

    #[tokio::test]
    async fn wait_systemd_unit_running_reports_missing_unit_and_propagates_wait_error() {
        let runtime = FakeSystemdRuntimePort::new(vec![SystemdUnitRuntimeStatus::missing()]);
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort {
            calls: Vec::new(),
            fail_on_call: Some(1),
        };

        let err =
            wait_systemd_unit_running(&runtime, &mut reporter, &mut wait_port, "demo.service")
                .await
                .unwrap_err();

        assert_eq!(err.to_string(), "wait interrupted");
        assert_eq!(
            reporter.info_messages,
            vec!["Waiting for systemd unit demo.service to exist...".to_string()]
        );
        assert_eq!(wait_port.calls.len(), 1);
    }

    #[tokio::test]
    async fn seed_systemd_unit_processes_seeds_directly_for_all_processes() {
        let mut process_seed = FakeProcessSeedPort::with_results(Ok(Vec::new()), Ok(()));
        let runtime = FixedUnitPidsRuntimePort { pids: vec![11, 22] };
        let mut reporter = FakeReporter::default();

        seed_systemd_unit_processes(
            &mut process_seed,
            &mut reporter,
            &runtime,
            SystemdSeedSpec {
                unit_name: "demo.service",
                main_pid: Some(55),
                flags: 0x4,
                watch_children: true,
                all_processes: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            process_seed.direct_calls.lock().unwrap().clone(),
            vec![(vec![11, 22], 0x4)]
        );
        assert!(process_seed.task_iter_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn seed_systemd_unit_processes_falls_back_to_task_iter_when_unit_pids_fail() {
        let mut process_seed = FakeProcessSeedPort::with_results(Ok(vec![77]), Ok(()));
        let runtime = FailingUnitPidsRuntimePort;
        let mut reporter = FakeReporter::default();

        seed_systemd_unit_processes(
            &mut process_seed,
            &mut reporter,
            &runtime,
            SystemdSeedSpec {
                unit_name: "demo.service",
                main_pid: Some(77),
                flags: 0x8,
                watch_children: true,
                all_processes: true,
            },
        )
        .await
        .unwrap();

        assert!(process_seed.direct_calls.lock().unwrap().is_empty());
        assert_eq!(process_seed.task_iter_calls.lock().unwrap().len(), 1);
        assert_eq!(reporter.warn_messages.len(), 1);
    }

    #[tokio::test]
    async fn apply_systemd_runtime_update_short_circuits_when_state_is_unchanged() {
        let mut process_seed = FakeProcessSeedPort::default();
        let mut runtime = SystemdRuntime {
            runtime: Arc::new(FakeSystemdRuntimePort::default()),
            unit_name: "demo.service".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x2,
            current_pid: Some(12),
            current_running: true,
        };
        let mut reporter = FakeReporter::default();

        apply_systemd_runtime_update(
            &mut process_seed,
            &mut reporter,
            &mut runtime,
            Some(12),
            true,
        )
        .await
        .unwrap();

        assert!(process_seed.direct_calls.lock().unwrap().is_empty());
        assert!(process_seed.task_iter_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn seed_systemd_unit_processes_errors_when_active_unit_has_no_main_pid() {
        let mut process_seed = FakeProcessSeedPort::default();
        let runtime = FixedUnitPidsRuntimePort { pids: vec![1, 2] };
        let mut reporter = FakeReporter::default();

        let err = seed_systemd_unit_processes(
            &mut process_seed,
            &mut reporter,
            &runtime,
            SystemdSeedSpec {
                unit_name: "demo.service",
                main_pid: None,
                flags: 0x4,
                watch_children: false,
                all_processes: false,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("has no MainPID while active"));
    }

    #[tokio::test]
    async fn apply_systemd_runtime_update_seeds_and_updates_state_when_running_changes() {
        let mut process_seed = FakeProcessSeedPort::with_results(Ok(Vec::new()), Ok(()));
        let mut runtime = SystemdRuntime {
            runtime: Arc::new(FixedStatusRuntimePort {
                status: SystemdUnitRuntimeStatus {
                    exists: true,
                    active_state: Some("active".to_string()),
                    sub_state: Some("running".to_string()),
                    main_pid: Some(88),
                },
            }),
            unit_name: "demo.service".to_string(),
            watch_children: false,
            all_processes: false,
            flags: 0x2,
            current_pid: None,
            current_running: false,
        };
        let mut reporter = FakeReporter::default();

        apply_systemd_runtime_update(
            &mut process_seed,
            &mut reporter,
            &mut runtime,
            Some(88),
            true,
        )
        .await
        .unwrap();

        assert_eq!(runtime.current_pid, Some(88));
        assert!(runtime.current_running);
        assert_eq!(
            process_seed.direct_calls.lock().unwrap().clone(),
            vec![(vec![88], 0x2)]
        );
    }

    struct FixedUnitPidsRuntimePort {
        pids: Vec<u32>,
    }

    impl SystemdRuntimePort for FixedUnitPidsRuntimePort {
        fn current_status<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
            Box::pin(async { Ok(SystemdUnitRuntimeStatus::missing()) })
        }

        fn unit_pids<'a>(&'a self, _unit_name: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<u32>>> {
            let pids = self.pids.clone();
            Box::pin(async move { Ok(pids) })
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

    struct FailingUnitPidsRuntimePort;

    impl SystemdRuntimePort for FailingUnitPidsRuntimePort {
        fn current_status<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
            Box::pin(async { Ok(SystemdUnitRuntimeStatus::missing()) })
        }

        fn unit_pids<'a>(&'a self, _unit_name: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<u32>>> {
            Box::pin(async { Err(anyhow::anyhow!("unit pids unavailable")) })
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

    struct FixedStatusRuntimePort {
        status: SystemdUnitRuntimeStatus,
    }

    impl SystemdRuntimePort for FixedStatusRuntimePort {
        fn current_status<'a>(
            &'a self,
            _unit_name: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
            let status = self.status.clone();
            Box::pin(async move { Ok(status) })
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
}
