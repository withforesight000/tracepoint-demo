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
    pub seeded_pids: Vec<u32>,
    pub flags: u32,
    pub current_pid: Option<u32>,
    pub current_running: bool,
}

pub struct SystemdSeedSpec<'a> {
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
) -> anyhow::Result<Vec<u32>> {
    if spec.all_processes {
        match runtime.unit_pids(spec.unit_name).await {
            Ok(pids) => {
                process_seed.seed_direct(&pids, spec.flags)?;
                return Ok(pids);
            }
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
                let seeded_roots = process_seed.seed_from_task_iter(
                    &[main_pid],
                    &empty_tty_filters,
                    spec.flags,
                )?;
                return Ok(seeded_roots);
            }
        }
    }

    let main_pid = spec.main_pid.ok_or_else(|| {
        anyhow::anyhow!(
            "systemd unit {} has no MainPID while active. Use --all-systemd-processes for units without MainPID.",
            spec.unit_name
        )
    })?;

    if spec.watch_children {
        let empty_tty_filters = HashSet::new();
        let seeded_roots =
            process_seed.seed_from_task_iter(&[main_pid], &empty_tty_filters, spec.flags)?;
        return Ok(seeded_roots);
    } else {
        process_seed.seed_direct(&[main_pid], spec.flags)?;
    }

    Ok(vec![main_pid])
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
        runtime.seeded_pids = seed_systemd_unit_processes(
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
    } else if !running {
        runtime.seeded_pids.clear();
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
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{
        MockProcessSeedPort, MockStatusReporter, MockWaitPort, NoopSystemdRuntimePort,
        QueuedSystemdRuntimePort, boxed_future,
    };

    #[tokio::test]
    async fn spawn_monitors_empty_returns_empty() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let handles = spawn_monitors(&[], &tx);
        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn wait_systemd_unit_running_returns_immediately_when_running() {
        let runtime = QueuedSystemdRuntimePort::with_statuses(vec![Ok(SystemdUnitRuntimeStatus {
            exists: true,
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            main_pid: Some(123),
        })]);
        let mut reporter = MockStatusReporter::new();
        let mut wait_port = MockWaitPort::new();

        let status =
            wait_systemd_unit_running(&runtime, &mut reporter, &mut wait_port, "demo.service")
                .await
                .unwrap();

        assert_eq!(status.main_pid, Some(123));
    }

    #[tokio::test]
    async fn wait_systemd_unit_running_announces_once_until_running() {
        let runtime = QueuedSystemdRuntimePort::with_statuses(
            vec![
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
            ]
            .into_iter()
            .map(Ok)
            .collect(),
        );
        let mut reporter = MockStatusReporter::new();
        reporter
            .expect_info()
            .times(1)
            .withf(|message| message.contains("Waiting for systemd unit demo.service to start"))
            .return_const(());
        let mut wait_port = MockWaitPort::new();
        wait_port
            .expect_wait()
            .times(2)
            .withf(|duration, interrupted_message| {
                *duration == Duration::from_secs(1)
                    && interrupted_message
                        == "Interrupted while waiting for systemd unit demo.service state to change."
            })
            .returning(|_, _| boxed_future(Ok(())));

        let status =
            wait_systemd_unit_running(&runtime, &mut reporter, &mut wait_port, "demo.service")
                .await
                .unwrap();

        assert_eq!(status.main_pid, Some(456));
    }

    #[tokio::test]
    async fn wait_systemd_unit_running_reports_missing_unit_and_propagates_wait_error() {
        let runtime =
            QueuedSystemdRuntimePort::with_statuses(vec![Ok(SystemdUnitRuntimeStatus::missing())]);
        let mut reporter = MockStatusReporter::new();
        reporter
            .expect_info()
            .times(1)
            .withf(|message| message == "Waiting for systemd unit demo.service to exist...")
            .return_const(());
        let mut wait_port = MockWaitPort::new();
        wait_port
            .expect_wait()
            .times(1)
            .withf(|duration, interrupted_message| {
                *duration == Duration::from_secs(1)
                    && interrupted_message
                        == "Interrupted while waiting for systemd unit demo.service state to change."
            })
            .returning(|_, _| boxed_future(Err(anyhow::anyhow!("wait interrupted"))));

        let err =
            wait_systemd_unit_running(&runtime, &mut reporter, &mut wait_port, "demo.service")
                .await
                .unwrap_err();

        assert_eq!(err.to_string(), "wait interrupted");
    }

    #[tokio::test]
    async fn seed_systemd_unit_processes_seeds_directly_for_all_processes() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [11, 22] && *flags == 0x4)
            .returning(|_, _| Ok(()));
        let runtime = QueuedSystemdRuntimePort::with_unit_pids_result(Ok(vec![11, 22]));
        let mut reporter = MockStatusReporter::new();

        let seeded_pids = seed_systemd_unit_processes(
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

        assert_eq!(seeded_pids, vec![11, 22]);
    }

    #[tokio::test]
    async fn seed_systemd_unit_processes_falls_back_to_task_iter_when_unit_pids_fail() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_from_task_iter()
            .times(1)
            .withf(|pid_roots, tty_filters, watch_flags| {
                pid_roots == [77] && tty_filters.is_empty() && *watch_flags == 0x8
            })
            .returning(|_, _, _| Ok(vec![77]));
        let runtime = QueuedSystemdRuntimePort::with_unit_pids_result(Err(anyhow::anyhow!(
            "unit pids unavailable"
        )));
        let mut reporter = MockStatusReporter::new();
        reporter.expect_warn().times(1).return_const(());

        let seeded_pids = seed_systemd_unit_processes(
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

        assert_eq!(seeded_pids, vec![77]);
    }

    #[tokio::test]
    async fn apply_systemd_runtime_update_short_circuits_when_state_is_unchanged() {
        let mut process_seed = MockProcessSeedPort::new();
        let mut runtime = SystemdRuntime {
            runtime: Arc::new(NoopSystemdRuntimePort),
            unit_name: "demo.service".to_string(),
            watch_children: false,
            all_processes: false,
            seeded_pids: Vec::new(),
            flags: 0x2,
            current_pid: Some(12),
            current_running: true,
        };
        let mut reporter = MockStatusReporter::new();

        apply_systemd_runtime_update(
            &mut process_seed,
            &mut reporter,
            &mut runtime,
            Some(12),
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn seed_systemd_unit_processes_errors_when_active_unit_has_no_main_pid() {
        let mut process_seed = MockProcessSeedPort::new();
        let runtime = NoopSystemdRuntimePort;
        let mut reporter = MockStatusReporter::new();

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
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_direct()
            .times(1)
            .withf(|pids, flags| pids == [88] && *flags == 0x2)
            .returning(|_, _| Ok(()));
        let mut runtime = SystemdRuntime {
            runtime: Arc::new(NoopSystemdRuntimePort),
            unit_name: "demo.service".to_string(),
            watch_children: false,
            all_processes: false,
            seeded_pids: Vec::new(),
            flags: 0x2,
            current_pid: None,
            current_running: false,
        };
        let mut reporter = MockStatusReporter::new();

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
    }
}
