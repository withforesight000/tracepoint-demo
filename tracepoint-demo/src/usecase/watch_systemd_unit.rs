use std::collections::HashSet;

use aya::Ebpf;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::{
    gateway::ebpf::{seed_proc_state_direct, seed_proc_state_from_task_iter},
    usecase::{
        ports::{
            SharedSystemdRuntimePort, StatusReporter, SystemdRuntimePort, SystemdUnitRuntimeStatus,
            WaitPort,
        },
        support::runtime_update::RuntimeUpdate,
    },
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
    ebpf: &mut Ebpf,
    reporter: &mut TReporter,
    runtime: &dyn SystemdRuntimePort,
    spec: SystemdSeedSpec<'_>,
) -> anyhow::Result<()> {
    if spec.all_processes {
        match runtime.unit_pids(spec.unit_name).await {
            Ok(pids) => seed_proc_state_direct(ebpf, &pids, spec.flags)?,
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
                let _ = seed_proc_state_from_task_iter(
                    ebpf,
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
        let _ = seed_proc_state_from_task_iter(ebpf, &[main_pid], &empty_tty_filters, spec.flags)?;
    } else {
        seed_proc_state_direct(ebpf, &[main_pid], spec.flags)?;
    }

    Ok(())
}

pub async fn apply_systemd_runtime_update<TReporter: StatusReporter + ?Sized>(
    ebpf: &mut Ebpf,
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
            ebpf,
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
    use super::*;

    #[tokio::test]
    async fn spawn_monitors_empty_returns_empty() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let handles = spawn_monitors(&[], &tx);
        assert!(handles.is_empty());
    }
}
