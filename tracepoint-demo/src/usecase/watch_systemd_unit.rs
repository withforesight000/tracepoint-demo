use std::collections::HashSet;

use aya::Ebpf;
use futures_util::StreamExt;
use tokio::{
    select, signal,
    sync::mpsc,
    time::{Duration, sleep},
};
use zbus::fdo::PropertiesProxy;
use zbus_systemd::systemd1::ManagerProxy;

use crate::{
    gateway::{
        ebpf::{seed_proc_state_direct, seed_proc_state_from_task_iter},
        systemd::{
            ResolvedSystemdUnit, SystemdUnitLookupError, SystemdUnitStatus,
            query_systemd_unit_status, resolve_systemd_unit, systemd_unit_pids,
        },
    },
    usecase::runtime_update::RuntimeUpdate,
};

#[derive(Debug)]
pub struct SystemdRuntime {
    pub conn: zbus::Connection,
    pub unit_name: String,
    pub watch_children: bool,
    pub all_processes: bool,
    pub flags: u32,
    pub current_pid: Option<u32>,
    pub current_running: bool,
}

pub async fn wait_systemd_unit_running<'a>(
    conn: &'a zbus::Connection,
    unit_name: &str,
) -> anyhow::Result<(ResolvedSystemdUnit<'a>, SystemdUnitStatus)> {
    let mut last_notice = String::new();
    let manager = ManagerProxy::new(conn)
        .await
        .map_err(|err| anyhow::anyhow!("failed to create systemd manager proxy: {err}"))?;
    let mut resolved_unit: Option<ResolvedSystemdUnit<'_>> = None;

    loop {
        if resolved_unit.is_none() {
            match resolve_systemd_unit(conn, &manager, unit_name).await {
                Ok(unit) => {
                    resolved_unit = Some(unit);
                }
                Err(SystemdUnitLookupError::NotFound) => {
                    let notice = format!("Waiting for systemd unit {unit_name} to exist...");
                    if notice != last_notice {
                        println!("{notice}");
                        last_notice = notice;
                    }
                }
                Err(SystemdUnitLookupError::Other(err)) => return Err(err),
            }
        }

        if let Some(cached_unit) = resolved_unit.as_ref() {
            match query_systemd_unit_status(&cached_unit.unit_proxy, &cached_unit.service_proxy)
                .await
            {
                Ok(status) => {
                    if status.is_running() {
                        let resolved_unit = resolved_unit
                            .take()
                            .expect("resolved_unit should exist when status is running");
                        return Ok((resolved_unit, status));
                    }

                    let notice = format!(
                        "Waiting for systemd unit {unit_name} to start (state={} substate={})...",
                        status.active_state, status.sub_state
                    );
                    if notice != last_notice {
                        println!("{notice}");
                        last_notice = notice;
                    }
                }
                Err(SystemdUnitLookupError::NotFound) => {
                    resolved_unit = None;
                    let notice = format!("Waiting for systemd unit {unit_name} to exist...");
                    if notice != last_notice {
                        println!("{notice}");
                        last_notice = notice;
                    }
                }
                Err(SystemdUnitLookupError::Other(err)) => return Err(err),
            }
        }

        select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = signal::ctrl_c() => return Err(anyhow::anyhow!(
                "Interrupted while waiting for systemd unit {unit_name} state to change."
            )),
        }
    }
}

pub async fn seed_systemd_unit_processes(
    ebpf: &mut Ebpf,
    conn: &zbus::Connection,
    unit_name: &str,
    main_pid: Option<u32>,
    unit_flags: u32,
    unit_watch_children: bool,
    all_systemd_processes: bool,
) -> anyhow::Result<()> {
    if all_systemd_processes {
        match systemd_unit_pids(conn, unit_name).await {
            Ok(pids) => seed_proc_state_direct(ebpf, &pids, unit_flags)?,
            Err(err) => {
                let main_pid = main_pid.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Failed to get all processes for systemd unit {}: {}. No MainPID is available for fallback.",
                        unit_name, err
                    )
                })?;
                eprintln!(
                    "Failed to get all processes for systemd unit {}: {}. Falling back to task iterator seed.",
                    unit_name, err
                );
                let empty_tty_filters = HashSet::new();
                let _ = seed_proc_state_from_task_iter(
                    ebpf,
                    &[main_pid],
                    &empty_tty_filters,
                    unit_flags,
                )?;
            }
        }
        return Ok(());
    }

    let main_pid = main_pid.ok_or_else(|| {
        anyhow::anyhow!(
            "systemd unit {} has no MainPID while active. Use --all-systemd-processes for units without MainPID.",
            unit_name
        )
    })?;

    if unit_watch_children {
        let empty_tty_filters = HashSet::new();
        let _ = seed_proc_state_from_task_iter(ebpf, &[main_pid], &empty_tty_filters, unit_flags)?;
    } else {
        seed_proc_state_direct(ebpf, &[main_pid], unit_flags)?;
    }

    Ok(())
}

pub async fn apply_systemd_runtime_update(
    ebpf: &mut Ebpf,
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
            &runtime.conn,
            &runtime.unit_name,
            next_pid,
            runtime.flags,
            runtime.watch_children,
            runtime.all_processes,
        )
        .await?;
    }

    runtime.current_pid = next_pid;
    runtime.current_running = running;
    Ok(())
}

pub async fn monitor_systemd_runtime(
    conn: zbus::Connection,
    unit_name: String,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    loop {
        let (resolved_unit, status) = wait_systemd_unit_running(&conn, &unit_name).await?;
        let mut current_pid = status.main_pid;
        let mut current_running = status.is_running();
        let _ = tx.send(RuntimeUpdate::SystemdStatus {
            index,
            pid: current_pid,
            running: current_running,
        });

        let properties_proxy = PropertiesProxy::builder(&conn)
            .destination("org.freedesktop.systemd1")
            .map_err(|err| anyhow::anyhow!("failed to set systemd destination: {err}"))?
            .path(resolved_unit._unit_path.clone())
            .map_err(|err| anyhow::anyhow!("failed to set systemd unit path: {err}"))?
            .build()
            .await
            .map_err(|err| anyhow::anyhow!("failed to build systemd properties proxy: {err}"))?;
        let mut main_pid_changes = properties_proxy
            .receive_properties_changed()
            .await
            .map_err(|err| {
                anyhow::anyhow!("failed to subscribe to systemd property changes: {err}")
            })?;

        let _ = main_pid_changes.next().await;

        loop {
            let Some(changed) = main_pid_changes.next().await else {
                let _ = tx.send(RuntimeUpdate::SystemdStatus {
                    index,
                    pid: None,
                    running: false,
                });
                break;
            };

            let _ = changed.args().map_err(|err| {
                anyhow::anyhow!("failed to decode systemd properties change: {err}")
            })?;

            let status =
                query_systemd_unit_status(&resolved_unit.unit_proxy, &resolved_unit.service_proxy)
                    .await
                    .map_err(|err| match err {
                        SystemdUnitLookupError::NotFound => {
                            anyhow::anyhow!("systemd unit {unit_name} disappeared while monitoring")
                        }
                        SystemdUnitLookupError::Other(err) => err,
                    })?;
            let next_pid = status.main_pid;
            let next_running = status.is_running();

            if next_pid != current_pid || next_running != current_running {
                current_pid = next_pid;
                current_running = next_running;
                let _ = tx.send(RuntimeUpdate::SystemdStatus {
                    index,
                    pid: next_pid,
                    running: next_running,
                });
            }
        }
    }
}

pub fn spawn_monitors(
    systemd_runtimes: &[SystemdRuntime],
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut monitor_handles = Vec::new();
    for (index, runtime) in systemd_runtimes.iter().enumerate() {
        let tx = update_tx.clone();
        let conn = runtime.conn.clone();
        let unit_name = runtime.unit_name.clone();
        monitor_handles.push(tokio::spawn(async move {
            if let Err(err) =
                monitor_systemd_runtime(conn, unit_name.clone(), tx.clone(), index).await
            {
                let _ = tx.send(RuntimeUpdate::MonitorError {
                    label: format!("systemd unit {unit_name}"),
                    error: err.to_string(),
                });
            }
        }));
    }
    monitor_handles
}
