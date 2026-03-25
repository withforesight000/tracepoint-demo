use std::{collections::HashSet, future::Future, sync::Arc};

use futures_util::StreamExt;
use tokio::{
    sync::{Mutex, mpsc},
    time::{Duration, sleep},
};
use zbus::Error as ZbusError;
use zbus::fdo::PropertiesProxy;
use zbus::zvariant::OwnedObjectPath;
use zbus_systemd::systemd1::{ManagerProxy, ServiceProxy, UnitProxy};

use crate::usecase::port::{
    BoxFuture, RuntimeUpdate, SharedSystemdRuntimePort, SystemdRuntimePort,
    SystemdUnitRuntimeStatus,
};

#[derive(Debug)]
pub struct SystemdUnitStatus {
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: Option<u32>,
}

impl SystemdUnitStatus {
    pub fn is_running(&self) -> bool {
        matches!(self.active_state.as_str(), "active" | "reloading")
    }
}

pub enum SystemdUnitLookupError {
    NotFound,
    Other(anyhow::Error),
}

pub struct ResolvedSystemdUnit<'a> {
    pub _unit_path: OwnedObjectPath,
    pub unit_proxy: UnitProxy<'a>,
    pub service_proxy: ServiceProxy<'a>,
}

const SYSTEMD_ERROR_NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
const DBUS_ERROR_UNKNOWN_INTERFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";
const DBUS_ERROR_UNKNOWN_PROPERTY: &str = "org.freedesktop.DBus.Error.UnknownProperty";

struct SystemdRuntimeGateway {
    conn: zbus::Connection,
}

fn is_zbus_method_error(err: &ZbusError, expected: &str) -> bool {
    matches!(err, ZbusError::MethodError(name, _, _) if **name == expected)
}

fn status_from_query(status: SystemdUnitStatus) -> SystemdUnitRuntimeStatus {
    SystemdUnitRuntimeStatus {
        exists: true,
        active_state: Some(status.active_state),
        sub_state: Some(status.sub_state),
        main_pid: status.main_pid,
    }
}

fn collect_unique_unit_pids(entries: Vec<(String, u32, String)>) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut seen = HashSet::new();
    for (_, pid, _) in entries {
        if pid != 0 && seen.insert(pid) {
            pids.push(pid);
        }
    }
    pids
}

pub async fn query_systemd_unit_status(
    unit_proxy: &UnitProxy<'_>,
    service_proxy: &ServiceProxy<'_>,
) -> Result<SystemdUnitStatus, SystemdUnitLookupError> {
    let active_state = unit_proxy
        .active_state()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;
    let sub_state = unit_proxy
        .sub_state()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;

    let main_pid = match service_proxy.main_pid().await {
        Ok(0) => None,
        Ok(pid) => Some(pid),
        Err(err)
            if is_zbus_method_error(&err, DBUS_ERROR_UNKNOWN_INTERFACE)
                || is_zbus_method_error(&err, DBUS_ERROR_UNKNOWN_PROPERTY) =>
        {
            None
        }
        Err(err) => return Err(SystemdUnitLookupError::Other(err.into())),
    };

    Ok(SystemdUnitStatus {
        active_state,
        sub_state,
        main_pid,
    })
}

pub async fn resolve_systemd_unit<'a>(
    conn: &'a zbus::Connection,
    manager: &ManagerProxy<'a>,
    unit_name: &str,
) -> Result<ResolvedSystemdUnit<'a>, SystemdUnitLookupError> {
    let unit_path = manager
        .load_unit(unit_name.to_string())
        .await
        .map_err(|err| {
            if is_zbus_method_error(&err, SYSTEMD_ERROR_NO_SUCH_UNIT) {
                SystemdUnitLookupError::NotFound
            } else {
                SystemdUnitLookupError::Other(err.into())
            }
        })?;

    let unit_proxy = UnitProxy::builder(conn)
        .path(unit_path.clone())
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?
        .build()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;

    let service_proxy = ServiceProxy::builder(conn)
        .path(unit_path.clone())
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?
        .build()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;

    Ok(ResolvedSystemdUnit {
        _unit_path: unit_path,
        unit_proxy,
        service_proxy,
    })
}

pub async fn systemd_unit_pids(
    conn: &zbus::Connection,
    unit_name: &str,
) -> anyhow::Result<Vec<u32>> {
    let manager = ManagerProxy::new(conn).await?;
    let entries = manager.get_unit_processes(unit_name.to_string()).await?;
    Ok(collect_unique_unit_pids(entries))
}

async fn current_systemd_status(
    conn: &zbus::Connection,
    unit_name: &str,
) -> anyhow::Result<SystemdUnitRuntimeStatus> {
    let manager = ManagerProxy::new(conn)
        .await
        .map_err(|err| anyhow::anyhow!("failed to create systemd manager proxy: {err}"))?;

    match resolve_systemd_unit(conn, &manager, unit_name).await {
        Ok(resolved_unit) => {
            query_systemd_unit_status(&resolved_unit.unit_proxy, &resolved_unit.service_proxy)
                .await
                .map(status_from_query)
                .map_err(|err| match err {
                    SystemdUnitLookupError::NotFound => {
                        anyhow::anyhow!("systemd unit {unit_name} disappeared during status lookup")
                    }
                    SystemdUnitLookupError::Other(err) => err,
                })
        }
        Err(SystemdUnitLookupError::NotFound) => Ok(SystemdUnitRuntimeStatus::missing()),
        Err(SystemdUnitLookupError::Other(err)) => Err(err),
    }
}

async fn wait_systemd_unit_running<'a>(
    conn: &'a zbus::Connection,
    unit_name: &str,
) -> anyhow::Result<(ResolvedSystemdUnit<'a>, SystemdUnitStatus)> {
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
                Err(SystemdUnitLookupError::NotFound) => {}
                Err(SystemdUnitLookupError::Other(err)) => return Err(err),
            }
        }

        if let Some(cached_unit) = resolved_unit.as_ref() {
            match query_systemd_unit_status(&cached_unit.unit_proxy, &cached_unit.service_proxy)
                .await
            {
                Ok(status) if status.is_running() => {
                    let resolved_unit = resolved_unit
                        .take()
                        .expect("resolved_unit should exist when status is running");
                    return Ok((resolved_unit, status));
                }
                Ok(_) => {}
                Err(SystemdUnitLookupError::NotFound) => {
                    resolved_unit = None;
                }
                Err(SystemdUnitLookupError::Other(err)) => return Err(err),
            }
        }

        sleep(Duration::from_secs(1)).await;
    }
}

async fn monitor_systemd_runtime(
    conn: zbus::Connection,
    unit_name: String,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    loop {
        let (resolved_unit, status) = wait_systemd_unit_running(&conn, &unit_name).await?;
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
        let main_pid_changes = Arc::new(Mutex::new(main_pid_changes));
        let unit_proxy = resolved_unit.unit_proxy.clone();
        let service_proxy = resolved_unit.service_proxy.clone();

        relay_systemd_runtime_changes(
            &tx,
            index,
            status,
            {
                let main_pid_changes = main_pid_changes.clone();
                move || {
                    let main_pid_changes = main_pid_changes.clone();
                    async move {
                        let maybe_changed = {
                            let mut main_pid_changes = main_pid_changes.lock().await;
                            main_pid_changes.next().await
                        };
                        let Some(changed) = maybe_changed else {
                            return Ok(false);
                        };

                        let _ = changed.args().map_err(|err| {
                            anyhow::anyhow!("failed to decode systemd properties change: {err}")
                        })?;
                        Ok(true)
                    }
                }
            },
            {
                let unit_proxy = unit_proxy.clone();
                let service_proxy = service_proxy.clone();
                move || {
                    let unit_proxy = unit_proxy.clone();
                    let service_proxy = service_proxy.clone();
                    async move { query_systemd_unit_status(&unit_proxy, &service_proxy).await }
                }
            },
        )
        .await?;
    }
}

async fn relay_systemd_runtime_changes<TWait, TWaitFuture, TQuery, TQueryFuture>(
    tx: &mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
    initial_status: SystemdUnitStatus,
    mut wait_for_change: TWait,
    mut query_status: TQuery,
) -> anyhow::Result<()>
where
    TWait: FnMut() -> TWaitFuture,
    TWaitFuture: Future<Output = anyhow::Result<bool>>,
    TQuery: FnMut() -> TQueryFuture,
    TQueryFuture: Future<Output = Result<SystemdUnitStatus, SystemdUnitLookupError>>,
{
    let mut current = (initial_status.main_pid, initial_status.is_running());
    let _ = tx.send(RuntimeUpdate::SystemdStatus {
        index,
        pid: current.0,
        running: current.1,
    });

    loop {
        if !wait_for_change().await? {
            let _ = tx.send(RuntimeUpdate::SystemdStatus {
                index,
                pid: None,
                running: false,
            });
            return Ok(());
        }

        let status = match query_status().await {
            Ok(status) => status,
            Err(SystemdUnitLookupError::NotFound) => {
                let _ = tx.send(RuntimeUpdate::SystemdStatus {
                    index,
                    pid: None,
                    running: false,
                });
                return Ok(());
            }
            Err(SystemdUnitLookupError::Other(err)) => return Err(err),
        };

        let next = (status.main_pid, status.is_running());
        if next != current {
            current = next;
            let _ = tx.send(RuntimeUpdate::SystemdStatus {
                index,
                pid: current.0,
                running: current.1,
            });
        }
    }
}

impl SystemdRuntimePort for SystemdRuntimeGateway {
    fn current_status<'a>(
        &'a self,
        unit_name: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>> {
        Box::pin(async move { current_systemd_status(&self.conn, unit_name).await })
    }

    fn unit_pids<'a>(&'a self, unit_name: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<u32>>> {
        Box::pin(async move { systemd_unit_pids(&self.conn, unit_name).await })
    }

    fn spawn_monitor(
        &self,
        unit_name: String,
        tx: mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> tokio::task::JoinHandle<()> {
        let conn = self.conn.clone();
        tokio::spawn(async move {
            if let Err(err) =
                monitor_systemd_runtime(conn, unit_name.clone(), tx.clone(), index).await
            {
                let _ = tx.send(RuntimeUpdate::MonitorError {
                    label: format!("systemd unit {unit_name}"),
                    error: err.to_string(),
                });
            }
        })
    }
}

pub fn runtime_port(conn: zbus::Connection) -> SharedSystemdRuntimePort {
    Arc::new(SystemdRuntimeGateway { conn })
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::{Arc, Mutex}};

    use super::*;

    fn drain_updates(
        mut rx: mpsc::UnboundedReceiver<RuntimeUpdate>,
    ) -> Vec<RuntimeUpdate> {
        let mut updates = Vec::new();
        while let Ok(update) = rx.try_recv() {
            updates.push(update);
        }
        updates
    }

    #[test]
    fn status_from_query_preserves_fields() {
        let runtime_status = status_from_query(SystemdUnitStatus {
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
            main_pid: Some(77),
        });

        assert_eq!(
            runtime_status,
            SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("active".to_string()),
                sub_state: Some("running".to_string()),
                main_pid: Some(77),
            }
        );
    }

    #[test]
    fn systemd_unit_status_is_running_for_active_states() {
        let active = SystemdUnitStatus {
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
            main_pid: Some(1),
        };
        let reloading = SystemdUnitStatus {
            active_state: "reloading".to_string(),
            sub_state: "reload".to_string(),
            main_pid: Some(2),
        };

        assert!(active.is_running());
        assert!(reloading.is_running());
    }

    #[test]
    fn systemd_unit_status_is_not_running_for_other_states() {
        let status = SystemdUnitStatus {
            active_state: "inactive".to_string(),
            sub_state: "dead".to_string(),
            main_pid: None,
        };

        assert!(!status.is_running());
    }

    #[test]
    fn collect_unique_unit_pids_deduplicates_and_skips_zero() {
        let pids = collect_unique_unit_pids(vec![
            ("sshd.service".to_string(), 0, "root".to_string()),
            ("sshd.service".to_string(), 101, "root".to_string()),
            ("sshd.service".to_string(), 101, "root".to_string()),
            ("sshd.service".to_string(), 202, "daemon".to_string()),
        ]);

        assert_eq!(pids, vec![101, 202]);
    }

    #[tokio::test]
    async fn runtime_port_wraps_system_connection() {
        if let Ok(conn) = zbus::Connection::system().await {
            let _runtime = runtime_port(conn);
        }
    }

    #[tokio::test]
    async fn relay_systemd_runtime_changes_emits_initial_and_changed_statuses() {
        let (tx, rx) = mpsc::unbounded_channel();
        let changes: Arc<Mutex<VecDeque<anyhow::Result<bool>>>> = Arc::new(Mutex::new(VecDeque::from([Ok(true), Ok(true), Ok(false)])));
        let statuses: Arc<Mutex<VecDeque<Result<SystemdUnitStatus, SystemdUnitLookupError>>>> = Arc::new(Mutex::new(VecDeque::from([
            Ok(SystemdUnitStatus {
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
                main_pid: Some(10),
            }),
            Ok(SystemdUnitStatus {
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
                main_pid: Some(22),
            }),
        ])));

        relay_systemd_runtime_changes(
            &tx,
            2,
            SystemdUnitStatus {
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
                main_pid: Some(10),
            },
            {
                let changes = changes.clone();
                move || {
                    let changes = changes.clone();
                    async move { changes.lock().unwrap().pop_front().unwrap() }
                }
            },
            {
                let statuses = statuses.clone();
                move || {
                    let statuses = statuses.clone();
                    async move { statuses.lock().unwrap().pop_front().unwrap() }
                }
            },
        )
        .await
        .unwrap();

        let updates = drain_updates(rx);
        assert_eq!(updates.len(), 3);
        assert!(matches!(updates[0], RuntimeUpdate::SystemdStatus { index: 2, pid: Some(10), running: true }));
        assert!(matches!(updates[1], RuntimeUpdate::SystemdStatus { index: 2, pid: Some(22), running: true }));
        assert!(matches!(updates[2], RuntimeUpdate::SystemdStatus { index: 2, pid: None, running: false }));
    }

    #[tokio::test]
    async fn relay_systemd_runtime_changes_sends_stopped_when_unit_disappears() {
        let (tx, rx) = mpsc::unbounded_channel();
        let changes: Arc<Mutex<VecDeque<anyhow::Result<bool>>>> = Arc::new(Mutex::new(VecDeque::from([Ok(true)])));

        relay_systemd_runtime_changes(
            &tx,
            0,
            SystemdUnitStatus {
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
                main_pid: Some(7),
            },
            {
                let changes = changes.clone();
                move || {
                    let changes = changes.clone();
                    async move { changes.lock().unwrap().pop_front().unwrap() }
                }
            },
            || async { Err(SystemdUnitLookupError::NotFound) },
        )
        .await
        .unwrap();

        let updates = drain_updates(rx);
        assert_eq!(updates.len(), 2);
        assert!(matches!(updates[0], RuntimeUpdate::SystemdStatus { index: 0, pid: Some(7), running: true }));
        assert!(matches!(updates[1], RuntimeUpdate::SystemdStatus { index: 0, pid: None, running: false }));
    }

    #[tokio::test]
    async fn relay_systemd_runtime_changes_propagates_query_errors() {
        let (tx, rx) = mpsc::unbounded_channel();
        let changes: Arc<Mutex<VecDeque<anyhow::Result<bool>>>> = Arc::new(Mutex::new(VecDeque::from([Ok(true)])));

        let err = relay_systemd_runtime_changes(
            &tx,
            1,
            SystemdUnitStatus {
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
                main_pid: Some(9),
            },
            {
                let changes = changes.clone();
                move || {
                    let changes = changes.clone();
                    async move { changes.lock().unwrap().pop_front().unwrap() }
                }
            },
            || async {
                Err(SystemdUnitLookupError::Other(anyhow::anyhow!(
                    "query failed"
                )))
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "query failed");
        let updates = drain_updates(rx);
        assert_eq!(updates.len(), 1);
        assert!(matches!(updates[0], RuntimeUpdate::SystemdStatus { index: 1, pid: Some(9), running: true }));
    }
}
