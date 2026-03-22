use std::collections::HashSet;

use zbus::Error as ZbusError;
use zbus::zvariant::OwnedObjectPath;
use zbus_systemd::systemd1::{ManagerProxy, ServiceProxy, UnitProxy};

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

fn is_zbus_method_error(err: &ZbusError, expected: &str) -> bool {
    matches!(err, ZbusError::MethodError(name, _, _) if **name == expected)
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
