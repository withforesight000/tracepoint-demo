use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdUnitRuntimeStatus {
    pub exists: bool,
    pub active_state: Option<String>,
    pub sub_state: Option<String>,
    pub main_pid: Option<u32>,
}

impl SystemdUnitRuntimeStatus {
    pub fn missing() -> Self {
        Self {
            exists: false,
            active_state: None,
            sub_state: None,
            main_pid: None,
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self.active_state.as_deref(), Some("active" | "reloading"))
    }
}

pub trait ContainerRuntimePort: Send + Sync {
    fn query_main_pid<'a>(
        &'a self,
        name_or_id: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<Option<u32>>>;
}

pub trait SystemdRuntimePort: Send + Sync {
    fn current_status<'a>(
        &'a self,
        unit_name: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<SystemdUnitRuntimeStatus>>;

    fn unit_pids<'a>(&'a self, unit_name: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<u32>>>;
}

pub type SharedContainerRuntimePort = Arc<dyn ContainerRuntimePort>;
pub type SharedSystemdRuntimePort = Arc<dyn SystemdRuntimePort>;

pub trait WatchPidStore {
    fn remove_watch_pid(&mut self, pid: u32) -> anyhow::Result<()>;

    fn upsert_watch_pid(&mut self, pid: u32, flags: u32) -> anyhow::Result<()>;
}

pub trait StatusReporter {
    fn info(&mut self, message: String);
    fn warn(&mut self, message: String);
}

pub trait WaitPort {
    fn wait<'a>(
        &'a mut self,
        duration: Duration,
        interrupted_message: String,
    ) -> BoxFuture<'a, anyhow::Result<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_systemd_status_is_not_running() {
        assert!(!SystemdUnitRuntimeStatus::missing().is_running());
    }

    #[test]
    fn running_systemd_status_matches_active_and_reloading_states() {
        assert!(
            SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("active".to_string()),
                sub_state: Some("running".to_string()),
                main_pid: Some(1),
            }
            .is_running()
        );

        assert!(
            SystemdUnitRuntimeStatus {
                exists: true,
                active_state: Some("reloading".to_string()),
                sub_state: Some("reload".to_string()),
                main_pid: Some(2),
            }
            .is_running()
        );
    }
}
