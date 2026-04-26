use std::collections::HashMap as StdHashMap;

use crate::{
    usecase::policy::watch_container::ContainerRuntime,
    usecase::policy::watch_systemd_unit::SystemdRuntime,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupWatchPidGroup {
    Simple {
        label: String,
        pids: Vec<u32>,
    },
    Runtime {
        label: String,
        current_pid: Option<u32>,
        seeded_pids: Vec<u32>,
    },
}

impl StartupWatchPidGroup {
    pub fn simple(label: impl Into<String>, pids: Vec<u32>) -> Self {
        Self::Simple {
            label: label.into(),
            pids,
        }
    }

    pub fn runtime(
        label: impl Into<String>,
        current_pid: Option<u32>,
        seeded_pids: Vec<u32>,
    ) -> Self {
        Self::Runtime {
            label: label.into(),
            current_pid,
            seeded_pids,
        }
    }
}

pub struct AppState {
    pub static_watch_roots: StdHashMap<u32, u32>,
    pub current_watch_roots: StdHashMap<u32, u32>,
    pub container_runtimes: Vec<ContainerRuntime>,
    pub systemd_runtimes: Vec<SystemdRuntime>,
}
