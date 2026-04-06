#[derive(Debug)]
pub enum RuntimeUpdate {
    ContainerPid {
        index: usize,
        pid: Option<u32>,
        /// Refresh even when the main PID is unchanged.
        force_refresh: bool,
        /// Additional PIDs to seed directly, such as Docker exec processes.
        extra_pids: Vec<u32>,
    },
    SystemdStatus {
        index: usize,
        pid: Option<u32>,
        running: bool,
    },
    MonitorError {
        label: String,
        error: String,
    },
}
