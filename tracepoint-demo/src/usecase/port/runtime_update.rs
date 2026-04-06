#[derive(Debug)]
pub enum RuntimeUpdate {
    ContainerPid {
        index: usize,
        pid: Option<u32>,
        /// Refresh even when the main PID is unchanged.
        force_refresh: bool,
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
