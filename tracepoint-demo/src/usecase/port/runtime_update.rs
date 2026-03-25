#[derive(Debug)]
pub enum RuntimeUpdate {
    ContainerPid {
        index: usize,
        pid: Option<u32>,
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
