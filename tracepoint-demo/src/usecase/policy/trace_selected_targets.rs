pub struct TraceRequest {
    pub pids: Vec<u32>,
    pub tty_inputs: Vec<String>,
    pub containers: Vec<String>,
    pub all_container_processes: bool,
    pub systemd_units: Vec<String>,
    pub all_systemd_processes: bool,
    pub watch_children: bool,
}
