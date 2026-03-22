use clap::{ArgGroup, Parser};

use crate::usecase::trace_selected_targets::TraceRequest;

#[derive(Parser)]
#[command(author, version, about = "Traces execve syscalls for a set of processes", long_about = None)]
#[command(arg_required_else_help = true)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(true)
        .args(["pid", "positional_pids", "tty", "container", "systemd_unit"])
))]
pub struct CliArgs {
    /// Repeated `--pid` arguments keep the option-style interface used in earlier versions.
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pub pid: Vec<u32>,

    /// Positional PIDs can be used instead of `--pid`.
    #[arg(value_name = "PID", conflicts_with_all = ["pid", "tty", "container", "systemd_unit"])]
    pub positional_pids: Vec<u32>,

    /// Monitor processes that share the specified controlling terminal.
    #[arg(
        short = 't',
        long = "tty",
        value_name = "TTY",
        conflicts_with_all = ["pid", "positional_pids", "container", "systemd_unit"]
    )]
    pub tty: Vec<String>,

    /// Monitor processes inside the specified Docker container (by name or ID).
    #[arg(
        short = 'c',
        long = "container",
        value_name = "NAME_OR_ID",
        conflicts_with_all = ["pid", "positional_pids", "tty"]
    )]
    pub container: Vec<String>,

    /// Seed all processes currently in the container at startup.
    /// This is useful to processes to start with `docker exec`.
    #[arg(long = "all-container-processes", requires = "container")]
    pub all_container_processes: bool,

    /// Monitor processes inside the specified systemd unit.
    #[arg(
        short = 'u',
        long = "systemd-unit",
        value_name = "UNIT",
        conflicts_with_all = ["pid", "positional_pids", "tty"]
    )]
    pub systemd_unit: Vec<String>,

    /// Seed all processes currently in the systemd unit at startup.
    #[arg(long = "all-systemd-processes", requires = "systemd_unit")]
    pub all_systemd_processes: bool,

    /// Do not follow child processes when tracing (default traces children as well).
    #[arg(long = "no-watch-children")]
    pub no_watch_children: bool,
}

impl CliArgs {
    pub fn into_request(self) -> TraceRequest {
        let mut pids = self.pid;
        pids.extend(self.positional_pids);

        TraceRequest {
            pids,
            tty_inputs: self.tty,
            containers: self.container,
            all_container_processes: self.all_container_processes,
            systemd_units: self.systemd_unit,
            all_systemd_processes: self.all_systemd_processes,
            watch_children: !self.no_watch_children,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_request_merges_pid_inputs_and_flips_watch_children_flag() {
        let request = CliArgs {
            pid: vec![10],
            positional_pids: vec![20],
            tty: vec!["/dev/pts/3".to_string()],
            container: vec!["web".to_string()],
            all_container_processes: true,
            systemd_unit: vec!["sshd.service".to_string()],
            all_systemd_processes: false,
            no_watch_children: true,
        }
        .into_request();

        assert_eq!(request.pids, vec![10, 20]);
        assert_eq!(request.tty_inputs, vec!["/dev/pts/3".to_string()]);
        assert_eq!(request.containers, vec!["web".to_string()]);
        assert!(request.all_container_processes);
        assert_eq!(request.systemd_units, vec!["sshd.service".to_string()]);
        assert!(!request.all_systemd_processes);
        assert!(!request.watch_children);
    }
}
