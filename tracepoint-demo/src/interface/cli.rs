use clap::{ArgGroup, Parser};

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

pub fn normalize_tty_name(tty: &str) -> String {
    let name = tty.strip_prefix("/dev/").unwrap_or(tty);
    if let Some(rest) = name.strip_prefix("pts/") {
        format!("pts{rest}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_tty_name_drops_dev_prefix_and_pts_slash() {
        assert_eq!(normalize_tty_name("/dev/pts/3"), "pts3");
        assert_eq!(normalize_tty_name("/dev/tty1"), "tty1");
    }

    #[test]
    fn normalize_tty_name_handles_already_normalized() {
        assert_eq!(normalize_tty_name("pts2"), "pts2");
        assert_eq!(normalize_tty_name("tty0"), "tty0");
    }
}
