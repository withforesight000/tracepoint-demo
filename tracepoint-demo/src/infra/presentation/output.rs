use tracepoint_demo_common::ExecEvent;

use crate::{
    gateway::ebpf::cstr_from_u8_escaped,
    usecase::{orchestration::state::StartupWatchPidGroup, port::StatusReporter},
};

fn format_simple_pid_group(label: &str, pids: &[u32]) -> Option<String> {
    let mut pids = pids.to_vec();
    pids.sort_unstable();
    pids.dedup();

    let (first, rest) = pids.split_first()?;
    let mut parts = vec![format!("pid={first}")];
    parts.extend(rest.iter().map(|pid| pid.to_string()));

    Some(format!("{label}:({})", parts.join(", ")))
}

fn format_runtime_pid_group(
    label: &str,
    current_pid: Option<u32>,
    seeded_pids: &[u32],
) -> Option<String> {
    let mut pids = seeded_pids.to_vec();
    pids.sort_unstable();
    pids.dedup();

    let mut parts = Vec::new();

    if let Some(pid) = current_pid {
        parts.push(format!("main={pid}"));
        pids.retain(|candidate| *candidate != pid);
    }

    if let Some((first, rest)) = pids.split_first() {
        parts.push(format!("pid={first}"));
        parts.extend(rest.iter().map(|pid| format!("pid={pid}")));
    }

    if parts.is_empty() {
        None
    } else {
        Some(format!("{label}:({})", parts.join(", ")))
    }
}

fn format_startup_watch_pid_group(group: &StartupWatchPidGroup) -> Option<String> {
    match group {
        StartupWatchPidGroup::Simple { label, pids } => format_simple_pid_group(label, pids),
        StartupWatchPidGroup::Runtime {
            label,
            current_pid,
            seeded_pids,
        } => format_runtime_pid_group(label, *current_pid, seeded_pids),
    }
}

fn startup_notice_message(
    watched_pid_groups: &[StartupWatchPidGroup],
    watch_children: bool,
    all_container_processes: bool,
    all_systemd_processes: bool,
) -> String {
    let child_status = if watch_children {
        "watch_children=on"
    } else {
        "watch_children=off"
    };
    let mut suffixes = Vec::new();
    if all_container_processes {
        suffixes.push("(all-container-processes=on)".to_string());
    }
    if all_systemd_processes {
        suffixes.push("(all-systemd-processes=on)".to_string());
    }

    let mut message = if watched_pid_groups.is_empty() {
        format!("Watching execve syscalls ({})", child_status)
    } else {
        let formatted_groups = watched_pid_groups
            .iter()
            .filter_map(format_startup_watch_pid_group)
            .collect::<Vec<_>>();

        if formatted_groups.is_empty() {
            format!("Watching execve syscalls ({})", child_status)
        } else {
            format!(
                "Watching execve syscalls for PIDs: [{}] ({})",
                formatted_groups.join(", "),
                child_status
            )
        }
    };

    for suffix in suffixes {
        message.push(' ');
        message.push_str(&suffix);
    }

    message.push_str(" (Ctrl-C to exit)");
    message
}

fn shutdown_message() -> &'static str {
    "Exiting..."
}

fn exec_event_message(event: &ExecEvent) -> String {
    format!(
        "[{:.6}] pid={} tid={} uid={} gid={} syscall_id={} \
         comm=\"{}\" filename=\"{}\" argv=\"{}\"",
        event.ktime_ns as f64 / 1e9,
        event.tgid,
        event.tid,
        event.uid,
        event.gid,
        event.syscall_id,
        cstr_from_u8_escaped(&event.comm),
        cstr_from_u8_escaped(&event.filename),
        exec_argv_string(event),
    )
}

fn exec_argv_string(event: &ExecEvent) -> String {
    event
        .argv
        .iter()
        .map(|slot| cstr_from_u8_escaped(slot))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn invalid_exec_event_size_message(actual: usize, expected: usize) -> String {
    format!("unexpected ExecEvent size: {actual} (expected {expected})")
}

pub struct ConsoleStatusReporter;

impl StatusReporter for ConsoleStatusReporter {
    fn info(&mut self, message: String) {
        println!("{message}");
    }

    fn warn(&mut self, message: String) {
        eprintln!("{message}");
    }
}

pub fn print_startup_notice(
    watched_pid_groups: &[StartupWatchPidGroup],
    watch_children: bool,
    all_container_processes: bool,
    all_systemd_processes: bool,
) {
    println!(
        "{}",
        startup_notice_message(
            watched_pid_groups,
            watch_children,
            all_container_processes,
            all_systemd_processes,
        )
    );
}

pub fn print_shutdown_message() {
    println!("{}", shutdown_message());
}

pub fn print_exec_event(event: &ExecEvent) {
    println!("{}", exec_event_message(event));
}

pub fn print_invalid_exec_event_size(actual: usize, expected: usize) {
    eprintln!("{}", invalid_exec_event_size_message(actual, expected));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_notice_message_with_pid_group() {
        let message = startup_notice_message(
            &[StartupWatchPidGroup::simple("pid", vec![1111, 2222])],
            true,
            false,
            false,
        );

        assert_eq!(
            message,
            "Watching execve syscalls for PIDs: [pid:(pid=1111, 2222)] (watch_children=on) (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_without_groups_or_flags() {
        let message = startup_notice_message(&[], false, false, false);

        assert_eq!(
            message,
            "Watching execve syscalls (watch_children=off) (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_with_tty_container_and_systemd_groups() {
        let message = startup_notice_message(
            &[
                StartupWatchPidGroup::simple("tty:/dev/pts/3", vec![527_814, 527_818]),
                StartupWatchPidGroup::runtime(
                    "container:mystifying_chatterjee",
                    Some(546_054),
                    vec![],
                ),
                StartupWatchPidGroup::runtime(
                    "systemd:libvirtd.service",
                    Some(565_043),
                    vec![1_138, 1_139],
                ),
            ],
            true,
            true,
            true,
        );

        assert_eq!(
            message,
            "Watching execve syscalls for PIDs: [tty:/dev/pts/3:(pid=527814, 527818), container:mystifying_chatterjee:(main=546054), systemd:libvirtd.service:(main=565043, pid=1138, pid=1139)] (watch_children=on) (all-container-processes=on) (all-systemd-processes=on) (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_with_pid_tty_container_and_systemd_groups() {
        let message = startup_notice_message(
            &[
                StartupWatchPidGroup::simple("pid", vec![1111]),
                StartupWatchPidGroup::simple("tty:/dev/pts/3", vec![3333, 3334]),
                StartupWatchPidGroup::runtime("container:web", Some(4444), vec![]),
                StartupWatchPidGroup::runtime("systemd:sshd.service", Some(5555), vec![]),
            ],
            false,
            true,
            false,
        );

        assert_eq!(
            message,
            "Watching execve syscalls for PIDs: [pid:(pid=1111), tty:/dev/pts/3:(pid=3333, 3334), container:web:(main=4444), systemd:sshd.service:(main=5555)] (watch_children=off) (all-container-processes=on) (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_with_pid_only_and_no_suffixes() {
        let message = startup_notice_message(
            &[StartupWatchPidGroup::simple("pid", vec![1])],
            false,
            false,
            false,
        );

        assert_eq!(
            message,
            "Watching execve syscalls for PIDs: [pid:(pid=1)] (watch_children=off) (Ctrl-C to exit)"
        );
    }

    #[test]
    fn shutdown_message_is_constant() {
        assert_eq!(shutdown_message(), "Exiting...");
    }

    #[test]
    fn exec_event_message_formats_fields() {
        let event = ExecEvent {
            ktime_ns: 123_000_000,
            tgid: 10,
            tid: 10,
            uid: 1000,
            gid: 1000,
            syscall_id: 59,
            comm: [0; tracepoint_demo_common::EXEC_EVENT_COMM_SIZE],
            filename: [0; tracepoint_demo_common::EXEC_EVENT_FILENAME_SIZE],
            argv: [[0; tracepoint_demo_common::EXEC_EVENT_ARG_SLOT_SIZE];
                tracepoint_demo_common::EXEC_EVENT_ARG_SLOTS],
        };

        let message = exec_event_message(&event);

        assert!(message.contains("[0.123000]"));
        assert!(message.contains("pid=10"));
        assert!(message.contains("tid=10"));
        assert!(message.contains("syscall_id=59"));
        assert!(message.contains("argv=\"\""));
    }

    #[test]
    fn invalid_exec_event_size_message_is_descriptive() {
        assert_eq!(
            invalid_exec_event_size_message(12, 496),
            "unexpected ExecEvent size: 12 (expected 496)"
        );
    }

    #[test]
    fn exec_event_message_escapes_non_utf8_bytes() {
        let mut event = ExecEvent {
            ktime_ns: 123_000_000,
            tgid: 10,
            tid: 10,
            uid: 1000,
            gid: 1000,
            syscall_id: 59,
            comm: [0; tracepoint_demo_common::EXEC_EVENT_COMM_SIZE],
            filename: [0; tracepoint_demo_common::EXEC_EVENT_FILENAME_SIZE],
            argv: [[0; tracepoint_demo_common::EXEC_EVENT_ARG_SLOT_SIZE];
                tracepoint_demo_common::EXEC_EVENT_ARG_SLOTS],
        };
        event.argv[0][..7].copy_from_slice(b"uname \xff");

        let message = exec_event_message(&event);

        assert!(message.contains("argv=\"uname \\xff\""));
    }

    #[test]
    fn print_functions_delegate_to_message_helpers() {
        print_startup_notice(
            &[StartupWatchPidGroup::simple("pid", vec![7])],
            true,
            false,
            true,
        );
        print_shutdown_message();
        print_exec_event(&ExecEvent {
            ktime_ns: 0,
            tgid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            syscall_id: 59,
            comm: [0; tracepoint_demo_common::EXEC_EVENT_COMM_SIZE],
            filename: [0; tracepoint_demo_common::EXEC_EVENT_FILENAME_SIZE],
            argv: [[0; tracepoint_demo_common::EXEC_EVENT_ARG_SLOT_SIZE];
                tracepoint_demo_common::EXEC_EVENT_ARG_SLOTS],
        });
        print_invalid_exec_event_size(12, 496);
    }

    #[test]
    fn console_status_reporter_accepts_info_and_warn_messages() {
        let mut reporter = ConsoleStatusReporter;

        reporter.info("hello info".to_string());
        reporter.warn("hello warn".to_string());
    }
}
