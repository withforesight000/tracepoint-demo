use tracepoint_demo_common::ExecEvent;

use crate::{gateway::ebpf::cstr_from_u8_escaped, usecase::port::StatusReporter};

fn startup_notice_message(
    watched_root_pids: &[String],
    tty_inputs: &[String],
    watch_children: bool,
    target_descriptions: &[String],
) -> String {
    let child_status = if watch_children {
        "watch_children=on"
    } else {
        "watch_children=off"
    };
    let target_suffix = if target_descriptions.is_empty() {
        String::new()
    } else {
        format!(" {}", target_descriptions.join(" "))
    };
    let formatted_roots = format!("[{}]", watched_root_pids.join(", "));
    let has_roots = !watched_root_pids.is_empty();

    if tty_inputs.is_empty() {
        if has_roots {
            format!(
                "Watching execve syscalls for PIDs: {} ({}){} (Ctrl-C to exit)",
                formatted_roots, child_status, target_suffix
            )
        } else {
            format!(
                "Watching execve syscalls ({}){} (Ctrl-C to exit)",
                child_status, target_suffix
            )
        }
    } else if has_roots {
        format!(
            "Watching execve syscalls for PIDs: {} (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            formatted_roots, tty_inputs, child_status, target_suffix
        )
    } else {
        format!(
            "Watching execve syscalls (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            tty_inputs, child_status, target_suffix
        )
    }
}

fn shutdown_message() -> &'static str {
    "Exiting..."
}

fn exec_event_message(event: &ExecEvent) -> String {
    format!(
        "[{:.6}] pid={} tid={} uid={} gid={} syscall_id={} \
         comm=\"{}\" filename=\"{}\" argv=\"{}\"",
        event.ktime_ns as f64 / 1e9,
        event.pid,
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
    watched_root_pids: &[String],
    tty_inputs: &[String],
    watch_children: bool,
    target_descriptions: &[String],
) {
    println!(
        "{}",
        startup_notice_message(
            watched_root_pids,
            tty_inputs,
            watch_children,
            target_descriptions,
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
    fn startup_notice_message_with_roots_and_targets() {
        let message = startup_notice_message(
            &["1".to_string(), "2".to_string(), "3".to_string()],
            &[],
            true,
            &[
                "containers=[web]".to_string(),
                "systemd-units=[sshd.service]".to_string(),
            ],
        );

        assert_eq!(
            message,
            "Watching execve syscalls for PIDs: [1, 2, 3] (watch_children=on) containers=[web] systemd-units=[sshd.service] (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_without_roots_or_targets() {
        let message = startup_notice_message(&[], &[], false, &[]);

        assert_eq!(
            message,
            "Watching execve syscalls (watch_children=off) (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_with_tty_and_roots() {
        let message = startup_notice_message(
            &["pid=4".to_string()],
            &["tty1".to_string(), "pts2".to_string()],
            true,
            &["tty=tty1".to_string()],
        );

        assert_eq!(
            message,
            "Watching execve syscalls for PIDs: [pid=4] (TTY filters: [\"tty1\", \"pts2\"]) (watch_children=on) tty=tty1 (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_with_tty_without_roots() {
        let message = startup_notice_message(
            &[],
            &["pts1".to_string()],
            false,
            &["containers=[web]".to_string()],
        );

        assert_eq!(
            message,
            "Watching execve syscalls (TTY filters: [\"pts1\"]) (watch_children=off) containers=[web] (Ctrl-C to exit)"
        );
    }

    #[test]
    fn startup_notice_message_with_targets_and_no_roots() {
        let message = startup_notice_message(
            &[],
            &[],
            true,
            &[
                "containers=[web]".to_string(),
                "systemd-units=[svc]".to_string(),
            ],
        );

        assert_eq!(
            message,
            "Watching execve syscalls (watch_children=on) containers=[web] systemd-units=[svc] (Ctrl-C to exit)"
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
            pid: 10,
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
            pid: 10,
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
            &["pid=7".to_string()],
            &["pts7".to_string()],
            true,
            &["containers=[api]".to_string()],
        );
        print_shutdown_message();
        print_exec_event(&ExecEvent {
            ktime_ns: 0,
            pid: 1,
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
