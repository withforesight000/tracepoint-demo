fn startup_notice_message(
    watched_root_pids: &[u32],
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
    let has_roots = !watched_root_pids.is_empty();

    if tty_inputs.is_empty() {
        if has_roots {
            format!(
                "Watching execve syscalls for PIDs: {:?} ({}){} (Ctrl-C to exit)",
                watched_root_pids, child_status, target_suffix
            )
        } else {
            format!(
                "Watching execve syscalls ({}){} (Ctrl-C to exit)",
                child_status, target_suffix
            )
        }
    } else if has_roots {
        format!(
            "Watching execve syscalls for PIDs: {:?} (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            watched_root_pids, tty_inputs, child_status, target_suffix
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

pub fn print_startup_notice(
    watched_root_pids: &[u32],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_notice_message_with_roots_and_targets() {
        let message = startup_notice_message(
            &[1, 2, 3],
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
            &[4],
            &["tty1".to_string(), "pts2".to_string()],
            true,
            &["tty=tty1".to_string()],
        );

        assert_eq!(
            message,
            "Watching execve syscalls for PIDs: [4] (TTY filters: [\"tty1\", \"pts2\"]) (watch_children=on) tty=tty1 (Ctrl-C to exit)"
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
    fn shutdown_message_is_constant() {
        assert_eq!(shutdown_message(), "Exiting...");
    }

    #[test]
    fn print_functions_delegate_to_message_helpers() {
        print_startup_notice(
            &[7],
            &["pts7".to_string()],
            true,
            &["containers=[api]".to_string()],
        );
        print_shutdown_message();
    }
}
