pub fn print_startup_notice(
    watched_root_pids: &[u32],
    tty_inputs: &[String],
    watch_children: bool,
    target_descriptions: &[String],
) {
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
            println!(
                "Watching execve syscalls for PIDs: {:?} ({}){} (Ctrl-C to exit)",
                watched_root_pids, child_status, target_suffix
            );
        } else {
            println!(
                "Watching execve syscalls ({}){} (Ctrl-C to exit)",
                child_status, target_suffix
            );
        }
    } else if has_roots {
        println!(
            "Watching execve syscalls for PIDs: {:?} (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            watched_root_pids, tty_inputs, child_status, target_suffix
        );
    } else {
        println!(
            "Watching execve syscalls (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            tty_inputs, child_status, target_suffix
        );
    }
}

pub fn print_shutdown_message() {
    println!("Exiting...");
}
