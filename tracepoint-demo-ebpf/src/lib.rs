#![no_std]

pub fn exiting_process_pid(pid_tgid: u64) -> Option<u32> {
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    (pid == tid).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::exiting_process_pid;

    #[test]
    fn exiting_process_pid_returns_pid_for_thread_group_leader() {
        let pid_tgid = (42_u64 << 32) | 42_u64;
        assert_eq!(exiting_process_pid(pid_tgid), Some(42));
    }

    #[test]
    fn exiting_process_pid_ignores_non_leader_thread_exit() {
        let pid_tgid = (42_u64 << 32) | 7_u64;
        assert_eq!(exiting_process_pid(pid_tgid), None);
    }
}
