#![no_std]

use tracepoint_demo_common::PROC_FLAG_WATCH_CHILDREN;

pub const MAX_LINEAGE_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineageHop {
    Parent,
    RealParent,
}

pub fn split_pid_tgid(pid_tgid: u64) -> (u32, u32) {
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

pub fn split_uid_gid(uid_gid: u64) -> (u32, u32) {
    ((uid_gid >> 32) as u32, uid_gid as u32)
}

pub fn exiting_process_pid(pid_tgid: u64) -> Option<u32> {
    let (pid, tid) = split_pid_tgid(pid_tgid);
    (pid == tid).then_some(pid)
}

pub fn child_watch_flags(flags: u32) -> Option<u32> {
    ((flags & PROC_FLAG_WATCH_CHILDREN) != 0).then_some(flags)
}

pub fn match_lineage_flags<TLookup>(
    current_pid: u32,
    parent_pid: Option<u32>,
    real_parent_pid: Option<u32>,
    mut lookup: TLookup,
) -> Option<u32>
where
    TLookup: FnMut(u32) -> Option<u32>,
{
    if let Some(flags) = lookup(current_pid) {
        return Some(flags);
    }

    let parent_pid = sanitize_parent_pid(current_pid, parent_pid);
    if let Some(pid) = parent_pid
        && let Some(flags) = lookup(pid)
    {
        return Some(flags);
    }

    let real_parent_pid = sanitize_real_parent_pid(current_pid, parent_pid, real_parent_pid);
    if let Some(pid) = real_parent_pid
        && let Some(flags) = lookup(pid)
    {
        return Some(flags);
    }

    None
}

pub fn next_lineage_hop(
    current_pid: u32,
    parent_pid: Option<u32>,
    real_parent_pid: Option<u32>,
) -> Option<LineageHop> {
    let parent_pid = sanitize_parent_pid(current_pid, parent_pid);
    if parent_pid.is_some() {
        return Some(LineageHop::Parent);
    }

    sanitize_real_parent_pid(current_pid, parent_pid, real_parent_pid)
        .map(|_| LineageHop::RealParent)
}

fn sanitize_parent_pid(current_pid: u32, parent_pid: Option<u32>) -> Option<u32> {
    parent_pid.filter(|pid| *pid != current_pid)
}

fn sanitize_real_parent_pid(
    current_pid: u32,
    parent_pid: Option<u32>,
    real_parent_pid: Option<u32>,
) -> Option<u32> {
    real_parent_pid.filter(|pid| *pid != current_pid && Some(*pid) != parent_pid)
}

#[cfg(test)]
mod tests {
    use super::{
        LineageHop, child_watch_flags, exiting_process_pid, match_lineage_flags, next_lineage_hop,
        split_pid_tgid, split_uid_gid,
    };
    use tracepoint_demo_common::{PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

    #[test]
    fn split_pid_tgid_splits_high_and_low_halves() {
        let pid_tgid = (42_u64 << 32) | 7_u64;
        assert_eq!(split_pid_tgid(pid_tgid), (42, 7));
    }

    #[test]
    fn split_uid_gid_splits_high_and_low_halves() {
        let uid_gid = (1000_u64 << 32) | 100_u64;
        assert_eq!(split_uid_gid(uid_gid), (1000, 100));
    }

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

    #[test]
    fn child_watch_flags_returns_flags_when_children_bit_is_set() {
        let flags = PROC_FLAG_WATCH_SELF | PROC_FLAG_WATCH_CHILDREN;
        assert_eq!(child_watch_flags(flags), Some(flags));
    }

    #[test]
    fn child_watch_flags_rejects_self_only_flags() {
        assert_eq!(child_watch_flags(PROC_FLAG_WATCH_SELF), None);
    }

    #[test]
    fn match_lineage_flags_checks_current_pid_first() {
        let matched = match_lineage_flags(10, Some(20), Some(30), |pid| match pid {
            10 => Some(0x1),
            20 => Some(0x2),
            30 => Some(0x4),
            _ => None,
        });

        assert_eq!(matched, Some(0x1));
    }

    #[test]
    fn match_lineage_flags_falls_back_to_parent() {
        let matched = match_lineage_flags(10, Some(20), Some(30), |pid| match pid {
            20 => Some(0x2),
            30 => Some(0x4),
            _ => None,
        });

        assert_eq!(matched, Some(0x2));
    }

    #[test]
    fn match_lineage_flags_uses_real_parent_when_parent_has_no_match() {
        let matched = match_lineage_flags(10, Some(20), Some(30), |pid| match pid {
            30 => Some(0x4),
            _ => None,
        });

        assert_eq!(matched, Some(0x4));
    }

    #[test]
    fn match_lineage_flags_skips_duplicate_parent_candidates() {
        let matched = match_lineage_flags(10, Some(20), Some(20), |pid| match pid {
            20 => Some(0x2),
            _ => None,
        });

        assert_eq!(matched, Some(0x2));
    }

    #[test]
    fn match_lineage_flags_skips_self_referential_parents() {
        let matched = match_lineage_flags(10, Some(10), Some(10), |_pid| None);
        assert_eq!(matched, None);
    }

    #[test]
    fn next_lineage_hop_prefers_parent_when_available() {
        assert_eq!(
            next_lineage_hop(10, Some(20), Some(30)),
            Some(LineageHop::Parent)
        );
    }

    #[test]
    fn next_lineage_hop_uses_real_parent_when_parent_is_invalid() {
        assert_eq!(
            next_lineage_hop(10, Some(10), Some(30)),
            Some(LineageHop::RealParent)
        );
    }

    #[test]
    fn next_lineage_hop_returns_none_without_valid_candidates() {
        assert_eq!(next_lineage_hop(10, Some(10), Some(10)), None);
        assert_eq!(next_lineage_hop(10, None, None), None);
    }
}
