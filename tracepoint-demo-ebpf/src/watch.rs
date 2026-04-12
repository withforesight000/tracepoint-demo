use aya_ebpf::helpers::bpf_get_current_task;

use crate::{
    maps::{PROC_STATE, WATCH_PIDS},
    vmlinux::task_struct,
};
use tracepoint_demo_ebpf::{
    LineageHop, MAX_LINEAGE_DEPTH, child_watch_flags, match_lineage_flags, next_lineage_hop,
};

pub(crate) unsafe fn lookup_watch_flags(pid: u32) -> Option<u32> {
    if let Some(flags) = unsafe { PROC_STATE.get(pid) } {
        return Some(*flags);
    }

    if let Some(flags) = unsafe { WATCH_PIDS.get(pid) } {
        let flags = *flags;
        let _ = PROC_STATE.insert(pid, flags, 0);
        return Some(flags);
    }

    None
}

unsafe fn lookup_watch_flags_from_task_lineage() -> Option<u32> {
    // Use the older helper here so the tracepoint program keeps loading on
    // kernels that reject bpf_get_current_task_btf in this program type.
    let mut task = unsafe { bpf_get_current_task() as *mut task_struct };
    if task.is_null() {
        return None;
    }

    let mut depth = 0;
    while depth < MAX_LINEAGE_DEPTH {
        let pid = unsafe { (*task).tgid as u32 };
        let parent = unsafe { (*task).parent };
        let parent_pid = if !parent.is_null() && parent != task {
            Some(unsafe { (*parent).tgid as u32 })
        } else {
            None
        };

        let real_parent = unsafe { (*task).real_parent };
        let real_parent_pid = if !real_parent.is_null() && real_parent != task {
            Some(unsafe { (*real_parent).tgid as u32 })
        } else {
            None
        };

        if let Some(flags) =
            match_lineage_flags(pid, parent_pid, real_parent_pid, |candidate_pid| unsafe {
                lookup_watch_flags(candidate_pid)
            })
        {
            return Some(flags);
        }

        let next_task = match next_lineage_hop(pid, parent_pid, real_parent_pid) {
            Some(LineageHop::Parent) => parent,
            Some(LineageHop::RealParent) => real_parent,
            None => break,
        };

        task = next_task;
        depth += 1;
    }

    None
}

pub(crate) unsafe fn resolve_watch_flags(pid: u32) -> Option<u32> {
    if let Some(flags) = unsafe { lookup_watch_flags(pid) } {
        return Some(flags);
    }

    let flags = match unsafe { lookup_watch_flags_from_task_lineage() } {
        Some(flags) => flags,
        None => return None,
    };
    if child_watch_flags(flags).is_none() {
        return None;
    }

    let _ = PROC_STATE.insert(pid, flags, 0);
    Some(flags)
}

pub(crate) unsafe fn inherit_child_watch(parent_pid: u32, child_pid: u32) {
    let flags = match unsafe { lookup_watch_flags(parent_pid) } {
        Some(flags) => flags,
        None => return,
    };

    if let Some(flags) = child_watch_flags(flags) {
        let _ = PROC_STATE.insert(child_pid, flags, 0);
    }
}

pub(crate) fn remove_watch_state(pid: u32) {
    let _ = PROC_STATE.remove(&pid);
}
