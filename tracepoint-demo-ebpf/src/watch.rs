use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use core::ptr;

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

unsafe fn read_task_tgid(task: *mut task_struct) -> Option<u32> {
    let pid = unsafe { bpf_probe_read_kernel(ptr::addr_of!((*task).tgid)) }.ok()?;
    Some(pid as u32)
}

unsafe fn read_task_parent(task: *mut task_struct) -> Option<*mut task_struct> {
    let parent = unsafe { bpf_probe_read_kernel(ptr::addr_of!((*task).parent)) }.ok()?;
    (!parent.is_null()).then_some(parent)
}

unsafe fn read_task_real_parent(task: *mut task_struct) -> Option<*mut task_struct> {
    let real_parent = unsafe { bpf_probe_read_kernel(ptr::addr_of!((*task).real_parent)) }.ok()?;
    (!real_parent.is_null()).then_some(real_parent)
}

unsafe fn lookup_watch_flags_from_task_lineage(current_pid: u32) -> Option<u32> {
    // Use the older helper here so the tracepoint program keeps loading on
    // kernels that reject bpf_get_current_task_btf in this program type.
    let mut task = unsafe { bpf_get_current_task() as *mut task_struct };
    if task.is_null() {
        return None;
    }

    let mut pid = current_pid;
    let mut depth = 0;
    while depth < MAX_LINEAGE_DEPTH {
        let parent = unsafe { read_task_parent(task) };
        let parent_pid = match parent {
            Some(parent) if parent != task => unsafe { read_task_tgid(parent) },
            _ => None,
        };

        let real_parent = unsafe { read_task_real_parent(task) };
        let real_parent_pid = match real_parent {
            Some(real_parent) if real_parent != task => unsafe { read_task_tgid(real_parent) },
            _ => None,
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
        let next_task = match next_task {
            Some(next_task) => next_task,
            None => break,
        };

        task = next_task;
        pid = match unsafe { read_task_tgid(task) } {
            Some(pid) => pid,
            None => break,
        };
        depth += 1;
    }

    None
}

pub(crate) unsafe fn resolve_watch_flags(pid: u32) -> Option<u32> {
    if let Some(flags) = unsafe { lookup_watch_flags(pid) } {
        return Some(flags);
    }

    let flags = match unsafe { lookup_watch_flags_from_task_lineage(pid) } {
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
