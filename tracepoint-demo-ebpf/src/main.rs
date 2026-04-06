#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    bindings::seq_file,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task_btf,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes, generated::bpf_seq_write,
    },
    macros::{map, tracepoint},
    maps::{hash_map::HashMap, per_cpu_array::PerCpuArray, ring_buf::RingBuf},
    programs::TracePointContext,
};

use tracepoint_demo_common::{
    ExecEvent, PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF, TASK_REL_TTY_NAME_SIZE, TaskRel,
};
use tracepoint_demo_ebpf::exiting_process_pid;

// aya-tool で生成した BTF 由来の型定義
#[allow(
    clippy::all,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    improper_ctypes_definitions,
    unsafe_op_in_unsafe_fn,
    unnecessary_transmutes
)]
#[rustfmt::skip]
mod vmlinux;

use crate::vmlinux::{
    bpf_iter__task, trace_event_raw_sched_process_fork, trace_event_raw_sys_enter,
};

#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
static WATCH_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static PROC_STATE: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

// per-CPU temporary buffers for filename and argv0 to avoid exceeding BPF stack limits
#[map]
static FNAME_BUF: PerCpuArray<[u8; 128]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static ARGV0_BUF: PerCpuArray<[u8; 128]> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn tracepoint_demo(ctx: TracePointContext) -> u32 {
    match unsafe { try_tracepoint_demo(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_tracepoint_demo(ctx: TracePointContext) -> Result<u32, i64> {
    let raw: trace_event_raw_sys_enter = unsafe { ctx.read_at(0) }?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid >> 32) as u32;
    let gid = uid_gid as u32;

    let flags = match unsafe { resolve_watch_flags(pid) } {
        Some(f) => f,
        None => return Ok(0),
    };

    let _watch_self = (flags & PROC_FLAG_WATCH_SELF) != 0;
    let _watch_children = (flags & PROC_FLAG_WATCH_CHILDREN) != 0;

    // Collect process name
    let mut comm = [0u8; 16];
    if let Ok(c) = bpf_get_current_comm() {
        comm = c;
    }

    // Read filename into per-CPU buffer slot 0, then copy into local array for the event
    let mut filename = [0u8; 128];
    let filename_addr = raw.args[0] as *const u8;
    if !filename_addr.is_null() {
        if let Some(ptr) = FNAME_BUF.get_ptr_mut(0) {
            let buf = unsafe { &mut *ptr };
            let _ = unsafe { bpf_probe_read_user_str_bytes(filename_addr, buf) };
            filename = *buf;
        }
    }

    // Read argv0 into per-CPU buffer slot 0, then copy into local array for the event
    let mut argv0 = [0u8; 128];
    let argv_ptr = raw.args[1] as *const *const u8;
    if !argv_ptr.is_null() {
        if let Ok(arg0_ptr) = unsafe { bpf_probe_read_user::<*const u8>(argv_ptr) } {
            if !arg0_ptr.is_null() {
                if let Some(ptr) = ARGV0_BUF.get_ptr_mut(0) {
                    let buf = unsafe { &mut *ptr };
                    let _ = unsafe { bpf_probe_read_user_str_bytes(arg0_ptr, buf) };
                    argv0 = *buf;
                }
            }
        }
    }

    if let Some(mut entry) = EXEC_EVENTS.reserve::<ExecEvent>(0) {
        let _ = entry.write(ExecEvent {
            ktime_ns: unsafe { bpf_ktime_get_ns() },
            pid,
            tid,
            uid,
            gid,
            syscall_id: raw.id as u32,
            comm,
            filename,
            argv0,
        });
        entry.submit(0);
    }

    Ok(0)
}

unsafe fn lookup_watch_flags(pid: u32) -> Option<u32> {
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
    let mut task = unsafe { bpf_get_current_task_btf() as *mut crate::vmlinux::task_struct };
    if task.is_null() {
        return None;
    }

    let mut depth = 0;
    while depth < 8 {
        let pid = unsafe { (*task).tgid as u32 };
        if let Some(flags) = unsafe { lookup_watch_flags(pid) } {
            return Some(flags);
        }

        let parent = unsafe { (*task).parent };
        if !parent.is_null() && parent != task {
            let parent_pid = unsafe { (*parent).tgid as u32 };
            if let Some(flags) = unsafe { lookup_watch_flags(parent_pid) } {
                return Some(flags);
            }
        }

        let real_parent = unsafe { (*task).real_parent };
        if !real_parent.is_null() && real_parent != task && real_parent != parent {
            let real_parent_pid = unsafe { (*real_parent).tgid as u32 };
            if let Some(flags) = unsafe { lookup_watch_flags(real_parent_pid) } {
                return Some(flags);
            }
        }

        let next_task = if !parent.is_null() && parent != task {
            parent
        } else {
            real_parent
        };
        if next_task.is_null() || next_task == task {
            break;
        }

        task = next_task;
        depth += 1;
    }

    None
}

unsafe fn resolve_watch_flags(pid: u32) -> Option<u32> {
    if let Some(flags) = unsafe { lookup_watch_flags(pid) } {
        return Some(flags);
    }

    // Walk a bounded ancestor chain so child execs stay traced even if the direct fork
    // promotion was missed or the process was inserted by an earlier runtime update.
    let flags = match unsafe { lookup_watch_flags_from_task_lineage() } {
        Some(flags) => flags,
        None => return None,
    };
    if (flags & PROC_FLAG_WATCH_CHILDREN) == 0 {
        return None;
    }

    let _ = PROC_STATE.insert(pid, flags, 0);
    Some(flags)
}

#[tracepoint]
pub fn on_fork(ctx: TracePointContext) -> u32 {
    match unsafe { try_on_fork(ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_on_fork(ctx: TracePointContext) -> Result<(), i64> {
    let raw: trace_event_raw_sched_process_fork = unsafe { ctx.read_at(0) }?;

    let cpid = raw.child_pid as u32;

    let flags = match unsafe { lookup_watch_flags(raw.parent_pid as u32) } {
        Some(f) => f,
        None => return Ok(()),
    };

    if (flags & PROC_FLAG_WATCH_CHILDREN) != 0 {
        let _ = PROC_STATE.insert(cpid, flags, 0);
    }
    Ok(())
}

#[tracepoint]
pub fn on_exit(_ctx: TracePointContext) -> u32 {
    // Keep process-granularity watch state alive across helper thread exits.
    if let Some(pid) = exiting_process_pid(bpf_get_current_pid_tgid()) {
        let _ = PROC_STATE.remove(&pid);
    }
    0
}

/// # Safety
///
/// This function is called by the BPF subsystem.
#[unsafe(link_section = "iter/task")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iter_tasks(ctx: *mut bpf_iter__task) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    unsafe {
        let meta = (*ctx).__bindgen_anon_1.meta;
        if meta.is_null() {
            return 0;
        }
        let seq = (*meta).__bindgen_anon_1.seq as *mut seq_file;
        if seq.is_null() {
            return 0;
        }

        let task = (*ctx).__bindgen_anon_2.task;
        if task.is_null() {
            return 0;
        }

        // Use thread-group IDs so userspace seeding works at process granularity
        // (not per-thread/TID granularity).
        let pid = (*task).tgid as u32;

        let parent = (*task).real_parent;
        let ppid = if parent.is_null() {
            0
        } else {
            (*parent).tgid as u32
        };

        let mut rel: TaskRel = TaskRel {
            pid,
            ppid,
            tty_name: [0u8; TASK_REL_TTY_NAME_SIZE],
        };

        if !(*task).signal.is_null() {
            let signal = (*task).signal;
            let tty = (*signal).tty;
            if !tty.is_null() {
                let name_ptr = (*tty).name.as_ptr() as *const u8;
                let _ = bpf_probe_read_kernel_str_bytes(name_ptr, &mut rel.tty_name);
            }
        }
        let _ = bpf_seq_write(
            seq,
            &rel as *const _ as *const c_void,
            core::mem::size_of::<TaskRel>() as u32,
        );

        0
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
