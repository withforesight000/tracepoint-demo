#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    bindings::seq_file,
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
        bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
        generated::bpf_seq_write,
    },
    macros::{map, tracepoint},
    maps::{hash_map::HashMap, per_cpu_array::PerCpuArray, ring_buf::RingBuf},
    programs::TracePointContext,
};

use tracepoint_demo_common::{ExecEvent, PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF, TASK_REL_TTY_NAME_SIZE, TaskRel};

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

    let mut flags_opt: Option<u32> = None;

    // implement the process-watch lookup and caching logic used to decide whether
    // to monitor the current PID:
    // - First check PROC_STATE (a per-PID cache) for existing watch flags.
    // - If not found, fall back to WATCH_PIDS (a userspace-managed map) and, when present,
    //   copy (promote) the flags into PROC_STATE so subsequent events for the same PID are
    //   resolved quickly on the hot path.
    // - If neither map contains flags, the handler returns early and does not emit an event.
    if let Some(flags) = unsafe { PROC_STATE.get(pid) } {
        flags_opt = Some(*flags);
    } else if let Some(flags) = unsafe { WATCH_PIDS.get(pid) } {
        flags_opt = Some(*flags);
        let _ = PROC_STATE.insert(pid, *flags, 0);
    }

    let flags = match flags_opt {
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

#[tracepoint]
pub fn on_fork(ctx: TracePointContext) -> u32 {
    match unsafe { try_on_fork(ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_on_fork(ctx: TracePointContext) -> Result<(), i64> {
    let raw: trace_event_raw_sched_process_fork = unsafe { ctx.read_at(0) }?;

    let ppid = raw.parent_pid as u32;
    let cpid = raw.child_pid as u32;

    let mut flags_opt: Option<u32> = None;

    if let Some(flags) = unsafe { PROC_STATE.get(ppid) } {
        flags_opt = Some(*flags);
    } else if let Some(flags) = unsafe { WATCH_PIDS.get(ppid) } {
        flags_opt = Some(*flags);
        let _ = PROC_STATE.insert(ppid, *flags, 0);
    }

    let flags = match flags_opt {
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
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = PROC_STATE.remove(&pid);
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

        let pid = (*task).pid as u32;

        let parent = (*task).real_parent;
        let ppid = if parent.is_null() {
            0
        } else {
            (*parent).pid as u32
        };

        let mut rel: TaskRel = TaskRel { pid, ppid, tty_name: [0u8; TASK_REL_TTY_NAME_SIZE] };

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
