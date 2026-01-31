#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{hash_map::HashMap, per_cpu_array::PerCpuArray, ring_buf::RingBuf},
    programs::TracePointContext,
};

use tracepoint_demo_common::{ExecEvent, PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

// aya-tool で生成した BTF 由来の型定義
#[allow(
    clippy::all,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    improper_ctypes_definitions,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use vmlinux::trace_event_raw_sys_enter;

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
