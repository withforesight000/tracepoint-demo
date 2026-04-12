use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    programs::TracePointContext,
};
use core::ptr;

use tracepoint_demo_common::ExecEvent;
use tracepoint_demo_ebpf::{split_pid_tgid, split_uid_gid};

use crate::{maps::EXEC_EVENTS, vmlinux::trace_event_raw_sys_enter, watch::resolve_watch_flags};

pub(crate) unsafe fn handle_exec_trace(ctx: TracePointContext) -> Result<u32, i64> {
    let raw: trace_event_raw_sys_enter = unsafe { ctx.read_at(0) }?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let (pid, tid) = split_pid_tgid(pid_tgid);

    let uid_gid = bpf_get_current_uid_gid();
    let (uid, gid) = split_uid_gid(uid_gid);

    if unsafe { resolve_watch_flags(pid) }.is_none() {
        return Ok(0);
    }

    if let Some(mut entry) = EXEC_EVENTS.reserve::<ExecEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe { ptr::write_bytes(event, 0, 1) };
        unsafe {
            (*event).ktime_ns = bpf_ktime_get_ns();
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).uid = uid;
            (*event).gid = gid;
            (*event).syscall_id = raw.id as u32;
            if let Ok(comm) = bpf_get_current_comm() {
                (*event).comm = comm;
            }
            read_filename(&raw, &mut (*event).filename);
            let argv_ptr = raw.args[1] as *const *const u8;
            read_arg(argv_ptr, 0, &mut (*event).argv[0]);
            read_arg(argv_ptr, 1, &mut (*event).argv[1]);
            read_arg(argv_ptr, 2, &mut (*event).argv[2]);
            read_arg(argv_ptr, 3, &mut (*event).argv[3]);
            read_arg(argv_ptr, 4, &mut (*event).argv[4]);
        }
        entry.submit(0);
    }

    Ok(0)
}

unsafe fn read_filename(raw: &trace_event_raw_sys_enter, filename: &mut [u8; 128]) {
    let filename_addr = raw.args[0] as *const u8;
    if filename_addr.is_null() {
        return;
    }

    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_addr, filename) };
}

unsafe fn read_arg(argv_ptr: *const *const u8, arg_index: usize, dst: &mut [u8; 64]) {
    if argv_ptr.is_null() {
        return;
    }

    let arg_slot = unsafe { argv_ptr.add(arg_index) };
    let Ok(arg_ptr) = (unsafe { bpf_probe_read_user::<*const u8>(arg_slot) }) else {
        return;
    };
    if arg_ptr.is_null() {
        return;
    }

    let _ = unsafe { bpf_probe_read_user_str_bytes(arg_ptr, dst) };
}
