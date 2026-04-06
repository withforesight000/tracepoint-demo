use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    programs::TracePointContext,
};

use tracepoint_demo_common::ExecEvent;
use tracepoint_demo_ebpf::{split_pid_tgid, split_uid_gid};

use crate::{
    maps::{ARGV0_BUF, EXEC_EVENTS, FNAME_BUF},
    vmlinux::trace_event_raw_sys_enter,
    watch::resolve_watch_flags,
};

pub(crate) unsafe fn handle_exec_trace(ctx: TracePointContext) -> Result<u32, i64> {
    let raw: trace_event_raw_sys_enter = unsafe { ctx.read_at(0) }?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let (pid, tid) = split_pid_tgid(pid_tgid);

    let uid_gid = bpf_get_current_uid_gid();
    let (uid, gid) = split_uid_gid(uid_gid);

    if unsafe { resolve_watch_flags(pid) }.is_none() {
        return Ok(0);
    }

    let mut comm = [0u8; 16];
    if let Ok(value) = bpf_get_current_comm() {
        comm = value;
    }

    let filename = unsafe { read_filename(&raw) };
    let argv0 = unsafe { read_argv0(&raw) };

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

unsafe fn read_filename(raw: &trace_event_raw_sys_enter) -> [u8; 128] {
    let mut filename = [0u8; 128];
    let filename_addr = raw.args[0] as *const u8;
    if filename_addr.is_null() {
        return filename;
    }

    if let Some(ptr) = FNAME_BUF.get_ptr_mut(0) {
        let buf = unsafe { &mut *ptr };
        let _ = unsafe { bpf_probe_read_user_str_bytes(filename_addr, buf) };
        filename = *buf;
    }

    filename
}

unsafe fn read_argv0(raw: &trace_event_raw_sys_enter) -> [u8; 128] {
    let mut argv0 = [0u8; 128];
    let argv_ptr = raw.args[1] as *const *const u8;
    if argv_ptr.is_null() {
        return argv0;
    }

    if let Ok(arg0_ptr) = unsafe { bpf_probe_read_user::<*const u8>(argv_ptr) } {
        if !arg0_ptr.is_null() {
            if let Some(ptr) = ARGV0_BUF.get_ptr_mut(0) {
                let buf = unsafe { &mut *ptr };
                let _ = unsafe { bpf_probe_read_user_str_bytes(arg0_ptr, buf) };
                argv0 = *buf;
            }
        }
    }

    argv0
}
