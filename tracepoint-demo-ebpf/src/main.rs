#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};

use tracepoint_demo_ebpf::exiting_process_pid;

mod exec_trace;
mod kernel_read;
mod maps;
mod task_iter;
mod watch;

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

use crate::vmlinux::{bpf_iter__task, trace_event_raw_sched_process_fork};

#[tracepoint]
pub fn tracepoint_demo(ctx: TracePointContext) -> u32 {
    match unsafe { exec_trace::handle_exec_trace(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
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
    unsafe { watch::inherit_child_watch(raw.parent_pid as u32, raw.child_pid as u32) };
    Ok(())
}

#[tracepoint]
pub fn on_exit(_ctx: TracePointContext) -> u32 {
    // Keep process-granularity watch state alive across helper thread exits.
    if let Some(pid) = exiting_process_pid(bpf_get_current_pid_tgid()) {
        watch::remove_watch_state(pid);
    }
    0
}

/// # Safety
///
/// This function is called by the BPF subsystem.
#[unsafe(link_section = "iter/task")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iter_tasks(ctx: *mut bpf_iter__task) -> i32 {
    unsafe { task_iter::run_task_iter(ctx) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
