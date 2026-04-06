use core::{ffi::c_void, mem::size_of};

use aya_ebpf::{
    bindings::seq_file,
    helpers::{bpf_probe_read_kernel_str_bytes, generated::bpf_seq_write},
};

use tracepoint_demo_common::{TASK_REL_TTY_NAME_SIZE, TaskRel};

use crate::vmlinux::bpf_iter__task;

pub(crate) unsafe fn run_task_iter(ctx: *mut bpf_iter__task) -> i32 {
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

        let pid = (*task).tgid as u32;
        let parent = (*task).real_parent;
        let ppid = if parent.is_null() {
            0
        } else {
            (*parent).tgid as u32
        };

        let mut rel = TaskRel {
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
            size_of::<TaskRel>() as u32,
        );
        0
    }
}
