use core::ptr;

use aya_ebpf::helpers::{bpf_probe_read_kernel, generated};

use tracepoint_demo_common::TASK_REL_TTY_NAME_SIZE;

use crate::vmlinux::{
    bpf_iter__task, bpf_iter_meta, seq_file, signal_struct, task_struct, tty_struct,
};

#[inline(always)]
unsafe fn read_kernel<T>(src: *const T) -> Option<T> {
    unsafe { bpf_probe_read_kernel(src).ok() }
}

#[inline(always)]
unsafe fn read_kernel_ptr<T>(src: *const *mut T) -> Option<*mut T> {
    let ptr = unsafe { read_kernel(src) }?;
    (!ptr.is_null()).then_some(ptr)
}

pub(crate) unsafe fn read_iter_meta(ctx: *const bpf_iter__task) -> Option<*mut bpf_iter_meta> {
    let meta = unsafe { (*ctx).__bindgen_anon_1.meta };
    (!meta.is_null()).then_some(meta)
}

pub(crate) unsafe fn read_iter_seq(meta: *const bpf_iter_meta) -> Option<*mut seq_file> {
    let seq = unsafe { (*meta).__bindgen_anon_1.seq };
    (!seq.is_null()).then_some(seq)
}

pub(crate) unsafe fn read_iter_task(ctx: *const bpf_iter__task) -> Option<*mut task_struct> {
    let task = unsafe { (*ctx).__bindgen_anon_2.task };
    (!task.is_null()).then_some(task)
}

pub(crate) unsafe fn read_task_tgid(task: *const task_struct) -> Option<u32> {
    let pid = unsafe { read_kernel(ptr::addr_of!((*task).tgid)) }?;
    Some(pid as u32)
}

pub(crate) unsafe fn read_task_parent(task: *const task_struct) -> Option<*mut task_struct> {
    unsafe { read_kernel_ptr(ptr::addr_of!((*task).parent)) }
}

pub(crate) unsafe fn read_task_real_parent(task: *const task_struct) -> Option<*mut task_struct> {
    unsafe { read_kernel_ptr(ptr::addr_of!((*task).real_parent)) }
}

pub(crate) unsafe fn read_task_signal(task: *const task_struct) -> Option<*mut signal_struct> {
    unsafe { read_kernel_ptr(ptr::addr_of!((*task).signal)) }
}

pub(crate) unsafe fn read_signal_tty(signal: *const signal_struct) -> Option<*mut tty_struct> {
    unsafe { read_kernel_ptr(ptr::addr_of!((*signal).tty)) }
}

pub(crate) unsafe fn read_tty_name(
    tty: *const tty_struct,
    dest: &mut [u8; TASK_REL_TTY_NAME_SIZE],
) {
    let name_ptr = unsafe { ptr::addr_of!((*tty).name).cast::<u8>() };
    let _ = unsafe {
        generated::bpf_probe_read_kernel_str(
            dest.as_mut_ptr().cast(),
            dest.len() as u32,
            name_ptr.cast(),
        )
    };
}
