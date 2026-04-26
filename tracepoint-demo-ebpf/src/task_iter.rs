use core::{mem::MaybeUninit, ptr};

use aya_ebpf::helpers::generated::bpf_seq_write;

use tracepoint_demo_common::TaskRel;

use crate::{
    kernel_read::{
        read_iter_meta, read_iter_seq, read_iter_task, read_signal_tty, read_task_real_parent,
        read_task_signal, read_task_tgid, read_tty_name,
    },
    vmlinux::bpf_iter__task,
};

pub(crate) unsafe fn run_task_iter(ctx: *mut bpf_iter__task) -> i32 {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        let meta = match read_iter_meta(ctx) {
            Some(meta) => meta,
            None => return 0,
        };
        let seq = match read_iter_seq(meta) {
            Some(seq) => seq,
            None => return 0,
        };
        let task = match read_iter_task(ctx) {
            Some(task) => task,
            None => return 0,
        };

        let pid = match read_task_tgid(task) {
            Some(pid) => pid,
            None => return 0,
        };
        let ppid = match read_task_real_parent(task) {
            Some(parent) => read_task_tgid(parent).unwrap_or(0),
            None => 0,
        };

        let mut rel = MaybeUninit::<TaskRel>::uninit();
        let rel_ptr = rel.as_mut_ptr();

        ptr::addr_of_mut!((*rel_ptr).pid).write(pid);
        ptr::addr_of_mut!((*rel_ptr).ppid).write(ppid);

        let tty_name_words = ptr::addr_of_mut!((*rel_ptr).tty_name).cast::<u64>();
        ptr::write_volatile(tty_name_words.add(0), 0);
        ptr::write_volatile(tty_name_words.add(1), 0);
        ptr::write_volatile(tty_name_words.add(2), 0);
        ptr::write_volatile(tty_name_words.add(3), 0);
        ptr::write_volatile(tty_name_words.add(4), 0);
        ptr::write_volatile(tty_name_words.add(5), 0);
        ptr::write_volatile(tty_name_words.add(6), 0);
        ptr::write_volatile(tty_name_words.add(7), 0);

        if let Some(signal) = read_task_signal(task)
            && let Some(tty) = read_signal_tty(signal)
        {
            read_tty_name(tty, &mut (*rel_ptr).tty_name);
        }

        let _ = bpf_seq_write(
            seq.cast(),
            rel_ptr.cast(),
            core::mem::size_of::<TaskRel>() as u32,
        );
        0
    }
}
