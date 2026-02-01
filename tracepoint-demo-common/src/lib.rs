#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaskRel {
    pub pid: u32,
    pub ppid: u32,
    pub tty_name: [u8; TASK_REL_TTY_NAME_SIZE],
}

pub const TASK_REL_TTY_NAME_SIZE: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub syscall_id: u32,
    pub comm: [u8; EXEC_EVENT_COMM_SIZE],
    pub filename: [u8; EXEC_EVENT_FILENAME_SIZE],
    pub argv0: [u8; EXEC_EVENT_ARGV0_SIZE],
}

pub const EXEC_EVENT_COMM_SIZE: usize = 16;
pub const EXEC_EVENT_FILENAME_SIZE: usize = 128;
pub const EXEC_EVENT_ARGV0_SIZE: usize = 128;

pub const EXEC_EVENTS_MAP: &str = "EXEC_EVENTS";
pub const WATCH_PIDS_MAP: &str = "WATCH_PIDS";
pub const PROC_STATE_MAP: &str = "PROC_STATE";

pub const PROC_FLAG_WATCH_SELF: u32 = 1 << 0;
pub const PROC_FLAG_WATCH_CHILDREN: u32 = 1 << 1;
