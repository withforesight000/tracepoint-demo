use aya_ebpf::{
    macros::map,
    maps::{hash_map::HashMap, per_cpu_array::PerCpuArray, ring_buf::RingBuf},
};

#[map]
pub(crate) static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
pub(crate) static WATCH_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static PROC_STATE: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

#[map]
pub(crate) static FNAME_BUF: PerCpuArray<[u8; 128]> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub(crate) static ARGV0_BUF: PerCpuArray<[u8; 128]> = PerCpuArray::with_max_entries(1, 0);
