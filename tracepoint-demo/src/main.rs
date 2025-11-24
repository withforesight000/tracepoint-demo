use std::{convert::TryFrom, env, mem};

use aya::{
    maps::{RingBuf, hash_map::HashMap as UserHashMap},
    programs::TracePoint,
};
use log::debug;
use tokio::{io::unix::AsyncFd, select, signal};

use tracepoint_demo_common::{EXEC_EVENTS_MAP, ExecEvent, PROC_FLAG_WATCH_SELF, WATCH_PIDS_MAP};

fn cstr_from_u8(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let pids: Vec<u32> = env::args()
        .skip(1)
        .map(|s| s.parse::<u32>())
        .collect::<Result<_, _>>()?;

    if pids.is_empty() {
        eprintln!("Usage: tracepoint-demo <PID> [PID ...]");
        eprintln!("  ex) tracepoint-demo 1234 5678");
        return Ok(());
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tracepoint-demo"
    )))?;

    {
        let program: &mut TracePoint = ebpf
            .program_mut("tracepoint_demo")
            .ok_or_else(|| anyhow::anyhow!("program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;
    }

    {
        let map = ebpf
            .map_mut(WATCH_PIDS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?;
        let mut watch_pids: UserHashMap<_, u32, u32> = UserHashMap::try_from(map)?;
        for pid in &pids {
            watch_pids.insert(*pid, PROC_FLAG_WATCH_SELF, 0)?;
        }
    }

    let ring_map = ebpf
        .take_map(EXEC_EVENTS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let ring = RingBuf::try_from(ring_map)?;
    let mut async_ring = AsyncFd::new(ring)?;

    println!(
        "Watching execve syscalls for PIDs: {:?} (Ctrl-C to exit)",
        pids
    );

    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();

                while let Some(item) = ring.next() {
                    let bytes = &item;
                    if bytes.len() != mem::size_of::<ExecEvent>() {
                        eprintln!("unexpected ExecEvent size: {} (expected {})", bytes.len(), mem::size_of::<ExecEvent>());
                        continue;
                    }

                    let event: ExecEvent = unsafe { *(bytes.as_ptr() as *const ExecEvent) };

                    println!(
                        "[{:.6}] pid={} tid={} uid={} gid={} syscall_id={} \
                         comm=\"{}\" filename=\"{}\" argv0=\"{}\"",
                        event.ktime_ns as f64 / 1e9,
                        event.pid,
                        event.tid,
                        event.uid,
                        event.gid,
                        event.syscall_id,
                        cstr_from_u8(&event.comm),
                        cstr_from_u8(&event.filename),
                        cstr_from_u8(&event.argv0),
                    );
                }

                guard.clear_ready();
            }

            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
