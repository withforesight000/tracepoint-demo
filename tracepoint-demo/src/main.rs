use std::{
    collections::{HashMap as StdHashMap, HashSet, VecDeque},
    convert::TryFrom,
    io::Read,
    mem,
};

use aya::{
    Btf, Ebpf,
    maps::{RingBuf, hash_map::HashMap as UserHashMap},
    programs::{Iter, TracePoint},
};
use clap::Parser;
use log::debug;
use tokio::{io::unix::AsyncFd, select, signal};

#[derive(Parser)]
#[command(author, version, about = "Traces execve syscalls for a set of processes", long_about = None)]
#[command(arg_required_else_help = true)]
struct CliArgs {
    /// Repeated `--pid` arguments keep the option-style interface used in earlier versions.
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pid: Vec<u32>,

    /// Positional PIDs can be used instead of `--pid`.
    #[arg(value_name = "PID", required_unless_present = "pid")]
    positional_pids: Vec<u32>,

    /// Do not follow child processes when tracing (default traces children as well).
    #[arg(long = "no-watch-children")]
    no_watch_children: bool,
}

use tracepoint_demo_common::{
    EXEC_EVENTS_MAP, ExecEvent, PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF, TaskRel,
    WATCH_PIDS_MAP,
};

fn cstr_from_u8(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn seed_proc_state_from_task_iter(ebpf: &mut Ebpf, roots: &[(u32, u32)]) -> anyhow::Result<()> {
    let mut watch_pids: UserHashMap<_, u32, u32> =
        UserHashMap::try_from(ebpf.map_mut("WATCH_PIDS").unwrap())?;
    for (pid, flags) in roots {
        watch_pids.insert(*pid, *flags, 0)?;
    }

    let btf = Btf::from_sys_fs()?;
    let program: &mut Iter = ebpf.program_mut("iter_tasks").unwrap().try_into()?;
    program.load("task", &btf)?;
    let link_id = program.attach()?;
    let link = program.take_link(link_id)?;
    let mut file = link.into_file()?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    let mut children: StdHashMap<u32, Vec<u32>> = StdHashMap::new();
    for chunk in buf.chunks_exact(mem::size_of::<TaskRel>()) {
        let pid = u32::from_ne_bytes(chunk[0..4].try_into().unwrap());
        let ppid = u32::from_ne_bytes(chunk[4..8].try_into().unwrap());
        children.entry(ppid).or_default().push(pid);
    }

    let mut proc_state: UserHashMap<_, u32, u32> =
        UserHashMap::try_from(ebpf.map_mut("PROC_STATE").unwrap())?;

    for (root_pid, flags) in roots {
        proc_state.insert(root_pid, flags, 0)?;

        if (flags & PROC_FLAG_WATCH_CHILDREN) == 0 {
            continue;
        }

        let mut q = VecDeque::new();
        let mut seen = HashSet::new();

        q.push_back(*root_pid);
        seen.insert(*root_pid);

        while let Some(ppid) = q.pop_front() {
            if let Some(ch) = children.get(&ppid) {
                for &cpid in ch {
                    if seen.insert(cpid) {
                        proc_state.insert(&cpid, flags, 0)?;
                        q.push_back(cpid);
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = CliArgs::parse();
    let mut pids = args.pid;
    pids.extend(args.positional_pids);
    let watch_children = !args.no_watch_children;

    if pids.is_empty() {
        // This should not happen because clap already enforces at least one PID,
        // but we keep the guard in case the parser changes.
        eprintln!("Please provide at least one PID (or use `--pid`).");
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
        let fork: &mut TracePoint = ebpf.program_mut("on_fork").unwrap().try_into()?;
        fork.load()?;
        fork.attach("sched", "sched_process_fork")?;
    }

    {
        let exit: &mut TracePoint = ebpf.program_mut("on_exit").unwrap().try_into()?;
        exit.load()?;
        exit.attach("sched", "sched_process_exit")?;
    }

    let watch_flags = PROC_FLAG_WATCH_SELF
        | if watch_children {
            PROC_FLAG_WATCH_CHILDREN
        } else {
            0
        };

    let mut roots = Vec::<(u32, u32)>::new();
    for &pid in &pids {
        roots.push((pid, watch_flags));
    }

    seed_proc_state_from_task_iter(&mut ebpf, &roots)?;

    {
        let map = ebpf
            .map_mut(WATCH_PIDS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?;
        let mut watch_pids: UserHashMap<_, u32, u32> = UserHashMap::try_from(map)?;
        for pid in &pids {
            watch_pids.insert(*pid, watch_flags, 0)?;
        }
    }

    let ring_map = ebpf
        .take_map(EXEC_EVENTS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let ring = RingBuf::try_from(ring_map)?;
    let mut async_ring = AsyncFd::new(ring)?;

    let child_status = if watch_children {
        "children included"
    } else {
        "children ignored"
    };

    println!(
        "Watching execve syscalls for PIDs: {:?} ({}) (Ctrl-C to exit)",
        pids, child_status
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
