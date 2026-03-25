use std::{
    collections::{HashMap as StdHashMap, HashSet, VecDeque},
    convert::TryFrom,
    io::Read,
    mem, ptr,
};

use aya::{
    Btf, Ebpf,
    maps::{MapData, RingBuf, hash_map::HashMap as UserHashMap},
    programs::{Iter, ProgramError, TracePoint},
};
use tokio::io::unix::AsyncFd;

use tracepoint_demo_common::{
    EXEC_EVENTS_MAP, ExecEvent, PROC_FLAG_WATCH_CHILDREN, PROC_STATE_MAP, TaskRel, WATCH_PIDS_MAP,
};

use crate::usecase::orchestration::tty::normalize_tty_name;

pub fn cstr_from_u8(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

pub fn drain_exec_events<TEvent, TInvalid>(
    ring: &mut RingBuf<MapData>,
    mut on_event: TEvent,
    mut on_invalid_size: TInvalid,
) where
    TEvent: FnMut(ExecEvent),
    TInvalid: FnMut(usize, usize),
{
    let expected_size = mem::size_of::<ExecEvent>();

    while let Some(item) = ring.next() {
        let bytes = &item;
        if bytes.len() != expected_size {
            on_invalid_size(bytes.len(), expected_size);
            continue;
        }

        let event: ExecEvent = unsafe { *(bytes.as_ptr() as *const ExecEvent) };
        on_event(event);
    }
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

pub fn attach_tracepoint_programs(ebpf: &mut Ebpf) -> anyhow::Result<()> {
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

    ensure_task_iter_program_loaded(ebpf)?;
    Ok(())
}

pub fn load_tracepoint_demo_ebpf() -> anyhow::Result<Ebpf> {
    bump_memlock_rlimit();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tracepoint-demo"
    )))?;
    attach_tracepoint_programs(&mut ebpf)?;
    Ok(ebpf)
}

pub fn ensure_task_iter_program_loaded(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let btf = Btf::from_sys_fs()?;
    let program: &mut Iter = ebpf.program_mut("iter_tasks").unwrap().try_into()?;
    if let Err(err) = program.load("task", &btf)
        && !matches!(err, ProgramError::AlreadyLoaded)
    {
        return Err(err.into());
    }
    Ok(())
}

pub fn seed_proc_state_from_task_iter(
    ebpf: &mut Ebpf,
    pid_roots: &[u32],
    tty_filters: &HashSet<String>,
    watch_flags: u32,
) -> anyhow::Result<Vec<u32>> {
    let mut buf = Vec::new();
    {
        let program: &mut Iter = ebpf.program_mut("iter_tasks").unwrap().try_into()?;
        let link_id = program.attach()?;
        let link = program.take_link(link_id)?;
        let mut file = link.into_file()?;

        file.read_to_end(&mut buf)?;
    }

    let pid_roots_set: HashSet<u32> = pid_roots.iter().copied().collect();
    let mut root_flags = StdHashMap::new();
    let mut children: StdHashMap<u32, Vec<u32>> = StdHashMap::new();
    let mut pid_tty: StdHashMap<u32, String> = StdHashMap::new();
    for chunk in buf.chunks_exact(mem::size_of::<TaskRel>()) {
        let rel: TaskRel = unsafe { ptr::read_unaligned(chunk.as_ptr() as *const TaskRel) };
        if pid_roots_set.contains(&rel.pid) {
            root_flags.entry(rel.pid).or_insert(watch_flags);
        }
        children.entry(rel.ppid).or_default().push(rel.pid);
        let tty_name = cstr_from_u8(&rel.tty_name);
        if !tty_name.is_empty() {
            let normalized = normalize_tty_name(&tty_name);
            if !normalized.is_empty() {
                pid_tty.insert(rel.pid, normalized);
            }
        }
    }

    let mut proc_state: UserHashMap<_, u32, u32> = UserHashMap::try_from(
        ebpf.map_mut(PROC_STATE_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?,
    )?;

    if !tty_filters.is_empty() {
        for (pid, tty_name) in pid_tty {
            if tty_filters.contains(&tty_name) {
                root_flags.entry(pid).or_insert(watch_flags);
            }
        }
    }

    if root_flags.is_empty() {
        return Ok(Vec::new());
    }

    let mut seeded_roots = Vec::new();
    for (&root_pid, &flags) in &root_flags {
        proc_state.insert(root_pid, flags, 0)?;
        seeded_roots.push(root_pid);

        if (flags & PROC_FLAG_WATCH_CHILDREN) == 0 {
            continue;
        }

        let mut q = VecDeque::new();
        let mut seen = HashSet::new();
        q.push_back(root_pid);
        seen.insert(root_pid);

        while let Some(ppid) = q.pop_front() {
            if let Some(children) = children.get(&ppid) {
                for &cpid in children {
                    if seen.insert(cpid) {
                        proc_state.insert(cpid, flags, 0)?;
                        q.push_back(cpid);
                    }
                }
            }
        }
    }

    seeded_roots.sort_unstable();
    Ok(seeded_roots)
}

pub fn seed_proc_state_direct(ebpf: &mut Ebpf, pids: &[u32], flags: u32) -> anyhow::Result<()> {
    if pids.is_empty() {
        return Ok(());
    }

    let mut proc_state: UserHashMap<_, u32, u32> = UserHashMap::try_from(
        ebpf.map_mut(PROC_STATE_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?,
    )?;

    for pid in pids {
        if let Err(err) = proc_state.insert(*pid, flags, 0) {
            return Err(anyhow::anyhow!(
                "failed to seed PROC_STATE for pid {}: {err}",
                pid
            ));
        }
    }

    Ok(())
}

type WatchPidsAndRing = (UserHashMap<MapData, u32, u32>, AsyncFd<RingBuf<MapData>>);

pub fn build_watch_pids_and_ring(
    ebpf: &mut Ebpf,
    watched_roots: &StdHashMap<u32, u32>,
) -> anyhow::Result<WatchPidsAndRing> {
    let map = ebpf
        .take_map(WATCH_PIDS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let mut watch_pids: UserHashMap<_, u32, u32> = UserHashMap::try_from(map)?;
    for (&pid, &flags) in watched_roots {
        watch_pids.insert(pid, flags, 0)?;
    }

    let ring_map = ebpf
        .take_map(EXEC_EVENTS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let ring = RingBuf::try_from(ring_map)?;
    let async_ring = AsyncFd::new(ring)?;

    Ok((watch_pids, async_ring))
}

pub fn build_watch_pids(
    ebpf: &mut Ebpf,
    watched_roots: &StdHashMap<u32, u32>,
) -> anyhow::Result<UserHashMap<MapData, u32, u32>> {
    let map = ebpf
        .take_map(WATCH_PIDS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let mut watch_pids: UserHashMap<_, u32, u32> = UserHashMap::try_from(map)?;
    for (&pid, &flags) in watched_roots {
        watch_pids.insert(pid, flags, 0)?;
    }

    Ok(watch_pids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_from_u8_ends_at_nul() {
        let bytes = b"hello\0world";
        assert_eq!(cstr_from_u8(bytes), "hello");
    }

    #[test]
    fn cstr_from_u8_returns_full_string_no_nul() {
        let bytes = b"foobar";
        assert_eq!(cstr_from_u8(bytes), "foobar");
    }
}
