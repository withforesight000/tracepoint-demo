use std::collections::HashMap as StdHashMap;

pub fn add_watch_root(watch_roots: &mut StdHashMap<u32, u32>, pid: u32, flags: u32) {
    watch_roots
        .entry(pid)
        .and_modify(|existing| *existing |= flags)
        .or_insert(flags);
}

pub fn collect_watch_roots(
    static_roots: &StdHashMap<u32, u32>,
    container_runtimes: &[crate::usecase::watch_container::ContainerRuntime],
    systemd_runtimes: &[crate::usecase::watch_systemd_unit::SystemdRuntime],
) -> StdHashMap<u32, u32> {
    let mut roots = static_roots.clone();

    for runtime in container_runtimes {
        if let Some(pid) = runtime.current_pid {
            add_watch_root(&mut roots, pid, runtime.flags);
        }
    }

    for runtime in systemd_runtimes {
        if let Some(pid) = runtime.current_pid {
            add_watch_root(&mut roots, pid, runtime.flags);
        }
    }

    roots
}

pub fn sync_watch_pids(
    watch_pids: &mut aya::maps::hash_map::HashMap<aya::maps::MapData, u32, u32>,
    current_roots: &mut StdHashMap<u32, u32>,
    desired_roots: &StdHashMap<u32, u32>,
) -> anyhow::Result<()> {
    let removals: Vec<u32> = current_roots
        .keys()
        .filter(|pid| !desired_roots.contains_key(pid))
        .copied()
        .collect();
    for pid in removals {
        watch_pids.remove(&pid)?;
    }

    for (&pid, &flags) in desired_roots {
        if current_roots.get(&pid).copied() != Some(flags) {
            watch_pids.insert(pid, flags, 0)?;
        }
    }

    *current_roots = desired_roots.clone();
    Ok(())
}
