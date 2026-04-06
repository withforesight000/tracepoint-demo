use std::collections::HashMap as StdHashMap;

pub fn add_watch_root(watch_roots: &mut StdHashMap<u32, u32>, pid: u32, flags: u32) {
    watch_roots
        .entry(pid)
        .and_modify(|existing| *existing |= flags)
        .or_insert(flags);
}

fn merge_runtime_roots<I>(roots: &mut StdHashMap<u32, u32>, runtimes: I)
where
    I: IntoIterator<Item = (Option<u32>, u32)>,
{
    for (pid, flags) in runtimes {
        if let Some(pid) = pid {
            add_watch_root(roots, pid, flags);
        }
    }
}

fn diff_watch_roots(
    current_roots: &StdHashMap<u32, u32>,
    desired_roots: &StdHashMap<u32, u32>,
) -> (Vec<u32>, Vec<(u32, u32)>) {
    let removals = current_roots
        .keys()
        .filter(|pid| !desired_roots.contains_key(pid))
        .copied()
        .collect();
    let inserts_or_updates = desired_roots
        .iter()
        .filter_map(|(&pid, &flags)| {
            (current_roots.get(&pid).copied() != Some(flags)).then_some((pid, flags))
        })
        .collect();

    (removals, inserts_or_updates)
}

#[derive(Debug, PartialEq, Eq)]
enum WatchRootChange {
    Remove(u32),
    Upsert(u32, u32),
}

fn apply_watch_root_changes<TApply>(
    current_roots: &mut StdHashMap<u32, u32>,
    desired_roots: &StdHashMap<u32, u32>,
    mut apply: TApply,
) -> anyhow::Result<()>
where
    TApply: FnMut(WatchRootChange) -> anyhow::Result<()>,
{
    let (removals, inserts_or_updates) = diff_watch_roots(current_roots, desired_roots);

    for pid in removals {
        apply(WatchRootChange::Remove(pid))?;
    }

    for (pid, flags) in inserts_or_updates {
        apply(WatchRootChange::Upsert(pid, flags))?;
    }

    *current_roots = desired_roots.clone();
    Ok(())
}

pub fn collect_watch_roots(
    static_roots: &StdHashMap<u32, u32>,
    container_runtimes: &[crate::usecase::policy::watch_container::ContainerRuntime],
    systemd_runtimes: &[crate::usecase::policy::watch_systemd_unit::SystemdRuntime],
) -> StdHashMap<u32, u32> {
    let mut roots = static_roots.clone();

    merge_runtime_roots(
        &mut roots,
        container_runtimes
            .iter()
            .map(|runtime| (runtime.current_pid, runtime.flags)),
    );
    merge_runtime_roots(
        &mut roots,
        systemd_runtimes
            .iter()
            .map(|runtime| (runtime.current_pid, runtime.flags)),
    );

    roots
}

pub fn sync_watch_pids(
    watch_pids: &mut aya::maps::hash_map::HashMap<aya::maps::MapData, u32, u32>,
    current_roots: &mut StdHashMap<u32, u32>,
    desired_roots: &StdHashMap<u32, u32>,
) -> anyhow::Result<()> {
    apply_watch_root_changes(current_roots, desired_roots, |change| match change {
        WatchRootChange::Remove(pid) => watch_pids.remove(&pid).map_err(Into::into),
        WatchRootChange::Upsert(pid, flags) => watch_pids.insert(pid, flags, 0).map_err(Into::into),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        test_support::{NoopContainerRuntimePort, NoopSystemdRuntimePort},
        usecase::policy::{watch_container::ContainerRuntime, watch_systemd_unit::SystemdRuntime},
    };

    #[test]
    fn add_watch_root_sets_and_merges_flags() {
        let mut roots = StdHashMap::new();
        add_watch_root(&mut roots, 1, 0x1);
        assert_eq!(roots.get(&1), Some(&0x1));
        add_watch_root(&mut roots, 1, 0x2);
        assert_eq!(roots.get(&1), Some(&0x3));
    }

    #[test]
    fn collect_watch_roots_includes_static_only_when_others_empty() {
        let mut static_roots = StdHashMap::new();
        static_roots.insert(10, 0x1);

        let result = collect_watch_roots(&static_roots, &[], &[]);
        assert_eq!(result, static_roots);
    }

    #[test]
    fn merge_runtime_roots_merges_duplicate_pids_and_ignores_missing_pids() {
        let mut roots = StdHashMap::from([(10, 0x1)]);

        merge_runtime_roots(&mut roots, [(Some(10), 0x2), (Some(20), 0x4), (None, 0x8)]);

        assert_eq!(roots, StdHashMap::from([(10, 0x3), (20, 0x4)]));
    }

    #[test]
    fn collect_watch_roots_merges_static_and_container_roots() {
        let mut static_roots = StdHashMap::new();
        static_roots.insert(10, 0x1);

        let container_runtimes = vec![
            ContainerRuntime {
                cgroup_port: Arc::new(crate::gateway::procfs::ProcfsCgroupPort),
                runtime: Arc::new(NoopContainerRuntimePort),
                name_or_id: "web".to_string(),
                watch_children: true,
                all_processes: false,
                flags: 0x2,
                current_pid: Some(10),
            },
            ContainerRuntime {
                cgroup_port: Arc::new(crate::gateway::procfs::ProcfsCgroupPort),
                runtime: Arc::new(NoopContainerRuntimePort),
                name_or_id: "worker".to_string(),
                watch_children: false,
                all_processes: false,
                flags: 0x4,
                current_pid: Some(30),
            },
        ];

        let systemd_runtimes = vec![SystemdRuntime {
            runtime: Arc::new(NoopSystemdRuntimePort),
            unit_name: "sshd.service".to_string(),
            watch_children: false,
            all_processes: false,
            seeded_pids: Vec::new(),
            flags: 0x8,
            current_pid: None,
            current_running: false,
        }];

        let result = collect_watch_roots(&static_roots, &container_runtimes, &systemd_runtimes);

        assert_eq!(result, StdHashMap::from([(10, 0x3), (30, 0x4)]));
    }

    #[test]
    fn diff_watch_roots_returns_expected_removals_and_updates() {
        let current = StdHashMap::from([(10, 0x1), (20, 0x2), (30, 0x4)]);
        let desired = StdHashMap::from([(20, 0x2), (30, 0x8), (40, 0x10)]);

        let (mut removals, mut updates) = diff_watch_roots(&current, &desired);
        removals.sort_unstable();
        updates.sort_unstable_by_key(|(pid, _)| *pid);

        assert_eq!(removals, vec![10]);
        assert_eq!(updates, vec![(30, 0x8), (40, 0x10)]);
    }

    #[test]
    fn diff_watch_roots_is_empty_when_roots_match() {
        let current = StdHashMap::from([(10, 0x1), (20, 0x2)]);

        let (removals, updates) = diff_watch_roots(&current, &current);

        assert!(removals.is_empty());
        assert!(updates.is_empty());
    }

    #[test]
    fn apply_watch_root_changes_records_removals_and_updates() {
        let mut current = StdHashMap::from([(10, 0x1), (20, 0x2), (30, 0x4)]);
        let desired = StdHashMap::from([(20, 0x2), (30, 0x8), (40, 0x10)]);
        let mut changes = Vec::new();

        apply_watch_root_changes(&mut current, &desired, |change| {
            changes.push(change);
            Ok(())
        })
        .unwrap();

        changes.sort_unstable_by_key(|change| match change {
            WatchRootChange::Remove(pid) => (*pid, 0),
            WatchRootChange::Upsert(pid, _) => (*pid, 1),
        });

        assert_eq!(
            changes,
            vec![
                WatchRootChange::Remove(10),
                WatchRootChange::Upsert(30, 0x8),
                WatchRootChange::Upsert(40, 0x10),
            ]
        );
        assert_eq!(current, desired);
    }

    #[test]
    fn apply_watch_root_changes_propagates_callback_errors() {
        let mut current = StdHashMap::from([(10, 0x1)]);
        let desired = StdHashMap::new();

        let err = apply_watch_root_changes(&mut current, &desired, |_change| {
            Err(anyhow::anyhow!("remove failed"))
        })
        .unwrap_err();

        assert_eq!(err.to_string(), "remove failed");
        assert_eq!(current, StdHashMap::from([(10, 0x1)]));
    }

    #[test]
    fn apply_watch_root_changes_skips_callback_when_roots_match() {
        let mut current = StdHashMap::from([(10, 0x1)]);
        let desired = StdHashMap::from([(10, 0x1)]);
        let mut called = false;

        apply_watch_root_changes(&mut current, &desired, |_change| {
            called = true;
            Ok(())
        })
        .unwrap();

        assert!(!called);
        assert_eq!(current, desired);
    }
}
