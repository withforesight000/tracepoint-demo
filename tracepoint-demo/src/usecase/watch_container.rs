use std::collections::HashSet;

use aya::Ebpf;
use tokio::sync::mpsc;

use crate::{
    gateway::{
        ebpf::{seed_proc_state_direct, seed_proc_state_from_task_iter},
        procfs::{read_cgroup_procs, read_cgroup_v2_path},
    },
    usecase::{
        ports::{SharedContainerRuntimePort, StatusReporter},
        support::runtime_update::RuntimeUpdate,
    },
};

pub struct ContainerRuntime {
    pub runtime: SharedContainerRuntimePort,
    pub name_or_id: String,
    pub watch_children: bool,
    pub all_processes: bool,
    pub flags: u32,
    pub current_pid: Option<u32>,
}

pub async fn seed_container_processes<TReporter: StatusReporter + ?Sized>(
    ebpf: &mut Ebpf,
    reporter: &mut TReporter,
    name_or_id: &str,
    main_pid: u32,
    container_flags: u32,
    container_watch_children: bool,
    all_container_processes: bool,
) -> anyhow::Result<()> {
    if all_container_processes {
        match read_cgroup_v2_path(main_pid).and_then(|path| read_cgroup_procs(&path)) {
            Ok(pids) => seed_proc_state_direct(ebpf, &pids, container_flags)?,
            Err(err) => {
                reporter.warn(format!(
                    "Failed to read cgroup.procs for container {} (pid {}): {}. Falling back to task iterator seed.",
                    name_or_id, main_pid, err
                ));
                let empty_tty_filters = HashSet::new();
                let _ = seed_proc_state_from_task_iter(
                    ebpf,
                    &[main_pid],
                    &empty_tty_filters,
                    container_flags,
                )?;
            }
        }
        return Ok(());
    }

    if container_watch_children {
        let empty_tty_filters = HashSet::new();
        let _ =
            seed_proc_state_from_task_iter(ebpf, &[main_pid], &empty_tty_filters, container_flags)?;
    } else {
        seed_proc_state_direct(ebpf, &[main_pid], container_flags)?;
    }

    Ok(())
}

pub async fn apply_container_runtime_update<TReporter: StatusReporter + ?Sized>(
    ebpf: &mut Ebpf,
    reporter: &mut TReporter,
    runtime: &mut ContainerRuntime,
    next_pid: Option<u32>,
) -> anyhow::Result<()> {
    if runtime.current_pid == next_pid {
        return Ok(());
    }

    if let Some(pid) = next_pid {
        seed_container_processes(
            ebpf,
            reporter,
            &runtime.name_or_id,
            pid,
            runtime.flags,
            runtime.watch_children,
            runtime.all_processes,
        )
        .await?;
    }

    runtime.current_pid = next_pid;
    Ok(())
}

pub fn spawn_monitors(
    container_runtimes: &[ContainerRuntime],
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    container_runtimes
        .iter()
        .enumerate()
        .map(|(index, runtime)| {
            runtime
                .runtime
                .spawn_monitor(runtime.name_or_id.clone(), update_tx.clone(), index)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::usecase::{
        ports::{BoxFuture, ContainerRuntimePort},
        support::runtime_update::RuntimeUpdate,
    };

    struct FakeContainerRuntimePort;

    impl ContainerRuntimePort for FakeContainerRuntimePort {
        fn query_main_pid<'a>(
            &'a self,
            _name_or_id: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<Option<u32>>> {
            Box::pin(async { Ok(None) })
        }

        fn spawn_monitor(
            &self,
            _name_or_id: String,
            _tx: mpsc::UnboundedSender<RuntimeUpdate>,
            _index: usize,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async {})
        }
    }

    #[tokio::test]
    async fn spawn_monitors_empty_returns_empty() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let handles = spawn_monitors(&[], &tx);
        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn spawn_monitors_non_empty_returns_handles() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let runtime = ContainerRuntime {
            runtime: Arc::new(FakeContainerRuntimePort),
            name_or_id: "dummy".to_string(),
            watch_children: true,
            all_processes: false,
            flags: 0,
            current_pid: None,
        };

        let handles = spawn_monitors(&[runtime], &tx);
        assert_eq!(handles.len(), 1);
    }
}
