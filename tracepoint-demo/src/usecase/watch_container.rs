use std::collections::HashSet;

use aya::Ebpf;
use bollard::{Docker, models::EventMessage, query_parameters::EventsOptions};
use futures_util::{StreamExt, stream::BoxStream};
use tokio::{
    select,
    sync::mpsc,
    time::{Duration, sleep},
};

use crate::{
    gateway::{
        docker::query_container_main_pid,
        ebpf::{seed_proc_state_direct, seed_proc_state_from_task_iter},
        procfs::{read_cgroup_procs, read_cgroup_v2_path},
    },
    usecase::support::{
        container_monitor::{ContainerMonitorBackend, monitor_container_runtime_with_backend},
        runtime_update::RuntimeUpdate,
    },
};

#[derive(Debug)]
pub struct ContainerRuntime {
    pub docker: Docker,
    pub name_or_id: String,
    pub watch_children: bool,
    pub all_processes: bool,
    pub flags: u32,
    pub current_pid: Option<u32>,
}

struct DockerContainerMonitorBackend {
    docker: Docker,
    events: BoxStream<'static, Result<EventMessage, bollard::errors::Error>>,
    poll_interval: Duration,
}

impl DockerContainerMonitorBackend {
    fn new(docker: Docker, name_or_id: &str, poll_interval: Duration) -> Self {
        let mut filters = std::collections::HashMap::new();
        filters.insert("container".to_string(), vec![name_or_id.to_string()]);
        filters.insert("type".to_string(), vec!["container".to_string()]);

        let events = docker
            .events(Some(EventsOptions {
                since: None,
                until: None,
                filters: Some(filters),
            }))
            .boxed();

        Self {
            docker,
            events,
            poll_interval,
        }
    }
}

impl ContainerMonitorBackend for DockerContainerMonitorBackend {
    async fn query_main_pid(&mut self, name_or_id: &str) -> anyhow::Result<Option<u32>> {
        query_container_main_pid(&self.docker, name_or_id).await
    }

    async fn wait_for_next_check(&mut self, name_or_id: &str) -> anyhow::Result<()> {
        select! {
            maybe_event = self.events.next() => {
                match maybe_event {
                    Some(Ok(_)) => Ok(()),
                    Some(Err(err)) => Err(err.into()),
                    None => Err(anyhow::anyhow!(
                        "Docker event stream ended while monitoring container {name_or_id}."
                    )),
                }
            }
            _ = sleep(self.poll_interval) => Ok(()),
        }
    }
}

pub async fn seed_container_processes(
    ebpf: &mut Ebpf,
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
                eprintln!(
                    "Failed to read cgroup.procs for container {} (pid {}): {}. Falling back to task iterator seed.",
                    name_or_id, main_pid, err
                );
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

pub async fn apply_container_runtime_update(
    ebpf: &mut Ebpf,
    runtime: &mut ContainerRuntime,
    next_pid: Option<u32>,
) -> anyhow::Result<()> {
    if runtime.current_pid == next_pid {
        return Ok(());
    }

    if let Some(pid) = next_pid {
        seed_container_processes(
            ebpf,
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

pub async fn monitor_container_runtime(
    docker: Docker,
    name_or_id: String,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    let mut backend =
        DockerContainerMonitorBackend::new(docker, &name_or_id, Duration::from_secs(1));
    monitor_container_runtime_with_backend(&mut backend, &name_or_id, &tx, index).await
}

pub fn spawn_monitors(
    container_runtimes: &[ContainerRuntime],
    update_tx: &mpsc::UnboundedSender<RuntimeUpdate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut monitor_handles = Vec::new();
    for (index, runtime) in container_runtimes.iter().enumerate() {
        let tx = update_tx.clone();
        let docker = runtime.docker.clone();
        let name_or_id = runtime.name_or_id.clone();
        monitor_handles.push(tokio::spawn(async move {
            if let Err(err) =
                monitor_container_runtime(docker, name_or_id.clone(), tx.clone(), index).await
            {
                let _ = tx.send(RuntimeUpdate::MonitorError {
                    label: format!("container {name_or_id}"),
                    error: err.to_string(),
                });
            }
        }));
    }
    monitor_handles
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::Docker;

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
            docker: Docker::connect_with_local_defaults().unwrap(),
            name_or_id: "dummy".to_string(),
            watch_children: true,
            all_processes: false,
            flags: 0,
            current_pid: None,
        };
        let handles = spawn_monitors(&[runtime], &tx);
        assert_eq!(handles.len(), 1);
        // drop handles to avoid waiting for hanging background tasks in tests
        for h in handles {
            h.abort();
        }
    }
}
