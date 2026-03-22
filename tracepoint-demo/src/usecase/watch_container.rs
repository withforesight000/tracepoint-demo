use std::collections::HashSet;

use aya::Ebpf;
use bollard::{Docker, query_parameters::EventsOptions};
use futures_util::StreamExt;
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
    usecase::runtime_update::RuntimeUpdate,
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
    let mut filters = std::collections::HashMap::new();
    filters.insert("container".to_string(), vec![name_or_id.clone()]);
    filters.insert("type".to_string(), vec!["container".to_string()]);

    let mut events = docker.events(Some(EventsOptions {
        since: None,
        until: None,
        filters: Some(filters),
    }));

    let mut current_pid = query_container_main_pid(&docker, &name_or_id).await?;
    let _ = tx.send(RuntimeUpdate::ContainerPid {
        index,
        pid: current_pid,
    });

    loop {
        select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(err.into()),
                    None => return Err(anyhow::anyhow!(
                        "Docker event stream ended while monitoring container {name_or_id}."
                    )),
                }

                let next_pid = query_container_main_pid(&docker, &name_or_id).await?;
                if next_pid != current_pid {
                    current_pid = next_pid;
                    let _ = tx.send(RuntimeUpdate::ContainerPid { index, pid: next_pid });
                }
            }

            _ = sleep(Duration::from_secs(1)) => {
                let next_pid = query_container_main_pid(&docker, &name_or_id).await?;
                if next_pid != current_pid {
                    current_pid = next_pid;
                    let _ = tx.send(RuntimeUpdate::ContainerPid { index, pid: next_pid });
                }
            }
        }
    }
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
