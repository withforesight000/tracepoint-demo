use std::{collections::HashMap, sync::Arc, time::Duration};

use bollard::{
    Docker,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerState, EventMessage},
    query_parameters::EventsOptions,
};
use futures_util::{StreamExt, stream::BoxStream};
use tokio::{select, sync::mpsc, time::sleep};

use crate::usecase::port::{
    BoxFuture, ContainerRuntimePort, RuntimeUpdate, SharedContainerRuntimePort,
};

struct DockerContainerRuntimeGateway {
    docker: Docker,
}

fn main_pid_from_container_state(
    state: &ContainerState,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    if !state.running.unwrap_or(false) {
        return Ok(None);
    }

    let pid = state.pid.unwrap_or(0);
    if pid <= 0 {
        return Err(anyhow::anyhow!(
            "Container {} returned invalid PID.",
            name_or_id
        ));
    }

    Ok(Some(pid as u32))
}

fn main_pid_from_inspect(
    inspect: &ContainerInspectResponse,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    inspect.state.as_ref().map_or(Ok(None), |state| {
        main_pid_from_container_state(state, name_or_id)
    })
}

pub async fn query_container_main_pid(
    docker: &Docker,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    match docker.inspect_container(name_or_id, None).await {
        Ok(inspect) => main_pid_from_inspect(&inspect, name_or_id),
        Err(err) => match err {
            BollardError::DockerResponseServerError {
                status_code: 404, ..
            } => Ok(None),
            _ => Err(err.into()),
        },
    }
}

async fn monitor_container_runtime(
    docker: Docker,
    name_or_id: String,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    let query_docker = docker.clone();
    let mut filters = HashMap::new();
    filters.insert("container".to_string(), vec![name_or_id.clone()]);
    filters.insert("type".to_string(), vec!["container".to_string()]);
    let mut events: BoxStream<'static, Result<EventMessage, bollard::errors::Error>> = docker
        .events(Some(EventsOptions {
            since: None,
            until: None,
            filters: Some(filters),
        }))
        .boxed();
    let poll_interval = Duration::from_secs(1);
    let mut current_pid = query_container_main_pid(&query_docker, &name_or_id).await?;
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
            }
            _ = sleep(poll_interval) => {}
        }

        let next_pid = query_container_main_pid(&query_docker, &name_or_id).await?;
        if next_pid != current_pid {
            current_pid = next_pid;
            let _ = tx.send(RuntimeUpdate::ContainerPid {
                index,
                pid: next_pid,
            });
        }
    }
}

impl ContainerRuntimePort for DockerContainerRuntimeGateway {
    fn query_main_pid<'a>(
        &'a self,
        name_or_id: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<Option<u32>>> {
        Box::pin(async move { query_container_main_pid(&self.docker, name_or_id).await })
    }

    fn spawn_monitor(
        &self,
        name_or_id: String,
        tx: mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> tokio::task::JoinHandle<()> {
        let docker = self.docker.clone();
        tokio::spawn(async move {
            if let Err(err) =
                monitor_container_runtime(docker, name_or_id.clone(), tx.clone(), index).await
            {
                let _ = tx.send(RuntimeUpdate::MonitorError {
                    label: format!("container {name_or_id}"),
                    error: err.to_string(),
                });
            }
        })
    }
}

pub fn runtime_port(docker: Docker) -> SharedContainerRuntimePort {
    Arc::new(DockerContainerRuntimeGateway { docker })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(running: Option<bool>, pid: Option<i64>) -> ContainerState {
        ContainerState {
            running,
            pid,
            ..Default::default()
        }
    }

    #[test]
    fn main_pid_from_inspect_returns_none_when_state_is_missing() {
        let inspect = ContainerInspectResponse::default();

        assert_eq!(main_pid_from_inspect(&inspect, "demo").unwrap(), None);
    }

    #[test]
    fn main_pid_from_container_state_returns_none_when_not_running() {
        let container_state = state(Some(false), Some(1234));

        assert_eq!(
            main_pid_from_container_state(&container_state, "demo").unwrap(),
            None
        );
    }

    #[test]
    fn main_pid_from_container_state_returns_pid_for_running_container() {
        let container_state = state(Some(true), Some(4321));

        assert_eq!(
            main_pid_from_container_state(&container_state, "demo").unwrap(),
            Some(4321)
        );
    }

    #[test]
    fn main_pid_from_container_state_rejects_non_positive_pid() {
        let container_state = state(Some(true), Some(0));

        let err = main_pid_from_container_state(&container_state, "demo").unwrap_err();

        assert_eq!(err.to_string(), "Container demo returned invalid PID.");
    }

    #[test]
    fn runtime_port_wraps_docker_client() {
        if let Ok(docker) = Docker::connect_with_local_defaults() {
            let _runtime = runtime_port(docker);
        }
    }
}
