use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::Arc,
    time::Duration,
};

use bollard::{
    Docker,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerState, EventMessage},
    query_parameters::EventsOptions,
};
use futures_util::{StreamExt, stream::BoxStream};
use tokio::{
    select,
    sync::{Mutex, mpsc},
    time::sleep,
};

use crate::usecase::port::{
    BoxFuture, ContainerRuntimePort, RuntimeUpdate, SharedContainerRuntimePort,
};

#[derive(Debug)]
enum ContainerMonitorSignal {
    Poll,
    Refresh { extra_pids: Vec<u32> },
}

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

fn exec_id_from_event(event: &EventMessage) -> Option<&str> {
    event
        .actor
        .as_ref()
        .and_then(|actor| actor.attributes.as_ref())
        .and_then(|attributes| attributes.get("execID"))
        .map(String::as_str)
}

async fn query_exec_pid(docker: &Docker, exec_id: &str) -> anyhow::Result<Option<u32>> {
    match docker.inspect_exec(exec_id).await {
        Ok(exec) => Ok(match exec.pid {
            Some(pid) if pid > 0 => Some(pid as u32),
            _ => None,
        }),
        Err(err) => match err {
            BollardError::DockerResponseServerError {
                status_code: 404, ..
            } => Ok(None),
            _ => Err(err.into()),
        },
    }
}

fn spawn_container_cgroup_probe(
    docker: Docker,
    name_or_id: String,
    index: usize,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
) {
    tokio::spawn(async move {
        let current_pid = match query_container_main_pid(&docker, &name_or_id).await {
            Ok(Some(pid)) => pid,
            Ok(None) => {
                log::debug!(
                    "docker cgroup probe for {} could not resolve current container pid",
                    name_or_id
                );
                return;
            }
            Err(err) => {
                log::debug!(
                    "docker cgroup probe for {} failed to resolve current container pid: {}",
                    name_or_id,
                    err
                );
                return;
            }
        };

        let cgroup_path = match crate::gateway::procfs::read_cgroup_v2_path(current_pid) {
            Ok(path) => path,
            Err(err) => {
                log::debug!(
                    "docker cgroup probe for {} failed to resolve cgroup path for pid {}: {}",
                    name_or_id,
                    current_pid,
                    err
                );
                return;
            }
        };

        let mut known_pids: HashSet<u32> =
            match crate::gateway::procfs::read_cgroup_procs(&cgroup_path) {
                Ok(pids) => pids.into_iter().collect(),
                Err(err) => {
                    log::debug!(
                        "docker cgroup probe for {} failed to read cgroup.procs at {}: {}",
                        name_or_id,
                        cgroup_path,
                        err
                    );
                    return;
                }
            };

        for _ in 0..100 {
            match crate::gateway::procfs::read_cgroup_procs(&cgroup_path) {
                Ok(pids) => {
                    let extra_pids: Vec<u32> = pids
                        .into_iter()
                        .filter(|pid| known_pids.insert(*pid))
                        .collect();

                    if !extra_pids.is_empty() {
                        log::debug!(
                            "docker cgroup probe for {} resolved new pid(s) {:?}",
                            name_or_id,
                            extra_pids
                        );
                        let _ = tx.send(RuntimeUpdate::ContainerPid {
                            index,
                            pid: Some(current_pid),
                            force_refresh: true,
                            extra_pids,
                        });
                        return;
                    }
                }
                Err(err) => {
                    log::debug!(
                        "docker cgroup probe for {} failed to reread cgroup.procs at {}: {}",
                        name_or_id,
                        cgroup_path,
                        err
                    );
                    return;
                }
            }

            sleep(Duration::from_millis(1)).await;
        }

        log::debug!(
            "docker cgroup probe for {} timed out without seeing a new pid",
            name_or_id
        );
    });
}

async fn monitor_container_runtime(
    docker: Docker,
    name_or_id: String,
    all_processes: bool,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    let query_docker = docker.clone();
    let update_tx = tx.clone();
    let mut filters = HashMap::new();
    filters.insert("container".to_string(), vec![name_or_id.clone()]);
    let events: BoxStream<'static, Result<EventMessage, bollard::errors::Error>> = docker
        .events(Some(EventsOptions {
            since: None,
            until: None,
            filters: Some(filters),
        }))
        .boxed();
    let poll_interval = Duration::from_secs(1);
    let events = Arc::new(Mutex::new(events));
    monitor_container_runtime_with(
        &tx,
        index,
        {
            let events = events.clone();
            let name_or_id = name_or_id.clone();
            let query_docker = query_docker.clone();
            let update_tx = update_tx.clone();
            move || {
                let events = events.clone();
                let name_or_id = name_or_id.clone();
                let query_docker = query_docker.clone();
                let update_tx = update_tx.clone();
                async move {
                    select! {
                        biased;
                        maybe_event = async {
                            let mut events = events.lock().await;
                            events.next().await
                        } => {
                            match maybe_event {
                                Some(Ok(event)) => {
                                    let action = event.action.as_deref();
                                    let is_exec_event = all_processes
                                        && matches!(
                                            action,
                                            Some(action)
                                                if action.starts_with("exec_create")
                                                    || action.starts_with("exec_start")
                                        );
                                    if is_exec_event {
                                        match exec_id_from_event(&event) {
                                            Some(exec_id) => {
                                                if matches!(
                                                    action,
                                                    Some(action) if action.starts_with("exec_create")
                                                ) {
                                                    spawn_container_cgroup_probe(
                                                        query_docker.clone(),
                                                        name_or_id.clone(),
                                                        index,
                                                        update_tx.clone(),
                                                    );
                                                    log::debug!(
                                                        "docker event for {}: action={:?} exec_id={} probe=scheduled",
                                                        name_or_id,
                                                        action,
                                                        exec_id
                                                    );
                                                } else {
                                                    let pid = query_exec_pid(&query_docker, exec_id).await;
                                                    log::debug!(
                                                        "docker event for {}: action={:?} exec_id={} pid_lookup={:?}",
                                                        name_or_id,
                                                        action,
                                                        exec_id,
                                                        pid
                                                    );
                                                    if let Ok(Some(pid)) = pid {
                                                        return Ok(ContainerMonitorSignal::Refresh {
                                                            extra_pids: vec![pid],
                                                        });
                                                    }
                                                }
                                                Ok(ContainerMonitorSignal::Poll)
                                            }
                                            None => {
                                                log::debug!(
                                                    "docker event for {}: action={:?} missing exec id",
                                                    name_or_id,
                                                    action
                                                );
                                                Ok(ContainerMonitorSignal::Poll)
                                            }
                                        }
                                    } else {
                                        Ok(ContainerMonitorSignal::Poll)
                                    }
                                }
                                Some(Err(err)) => Err(err.into()),
                                None => Err(anyhow::anyhow!(
                                    "Docker event stream ended while monitoring container {name_or_id}."
                                )),
                            }
                        }
                        _ = sleep(poll_interval) => Ok(ContainerMonitorSignal::Poll),
                    }
                }
            }
        },
        {
            let query_docker = query_docker.clone();
            let name_or_id = name_or_id.clone();
            move || {
                let query_docker = query_docker.clone();
                let name_or_id = name_or_id.clone();
                async move { query_container_main_pid(&query_docker, &name_or_id).await }
            }
        },
    )
    .await
}

async fn monitor_container_runtime_with<TWait, TWaitFuture, TQuery, TQueryFuture>(
    tx: &mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
    mut wait_for_signal: TWait,
    mut query_main_pid: TQuery,
) -> anyhow::Result<()>
where
    TWait: FnMut() -> TWaitFuture,
    TWaitFuture: Future<Output = anyhow::Result<ContainerMonitorSignal>>,
    TQuery: FnMut() -> TQueryFuture,
    TQueryFuture: Future<Output = anyhow::Result<Option<u32>>>,
{
    let mut current_pid = query_main_pid().await?;
    let _ = tx.send(RuntimeUpdate::ContainerPid {
        index,
        pid: current_pid,
        force_refresh: false,
        extra_pids: Vec::new(),
    });

    loop {
        match wait_for_signal().await? {
            ContainerMonitorSignal::Refresh { extra_pids } => {
                let _ = tx.send(RuntimeUpdate::ContainerPid {
                    index,
                    pid: current_pid,
                    force_refresh: true,
                    extra_pids,
                });
            }
            ContainerMonitorSignal::Poll => {
                let next_pid = query_main_pid().await?;
                if next_pid != current_pid {
                    current_pid = next_pid;
                    let _ = tx.send(RuntimeUpdate::ContainerPid {
                        index,
                        pid: next_pid,
                        force_refresh: false,
                        extra_pids: Vec::new(),
                    });
                }
            }
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
        all_processes: bool,
        tx: mpsc::UnboundedSender<RuntimeUpdate>,
        index: usize,
    ) -> tokio::task::JoinHandle<()> {
        let docker = self.docker.clone();
        tokio::spawn(async move {
            if let Err(err) = monitor_container_runtime(
                docker,
                name_or_id.clone(),
                all_processes,
                tx.clone(),
                index,
            )
            .await
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
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    fn drain_updates(mut rx: mpsc::UnboundedReceiver<RuntimeUpdate>) -> Vec<RuntimeUpdate> {
        let mut updates = Vec::new();
        while let Ok(update) = rx.try_recv() {
            updates.push(update);
        }
        updates
    }

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
    fn main_pid_from_inspect_propagates_invalid_running_pid() {
        let inspect = ContainerInspectResponse {
            state: Some(state(Some(true), Some(0))),
            ..Default::default()
        };

        let err = main_pid_from_inspect(&inspect, "demo").unwrap_err();

        assert_eq!(err.to_string(), "Container demo returned invalid PID.");
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

    #[tokio::test]
    async fn monitor_container_runtime_with_sends_initial_and_changed_pids() {
        let (tx, rx) = mpsc::unbounded_channel();
        let signals: Arc<Mutex<VecDeque<anyhow::Result<ContainerMonitorSignal>>>> =
            Arc::new(Mutex::new(VecDeque::from([
                Ok(ContainerMonitorSignal::Poll),
                Ok(ContainerMonitorSignal::Poll),
                Err(anyhow::anyhow!("stop")),
            ])));
        let pids: Arc<Mutex<VecDeque<anyhow::Result<Option<u32>>>>> =
            Arc::new(Mutex::new(VecDeque::from([
                Ok(Some(10)),
                Ok(Some(10)),
                Ok(Some(20)),
            ])));

        let err = monitor_container_runtime_with(
            &tx,
            3,
            {
                let signals = signals.clone();
                move || {
                    let signals = signals.clone();
                    async move { signals.lock().unwrap().pop_front().unwrap() }
                }
            },
            {
                let pids = pids.clone();
                move || {
                    let pids = pids.clone();
                    async move { pids.lock().unwrap().pop_front().unwrap() }
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "stop");
        let updates = drain_updates(rx);
        assert_eq!(updates.len(), 2);
        match &updates[0] {
            RuntimeUpdate::ContainerPid {
                index,
                pid,
                force_refresh,
                extra_pids,
            } => {
                assert_eq!(*index, 3);
                assert_eq!(*pid, Some(10));
                assert!(!*force_refresh);
                assert!(extra_pids.is_empty());
            }
            _ => panic!("expected container pid update"),
        }
        match &updates[1] {
            RuntimeUpdate::ContainerPid {
                index,
                pid,
                force_refresh,
                extra_pids,
            } => {
                assert_eq!(*index, 3);
                assert_eq!(*pid, Some(20));
                assert!(!*force_refresh);
                assert!(extra_pids.is_empty());
            }
            _ => panic!("expected container pid update"),
        }
    }

    #[tokio::test]
    async fn monitor_container_runtime_with_forces_refresh_for_exec_start_events() {
        let (tx, rx) = mpsc::unbounded_channel();
        let signals: Arc<Mutex<VecDeque<anyhow::Result<ContainerMonitorSignal>>>> =
            Arc::new(Mutex::new(VecDeque::from([
                Ok(ContainerMonitorSignal::Refresh {
                    extra_pids: vec![777],
                }),
                Err(anyhow::anyhow!("stop")),
            ])));
        let pids: Arc<Mutex<VecDeque<anyhow::Result<Option<u32>>>>> =
            Arc::new(Mutex::new(VecDeque::from([Ok(Some(10))])));

        let err = monitor_container_runtime_with(
            &tx,
            7,
            {
                let signals = signals.clone();
                move || {
                    let signals = signals.clone();
                    async move { signals.lock().unwrap().pop_front().unwrap() }
                }
            },
            {
                let pids = pids.clone();
                move || {
                    let pids = pids.clone();
                    async move { pids.lock().unwrap().pop_front().unwrap() }
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "stop");
        let updates = drain_updates(rx);
        assert_eq!(updates.len(), 2);
        match &updates[0] {
            RuntimeUpdate::ContainerPid {
                index,
                pid,
                force_refresh,
                extra_pids,
            } => {
                assert_eq!(*index, 7);
                assert_eq!(*pid, Some(10));
                assert!(!*force_refresh);
                assert!(extra_pids.is_empty());
            }
            _ => panic!("expected container pid update"),
        }
        match &updates[1] {
            RuntimeUpdate::ContainerPid {
                index,
                pid,
                force_refresh,
                extra_pids,
            } => {
                assert_eq!(*index, 7);
                assert_eq!(*pid, Some(10));
                assert!(*force_refresh);
                assert_eq!(extra_pids, &vec![777]);
            }
            _ => panic!("expected container pid update"),
        }
    }

    #[tokio::test]
    async fn monitor_container_runtime_with_propagates_query_errors_after_initial_send() {
        let (tx, rx) = mpsc::unbounded_channel();
        let signals: Arc<Mutex<VecDeque<anyhow::Result<ContainerMonitorSignal>>>> = Arc::new(
            Mutex::new(VecDeque::from([Ok(ContainerMonitorSignal::Poll)])),
        );
        let pids: Arc<Mutex<VecDeque<anyhow::Result<Option<u32>>>>> =
            Arc::new(Mutex::new(VecDeque::from([
                Ok(Some(10)),
                Err(anyhow::anyhow!("inspect failed")),
            ])));

        let err = monitor_container_runtime_with(
            &tx,
            1,
            {
                let signals = signals.clone();
                move || {
                    let signals = signals.clone();
                    async move { signals.lock().unwrap().pop_front().unwrap() }
                }
            },
            {
                let pids = pids.clone();
                move || {
                    let pids = pids.clone();
                    async move { pids.lock().unwrap().pop_front().unwrap() }
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "inspect failed");
        let updates = drain_updates(rx);
        assert_eq!(updates.len(), 1);
        match &updates[0] {
            RuntimeUpdate::ContainerPid {
                index,
                pid,
                force_refresh,
                extra_pids,
            } => {
                assert_eq!(*index, 1);
                assert_eq!(*pid, Some(10));
                assert!(!*force_refresh);
                assert!(extra_pids.is_empty());
            }
            _ => panic!("expected container pid update"),
        }
    }
}
