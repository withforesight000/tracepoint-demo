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
        log::debug!(
            "Container {} reported running with invalid PID {}, deferring",
            name_or_id,
            pid
        );
        return Ok(None);
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
        // First resolve the container's current main PID. We need a concrete PID
        // before we can look up the container's cgroup membership.
        let current_pid = match query_container_main_pid(&docker, &name_or_id).await {
            Ok(Some(pid)) => pid,
            Ok(None) => {
                // If Docker still does not expose a usable PID, there is nothing
                // to probe yet. Give up quietly and let the next event retry.
                log::debug!(
                    "docker cgroup probe for {} could not resolve current container pid",
                    name_or_id
                );
                return;
            }
            Err(err) => {
                // Any inspect failure here means we cannot safely continue to the
                // cgroup lookup step.
                log::debug!(
                    "docker cgroup probe for {} failed to resolve current container pid: {}",
                    name_or_id,
                    err
                );
                return;
            }
        };

        // Use procfs to map that PID to the cgroup v2 path. The cgroup path is
        // what lets us observe the container's process set directly.
        let cgroup_path = match crate::gateway::procfs::read_cgroup_v2_path(current_pid) {
            Ok(path) => path,
            Err(err) => {
                // If the PID cannot be mapped to a cgroup path, we cannot inspect
                // membership changes for this container.
                log::debug!(
                    "docker cgroup probe for {} failed to resolve cgroup path for pid {}: {}",
                    name_or_id,
                    current_pid,
                    err
                );
                return;
            }
        };

        // Capture the current membership as a baseline snapshot. This probe is
        // best-effort: if the PID is already present here, it will not be treated
        // as "new" by the diff below.
        let mut known_pids: HashSet<u32> =
            match crate::gateway::procfs::read_cgroup_procs(&cgroup_path) {
                Ok(pids) => pids.into_iter().collect(),
                Err(err) => {
                    // If we cannot read cgroup.procs even once, there is no reliable
                    // baseline to compare against, so the probe stops here.
                    log::debug!(
                        "docker cgroup probe for {} failed to read cgroup.procs at {}: {}",
                        name_or_id,
                        cgroup_path,
                        err
                    );
                    return;
                }
            };

        // Poll the cgroup briefly. The goal is to catch a PID that appears just
        // after exec_create, before the rest of the runtime has a chance to miss it.
        // This is not a guarantee: exec_start also does a direct inspect_exec()
        // lookup, and the two paths together reduce the chance of missing the
        // container's new process.
        for _ in 0..100 {
            match crate::gateway::procfs::read_cgroup_procs(&cgroup_path) {
                Ok(pids) => {
                    // Keep only PIDs that were not present in the baseline snapshot.
                    // If a PID was already in known_pids here, this probe treats it
                    // as already accounted for rather than "new".
                    let extra_pids: Vec<u32> = pids
                        .into_iter()
                        .filter(|pid| known_pids.insert(*pid))
                        .collect();

                    if !extra_pids.is_empty() {
                        // As soon as we see a new PID, tell the runtime layer to
                        // refresh the container state and seed those extra PIDs.
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
                    // If the cgroup disappears or becomes unreadable, this probe no
                    // longer has a trustworthy signal to follow.
                    log::debug!(
                        "docker cgroup probe for {} failed to reread cgroup.procs at {}: {}",
                        name_or_id,
                        cgroup_path,
                        err
                    );
                    return;
                }
            }

            // Short sleep so we can catch the new PID soon after exec_create without
            // holding the runtime loop hostage.
            sleep(Duration::from_millis(1)).await;
        }

        // No new PID appeared within the probe window. That is not an error; the
        // normal polling path will continue to watch the container.
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
    // Position of this container in the runtime list. The same number is sent back
    // in RuntimeUpdate so the upper layers can update the exact container entry
    // that owns this monitor.
    index: usize,
) -> anyhow::Result<()> {
    let query_docker = docker.clone();
    let update_tx = tx.clone();
    let mut filters = HashMap::new();
    filters.insert("container".to_string(), vec![name_or_id.clone()]);
    // NOTE:
    // `docker.events(...)` returns `impl Stream<Item = Result<EventMessage, Error>>`.
    //
    // In Bollard, that `impl Stream` is not a named public type. Internally it is
    // built from a chain of stream combinators and a `Box::pin(...)` around that
    // chain. The concrete type is therefore intentionally hidden from callers.
    //
    // We call `.boxed()` here for a separate reason: to erase the anonymous stream
    // type into `BoxStream<'static, _>`, which is just:
    //   `Pin<Box<dyn Stream<Item = T> + Send + 'a>>`
    //
    // `Box` puts the stream on the heap so the value has a stable address, and
    // `Pin` tells Rust that the boxed stream must not be moved after it has been
    // pinned. That matters because `Stream::poll_next` takes `Pin<&mut Self>`, so
    // poll-based async code is allowed to rely on the stream staying at the same
    // address while it is being driven. Without `Pin`, a stream implementation that
    // contains self-references or other address-sensitive state could be moved after
    // it had been partially polled, which would make those internal references
    // invalid and break the safety guarantees that the async/stream machinery
    // depends on.
    //
    // That makes the value easier to name, store in `Arc<Mutex<_>>`, and move into
    // the closures below without dragging the full concrete type through this
    // function. In other words, this is type erasure for convenience, not a
    // behavioral requirement.
    //
    // If you need to understand this again later, trace the definitions in this
    // order:
    //   1. `bollard::Docker::events(...)`
    //   2. `bollard::Docker::process_into_stream(...)`
    //   3. `bollard::Docker::decode_into_stream(...)`
    //   4. `futures_core::stream::BoxStream`
    //
    // The stream itself is still the same runtime event stream from Docker; only
    // the Rust type used to hold it has been erased.
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
        // The outer `clone()` calls below are not the same thing as `move`.
        //
        // `let events = events.clone();` means "borrow the outer `events`
        // immutably for the duration of the method call, create a new owned
        // handle, then bind that new handle to the inner name `events`."
        // In other words, the right-hand side is effectively `Clone::clone(&events)`.
        //
        // The reason we do this before `move || { ... }` is that the closure
        // needs to capture its own owned copies. Once the closure is created,
        // the values it captures are moved into the closure environment.
        //
        // That distinction matters:
        // - reading a captured value usually gives the closure an immutable
        //   borrow of the original value,
        // - mutating a captured value usually gives the closure a mutable
        //   borrow,
        // - `move` forces the closure to take ownership of the captured value.
        //
        // Here we want ownership inside the closure, but we do not want to move
        // the original outer variables out of this scope yet. So we clone first,
        // then move the cloned handles into the closure.
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
                    // This `select!` is a small event loop with a timeout fallback.
                    //
                    // The first branch waits for the Docker event stream to yield an
                    // item. The second branch is a periodic sleep that lets us poll
                    // the container state even when no relevant Docker event arrives.
                    //
                    // `biased;` makes the branch order significant: the event branch
                    // is checked first, and the timer is only used as a fallback.
                    // That matches the intent here, which is to react to Docker
                    // events as soon as possible and only poll when the stream is
                    // quiet.
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
                                                // `exec_create` / `exec_start` indicate that a new
                                                // process may have appeared inside the container.
                                                // The goal here is not to log Docker events, but to
                                                // update WATCH_PIDS quickly enough that we do not miss
                                                // the next execve.
                                                if matches!(
                                                    action,
                                                    Some(action) if action.starts_with("exec_create")
                                                ) {
                                                    // `exec_create` happens very early, when the exec PID
                                                    // may not yet be stable in Docker's inspect APIs.
                                                    // Spawn a short-lived cgroup probe so we can wait for
                                                    // the new PID to show up in the container's cgroup.
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
                                                        // `exec_start` can often be resolved to a PID
                                                        // immediately. When that works, return it as an
                                                        // additional pid that should be watched right away.
                                                        return Ok(ContainerMonitorSignal::Refresh {
                                                            extra_pids: vec![pid],
                                                        });
                                                    }
                                                }
                                                // Do not end monitoring after one Docker exec event.
                                                // Keep looping so we can continue tracking main pid
                                                // changes and any later events.
                                                Ok(ContainerMonitorSignal::Poll)
                                            }
                                            None => {
                                                // If we cannot extract an exec ID, we do not have
                                                // enough information to drive a watch update.
                                                // Fall back to normal polling.
                                                log::debug!(
                                                    "docker event for {}: action={:?} missing exec id",
                                                    name_or_id,
                                                    action
                                                );
                                                Ok(ContainerMonitorSignal::Poll)
                                            }
                                        }
                                    } else {
                                        // Non-exec Docker events are not directly useful for this
                                        // watcher. Consume the event and fall back to periodic
                                        // polling.
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
    fn main_pid_from_inspect_returns_none_for_invalid_running_pid() {
        let inspect = ContainerInspectResponse {
            state: Some(state(Some(true), Some(0))),
            ..Default::default()
        };

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
    fn main_pid_from_container_state_returns_none_for_non_positive_pid() {
        let container_state = state(Some(true), Some(0));

        assert_eq!(
            main_pid_from_container_state(&container_state, "demo").unwrap(),
            None
        );
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
