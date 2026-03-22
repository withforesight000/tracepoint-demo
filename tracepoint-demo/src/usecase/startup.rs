use std::collections::{HashMap as StdHashMap, HashSet};

use aya::Ebpf;
use bollard::Docker;
use zbus_systemd::systemd1::ManagerProxy;

use tracepoint_demo_common::{PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF};

use crate::{
    gateway::{
        docker::query_container_main_pid,
        ebpf::{build_watch_pids, seed_proc_state_from_task_iter},
        systemd::{SystemdUnitLookupError, query_systemd_unit_status, resolve_systemd_unit},
    },
    interface::cli::{CliArgs, normalize_tty_name},
    usecase::{
        state::{AppState, PreparedApp},
        watch_container::{ContainerRuntime, seed_container_processes},
        watch_pid_or_tty::wait_pid_or_tty_targets,
        watch_roots::add_watch_root,
        watch_systemd_unit::{SystemdRuntime, seed_systemd_unit_processes},
    },
};

pub struct StartupResources {
    pub ebpf: Ebpf,
    pub docker: Option<Docker>,
    pub systemd_conn: Option<zbus::Connection>,
}

fn collect_target_descriptions(
    container_runtimes: &[ContainerRuntime],
    systemd_runtimes: &[SystemdRuntime],
    all_container_processes: bool,
    all_systemd_processes: bool,
) -> Vec<String> {
    let mut target_descriptions = Vec::new();
    if !container_runtimes.is_empty() {
        let container_list = container_runtimes
            .iter()
            .map(|runtime| runtime.name_or_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if all_container_processes {
            target_descriptions.push(format!("containers=[{}] seed=all-procs", container_list));
        } else {
            target_descriptions.push(format!("containers=[{}]", container_list));
        }
    }
    if !systemd_runtimes.is_empty() {
        let unit_list = systemd_runtimes
            .iter()
            .map(|runtime| runtime.unit_name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if all_systemd_processes {
            target_descriptions.push(format!("systemd-units=[{}] seed=all-procs", unit_list));
        } else {
            target_descriptions.push(format!("systemd-units=[{}]", unit_list));
        }
    }
    target_descriptions
}

async fn initialize_container_runtimes(
    ebpf: &mut Ebpf,
    docker: &Docker,
    container: &[String],
    watch_children: bool,
    all_container_processes: bool,
) -> anyhow::Result<Vec<ContainerRuntime>> {
    let mut container_runtimes = Vec::new();
    if container.is_empty() {
        return Ok(container_runtimes);
    }

    for container_name in container {
        let container_watch_children = if all_container_processes {
            true
        } else {
            watch_children
        };
        let container_flags = PROC_FLAG_WATCH_SELF
            | if container_watch_children {
                PROC_FLAG_WATCH_CHILDREN
            } else {
                0
            };

        let current_pid = query_container_main_pid(docker, container_name).await?;
        if let Some(main_pid) = current_pid {
            seed_container_processes(
                ebpf,
                container_name,
                main_pid,
                container_flags,
                container_watch_children,
                all_container_processes,
            )
            .await?;
        }

        container_runtimes.push(ContainerRuntime {
            docker: docker.clone(),
            name_or_id: container_name.clone(),
            watch_children: container_watch_children,
            all_processes: all_container_processes,
            flags: container_flags,
            current_pid,
        });
    }

    Ok(container_runtimes)
}

async fn initialize_systemd_runtimes(
    ebpf: &mut Ebpf,
    conn: &zbus::Connection,
    systemd_unit: &[String],
    watch_children: bool,
    all_systemd_processes: bool,
) -> anyhow::Result<Vec<SystemdRuntime>> {
    let mut systemd_runtimes = Vec::new();
    if systemd_unit.is_empty() {
        return Ok(systemd_runtimes);
    }

    let manager = ManagerProxy::new(conn)
        .await
        .map_err(|err| anyhow::anyhow!("failed to create systemd manager proxy: {err}"))?;

    for unit_name in systemd_unit {
        let unit_watch_children = if all_systemd_processes {
            true
        } else {
            watch_children
        };
        let unit_flags = PROC_FLAG_WATCH_SELF
            | if unit_watch_children {
                PROC_FLAG_WATCH_CHILDREN
            } else {
                0
            };

        let (current_pid, current_running) =
            match resolve_systemd_unit(conn, &manager, unit_name).await {
                Ok(resolved_unit) => {
                    let status = query_systemd_unit_status(
                        &resolved_unit.unit_proxy,
                        &resolved_unit.service_proxy,
                    )
                    .await
                    .map_err(|err| match err {
                        SystemdUnitLookupError::NotFound => {
                            anyhow::anyhow!("systemd unit {unit_name} disappeared during startup")
                        }
                        SystemdUnitLookupError::Other(err) => err,
                    })?;

                    let status = if status.is_running() {
                        status
                    } else {
                        let (_, status) =
                            crate::usecase::watch_systemd_unit::wait_systemd_unit_running(
                                conn, unit_name,
                            )
                            .await?;
                        status
                    };

                    let current_running = status.is_running();
                    seed_systemd_unit_processes(
                        ebpf,
                        conn,
                        unit_name,
                        status.main_pid,
                        unit_flags,
                        unit_watch_children,
                        all_systemd_processes,
                    )
                    .await?;

                    (status.main_pid, current_running)
                }
                Err(SystemdUnitLookupError::NotFound) => (None, false),
                Err(SystemdUnitLookupError::Other(err)) => return Err(err.into()),
            };

        systemd_runtimes.push(SystemdRuntime {
            conn: conn.clone(),
            unit_name: unit_name.clone(),
            watch_children: unit_watch_children,
            all_processes: all_systemd_processes,
            flags: unit_flags,
            current_pid,
            current_running,
        });
    }

    Ok(systemd_runtimes)
}

pub async fn prepare(args: CliArgs, resources: StartupResources) -> anyhow::Result<PreparedApp> {
    let CliArgs {
        pid,
        positional_pids,
        tty: tty_inputs,
        container,
        all_container_processes,
        systemd_unit,
        all_systemd_processes,
        no_watch_children,
    } = args;

    let mut pids = pid;
    pids.extend(positional_pids);

    let mut tty_filters = HashSet::new();
    for tty in &tty_inputs {
        let normalized = normalize_tty_name(tty);
        if !normalized.is_empty() {
            tty_filters.insert(normalized);
        }
    }

    let watch_children = !no_watch_children;

    let mut ebpf = resources.ebpf;

    let watch_flags = PROC_FLAG_WATCH_SELF
        | if watch_children {
            PROC_FLAG_WATCH_CHILDREN
        } else {
            0
        };

    let mut static_watch_roots: StdHashMap<u32, u32> = StdHashMap::new();
    if !pids.is_empty() || !tty_filters.is_empty() {
        let roots = seed_proc_state_from_task_iter(&mut ebpf, &pids, &tty_filters, watch_flags)?;
        for pid in roots {
            add_watch_root(&mut static_watch_roots, pid, watch_flags);
        }
        if static_watch_roots.is_empty() && container.is_empty() && systemd_unit.is_empty() {
            let roots =
                wait_pid_or_tty_targets(&mut ebpf, &pids, &tty_filters, &tty_inputs, watch_flags)
                    .await?;
            for pid in roots {
                add_watch_root(&mut static_watch_roots, pid, watch_flags);
            }
        }
    }

    let container_runtimes = match (container.is_empty(), resources.docker.as_ref()) {
        (true, _) => Vec::new(),
        (false, Some(docker)) => {
            initialize_container_runtimes(
                &mut ebpf,
                docker,
                &container,
                watch_children,
                all_container_processes,
            )
            .await?
        }
        (false, None) => return Err(anyhow::anyhow!("Docker client is not initialized")),
    };
    let systemd_runtimes = match (systemd_unit.is_empty(), resources.systemd_conn.as_ref()) {
        (true, _) => Vec::new(),
        (false, Some(conn)) => {
            initialize_systemd_runtimes(
                &mut ebpf,
                conn,
                &systemd_unit,
                watch_children,
                all_systemd_processes,
            )
            .await?
        }
        (false, None) => return Err(anyhow::anyhow!("systemd connection is not initialized")),
    };

    let current_watch_roots = crate::usecase::watch_roots::collect_watch_roots(
        &static_watch_roots,
        &container_runtimes,
        &systemd_runtimes,
    );
    let watch_pids = build_watch_pids(&mut ebpf, &current_watch_roots)?;

    let target_descriptions = collect_target_descriptions(
        &container_runtimes,
        &systemd_runtimes,
        all_container_processes,
        all_systemd_processes,
    );

    let state = AppState {
        static_watch_roots,
        current_watch_roots,
        watch_pids,
        container_runtimes,
        systemd_runtimes,
    };

    Ok(PreparedApp {
        ebpf,
        state,
        tty_inputs,
        watch_children,
        target_descriptions,
    })
}
