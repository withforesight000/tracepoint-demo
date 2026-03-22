use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
};
use tokio::{io::unix::AsyncFd, select, signal, sync::mpsc};

use crate::{
    gateway::ebpf::drain_exec_events,
    interface::output::{print_shutdown_message, print_startup_notice},
    usecase::{
        runtime_update::RuntimeUpdate,
        state::AppState,
        watch_container::apply_container_runtime_update,
        watch_roots::{collect_watch_roots, sync_watch_pids},
        watch_systemd_unit::apply_systemd_runtime_update,
    },
};
use tracepoint_demo_common::EXEC_EVENTS_MAP;

pub async fn run(
    ebpf: &mut Ebpf,
    state: &mut AppState,
    update_rx: &mut mpsc::UnboundedReceiver<RuntimeUpdate>,
    tty_inputs: &[String],
    watch_children: bool,
    target_descriptions: &[String],
    has_monitors: bool,
) -> anyhow::Result<()> {
    print_startup_notice(
        &state
            .current_watch_roots
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        tty_inputs,
        watch_children,
        target_descriptions,
    );

    let mut async_ring = AsyncFd::new(RingBuf::try_from(
        ebpf.take_map(EXEC_EVENTS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?,
    )?)?;

    if !has_monitors {
        return run_plain_event_loop(&mut async_ring).await;
    }

    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();
                drain_exec_events(ring);
                guard.clear_ready();
            }

            maybe_update = update_rx.recv() => {
                match maybe_update {
                    Some(RuntimeUpdate::ContainerPid { index, pid }) => {
                        let runtime = state.container_runtimes.get_mut(index).ok_or_else(|| {
                            anyhow::anyhow!("container runtime index {index} out of range")
                        })?;
                        apply_container_runtime_update(ebpf, runtime, pid).await?;
                        refresh_watch_pids(state)?;
                    }
                    Some(RuntimeUpdate::SystemdStatus { index, pid, running }) => {
                        let runtime = state.systemd_runtimes.get_mut(index).ok_or_else(|| {
                            anyhow::anyhow!("systemd runtime index {index} out of range")
                        })?;
                        apply_systemd_runtime_update(ebpf, runtime, pid, running).await?;
                        refresh_watch_pids(state)?;
                    }
                    Some(RuntimeUpdate::MonitorError { label, error }) => {
                        return Err(anyhow::anyhow!("{label}: {error}"));
                    }
                    None => break,
                }
            }

            _ = signal::ctrl_c() => {
                print_shutdown_message();
                break;
            }
        }
    }

    Ok(())
}

fn refresh_watch_pids(state: &mut AppState) -> anyhow::Result<()> {
    let desired_roots = collect_watch_roots(
        &state.static_watch_roots,
        &state.container_runtimes,
        &state.systemd_runtimes,
    );
    sync_watch_pids(
        &mut state.watch_pids,
        &mut state.current_watch_roots,
        &desired_roots,
    )?;
    Ok(())
}

async fn run_plain_event_loop(async_ring: &mut AsyncFd<RingBuf<MapData>>) -> anyhow::Result<()> {
    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();
                drain_exec_events(ring);
                guard.clear_ready();
            }

            _ = signal::ctrl_c() => {
                print_shutdown_message();
                break;
            }
        }
    }

    Ok(())
}
