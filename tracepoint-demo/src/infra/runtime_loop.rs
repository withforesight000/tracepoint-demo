use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
};
use tokio::{io::unix::AsyncFd, select, signal, sync::mpsc};

use crate::{
    gateway::ebpf::drain_exec_events,
    infra::presentation::output::{
        ConsoleStatusReporter, print_exec_event, print_invalid_exec_event_size,
        print_shutdown_message, print_startup_notice,
    },
    infra::presentation::runtime_updates::handle_runtime_update_with_state,
    usecase::{orchestration::state::AppState, port::RuntimeUpdate},
};
use tracepoint_demo_common::EXEC_EVENTS_MAP;

pub struct RuntimeLoopConfig<'a> {
    pub startup_watch_pid_labels: &'a [String],
    pub tty_inputs: &'a [String],
    pub watch_children: bool,
    pub target_descriptions: &'a [String],
    pub has_monitors: bool,
}

pub async fn run(
    ebpf: &mut Ebpf,
    state: &mut AppState,
    update_rx: &mut mpsc::UnboundedReceiver<RuntimeUpdate>,
    config: RuntimeLoopConfig<'_>,
) -> anyhow::Result<()> {
    let mut reporter = ConsoleStatusReporter;

    print_startup_notice(
        config.startup_watch_pid_labels,
        config.tty_inputs,
        config.watch_children,
        config.target_descriptions,
    );

    let mut async_ring = AsyncFd::new(RingBuf::try_from(
        ebpf.take_map(EXEC_EVENTS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?,
    )?)?;

    if !config.has_monitors {
        return run_plain_event_loop(&mut async_ring).await;
    }

    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();
                drain_exec_events(ring, |event| print_exec_event(&event), print_invalid_exec_event_size);
                guard.clear_ready();
            }

            maybe_update = update_rx.recv() => {
                if !handle_runtime_update_with_state(ebpf, state, maybe_update, &mut reporter).await? {
                    break;
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

async fn run_plain_event_loop(async_ring: &mut AsyncFd<RingBuf<MapData>>) -> anyhow::Result<()> {
    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();
                drain_exec_events(ring, |event| print_exec_event(&event), print_invalid_exec_event_size);
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
