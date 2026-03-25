use aya::Ebpf;

use crate::infra::presentation::runtime_update_dispatch::{
    RuntimeUpdateHandler, handle_runtime_update,
};
use crate::usecase::{
    orchestration::{
        state::AppState,
        watch_roots::{collect_watch_roots, sync_watch_pids},
    },
    policy::{
        watch_container::apply_container_runtime_update,
        watch_systemd_unit::apply_systemd_runtime_update,
    },
    port::{RuntimeUpdate, StatusReporter},
};

struct AppRuntimeUpdateHandler<'a, TReporter: StatusReporter + ?Sized> {
    ebpf: &'a mut Ebpf,
    state: &'a mut AppState,
    reporter: &'a mut TReporter,
}

impl<TReporter: StatusReporter + ?Sized> RuntimeUpdateHandler
    for AppRuntimeUpdateHandler<'_, TReporter>
{
    async fn apply_container_pid(&mut self, index: usize, pid: Option<u32>) -> anyhow::Result<()> {
        let runtime = self
            .state
            .container_runtimes
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("container runtime index {index} out of range"))?;
        apply_container_runtime_update(self.ebpf, self.reporter, runtime, pid).await?;
        refresh_watch_pids(self.state)
    }

    async fn apply_systemd_status(
        &mut self,
        index: usize,
        pid: Option<u32>,
        running: bool,
    ) -> anyhow::Result<()> {
        let runtime = self
            .state
            .systemd_runtimes
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("systemd runtime index {index} out of range"))?;
        apply_systemd_runtime_update(self.ebpf, self.reporter, runtime, pid, running).await?;
        refresh_watch_pids(self.state)
    }
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

pub async fn handle_runtime_update_with_state<TReporter: StatusReporter + ?Sized>(
    ebpf: &mut Ebpf,
    state: &mut AppState,
    maybe_update: Option<RuntimeUpdate>,
    reporter: &mut TReporter,
) -> anyhow::Result<bool> {
    let mut handler = AppRuntimeUpdateHandler {
        ebpf,
        state,
        reporter,
    };
    handle_runtime_update(&mut handler, maybe_update).await
}
