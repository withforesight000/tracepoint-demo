use std::{collections::HashSet, time::Duration};

use crate::{
    gateway::ebpf::seed_proc_state_from_task_iter,
    usecase::ports::{StatusReporter, WaitPort},
};

pub async fn wait_pid_or_tty_targets<
    TReporter: StatusReporter + ?Sized,
    TWait: WaitPort + ?Sized,
>(
    ebpf: &mut aya::Ebpf,
    pids: &[u32],
    tty_filters: &HashSet<String>,
    tty_inputs: &[String],
    watch_flags: u32,
    reporter: &mut TReporter,
    wait_port: &mut TWait,
) -> anyhow::Result<Vec<u32>> {
    let mut announced = false;
    loop {
        let roots = seed_proc_state_from_task_iter(ebpf, pids, tty_filters, watch_flags)?;
        if !roots.is_empty() {
            return Ok(roots);
        }

        if !announced {
            reporter.warn(format!(
                "No processes matched PID(s) {:?} or tty(s) {:?}. Waiting for a match...",
                pids, tty_inputs
            ));
            announced = true;
        }

        wait_port
            .wait(
                Duration::from_secs(1),
                "Interrupted while waiting for matching PID/TTY targets.".to_string(),
            )
            .await?;
    }
}
