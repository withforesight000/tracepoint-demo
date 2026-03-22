use std::{collections::HashSet, time::Duration};

use tokio::{select, signal, time::sleep};

use crate::gateway::ebpf::seed_proc_state_from_task_iter;

pub async fn wait_pid_or_tty_targets(
    ebpf: &mut aya::Ebpf,
    pids: &[u32],
    tty_filters: &HashSet<String>,
    tty_inputs: &[String],
    watch_flags: u32,
) -> anyhow::Result<Vec<u32>> {
    let mut announced = false;
    loop {
        let roots = seed_proc_state_from_task_iter(ebpf, pids, tty_filters, watch_flags)?;
        if !roots.is_empty() {
            return Ok(roots);
        }

        if !announced {
            eprintln!(
                "No processes matched PID(s) {:?} or tty(s) {:?}. Waiting for a match...",
                pids, tty_inputs
            );
            announced = true;
        }

        select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = signal::ctrl_c() => return Err(anyhow::anyhow!(
                "Interrupted while waiting for matching PID/TTY targets."
            )),
        }
    }
}
