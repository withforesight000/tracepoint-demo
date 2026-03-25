use std::collections::HashSet;

pub trait ProcessSeedPort: Send + Sync {
    fn seed_from_task_iter(
        &mut self,
        pid_roots: &[u32],
        tty_filters: &HashSet<String>,
        watch_flags: u32,
    ) -> anyhow::Result<Vec<u32>>;

    fn seed_direct(&mut self, pids: &[u32], flags: u32) -> anyhow::Result<()>;
}
