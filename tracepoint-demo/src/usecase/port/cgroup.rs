use std::sync::Arc;

pub trait CgroupPort: Send + Sync {
    fn read_cgroup_v2_path(&self, pid: u32) -> anyhow::Result<String>;

    fn read_cgroup_procs(&self, path: &str) -> anyhow::Result<Vec<u32>>;
}

pub type SharedCgroupPort = Arc<dyn CgroupPort>;
