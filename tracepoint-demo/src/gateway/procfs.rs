use std::{fs, path::PathBuf};

pub fn ensure_non_root_cgroup_path(path: &str, label: &str) -> anyhow::Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Err(anyhow::anyhow!(
            "{label} is attached to the root cgroup, refusing to seed all host processes"
        ));
    }
    Ok(())
}

pub fn read_cgroup_v2_path(pid: u32) -> anyhow::Result<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = fs::read_to_string(&path)?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let trimmed = rest.trim();
            ensure_non_root_cgroup_path(trimmed, "container")?;
            return Ok(trimmed.to_string());
        }
    }

    Err(anyhow::anyhow!("cgroup v2 path not found in {}", path))
}

pub fn read_cgroup_procs(path: &str) -> anyhow::Result<Vec<u32>> {
    let mut full_path = PathBuf::from("/sys/fs/cgroup");
    let relative = path.trim_start_matches('/');
    if !relative.is_empty() {
        full_path.push(relative);
    }
    full_path.push("cgroup.procs");

    let content = fs::read_to_string(&full_path)?;
    let mut pids = Vec::new();
    for token in content.split_whitespace() {
        let pid: u32 = token.parse().map_err(|err| {
            anyhow::anyhow!("invalid pid {} in {}: {err}", token, full_path.display())
        })?;
        pids.push(pid);
    }

    Ok(pids)
}
