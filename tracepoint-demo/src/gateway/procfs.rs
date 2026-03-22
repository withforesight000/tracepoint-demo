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

fn parse_cgroup_v2_path(content: &str, pid: u32) -> anyhow::Result<String> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let trimmed = rest.trim();
            ensure_non_root_cgroup_path(trimmed, "container")?;
            return Ok(trimmed.to_string());
        }
    }

    Err(anyhow::anyhow!(
        "cgroup v2 path not found in /proc/{pid}/cgroup"
    ))
}

fn parse_cgroup_procs_content(
    content: &str,
    full_path: &std::path::Path,
) -> anyhow::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for token in content.split_whitespace() {
        let pid: u32 = token.parse().map_err(|err| {
            anyhow::anyhow!("invalid pid {} in {}: {err}", token, full_path.display())
        })?;
        pids.push(pid);
    }

    Ok(pids)
}

pub fn read_cgroup_v2_path(pid: u32) -> anyhow::Result<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = fs::read_to_string(&path)?;

    parse_cgroup_v2_path(&content, pid)
}

pub fn read_cgroup_procs(path: &str) -> anyhow::Result<Vec<u32>> {
    let mut full_path = PathBuf::from("/sys/fs/cgroup");
    let relative = path.trim_start_matches('/');
    if !relative.is_empty() {
        full_path.push(relative);
    }
    full_path.push("cgroup.procs");

    let content = fs::read_to_string(&full_path)?;

    parse_cgroup_procs_content(&content, &full_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_non_root_cgroup_path_ok_for_non_root_directory() {
        assert!(ensure_non_root_cgroup_path("/org/foo", "container").is_ok());
        assert!(ensure_non_root_cgroup_path("org/foo", "container").is_ok());
    }

    #[test]
    fn ensure_non_root_cgroup_path_rejects_empty_or_root() {
        assert!(ensure_non_root_cgroup_path("", "container").is_err());
        assert!(ensure_non_root_cgroup_path("/", "container").is_err());
    }

    #[test]
    fn ensure_non_root_cgroup_path_trims_whitespace() {
        assert!(ensure_non_root_cgroup_path("  /slice/demo  ", "container").is_ok());
    }

    #[test]
    fn parse_cgroup_v2_path_returns_trimmed_non_root_path() {
        let content = "12:cpu:/legacy\n0::/kubepods.slice/demo.scope  \n";

        let path = parse_cgroup_v2_path(content, 42).unwrap();

        assert_eq!(path, "/kubepods.slice/demo.scope");
    }

    #[test]
    fn parse_cgroup_v2_path_rejects_root_cgroup() {
        let content = "0::/\n";
        let err = parse_cgroup_v2_path(content, 7).unwrap_err();

        assert!(
            err.to_string()
                .contains("refusing to seed all host processes")
        );
    }

    #[test]
    fn parse_cgroup_v2_path_requires_v2_entry() {
        let err = parse_cgroup_v2_path("9:cpu:/legacy\n", 99).unwrap_err();

        assert_eq!(
            err.to_string(),
            "cgroup v2 path not found in /proc/99/cgroup"
        );
    }

    #[test]
    fn parse_cgroup_procs_content_parses_whitespace_separated_pids() {
        let path = PathBuf::from("/sys/fs/cgroup/demo/cgroup.procs");
        let pids = parse_cgroup_procs_content("101\n202 303\t404\n", &path).unwrap();

        assert_eq!(pids, vec![101, 202, 303, 404]);
    }

    #[test]
    fn parse_cgroup_procs_content_reports_invalid_pid() {
        let path = PathBuf::from("/sys/fs/cgroup/demo/cgroup.procs");
        let err = parse_cgroup_procs_content("101 nope 303", &path).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("invalid pid nope"));
        assert!(message.contains("/sys/fs/cgroup/demo/cgroup.procs"));
    }
}
