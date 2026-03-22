use bollard::Docker;

pub fn connect_if_needed(containers: &[String]) -> anyhow::Result<Option<Docker>> {
    if containers.is_empty() {
        return Ok(None);
    }

    Docker::connect_with_local_defaults()
        .map(Some)
        .map_err(|err| anyhow::anyhow!("failed to connect to Docker: {err}"))
}
