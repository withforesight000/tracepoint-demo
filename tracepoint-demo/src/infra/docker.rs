use bollard::Docker;

use crate::gateway::docker;

pub fn connect_if_needed(
    containers: &[String],
) -> anyhow::Result<Option<std::sync::Arc<docker::DockerContainerRuntimeGateway>>> {
    if containers.is_empty() {
        return Ok(None);
    }

    let docker = Docker::connect_with_local_defaults()
        .map_err(|err| anyhow::anyhow!("failed to connect to Docker: {err}"))?;
    Ok(Some(docker::runtime_port(docker)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_if_needed_returns_none_when_no_containers() {
        assert!(connect_if_needed(&[]).unwrap().is_none());
    }

    #[test]
    fn connect_if_needed_with_containers_returns_err_or_some() {
        let result = connect_if_needed(&["dummy".to_string()]);
        assert!(result.is_err() || result.unwrap().is_some());
    }
}
