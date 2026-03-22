use bollard::Docker;

pub fn connect_if_needed(containers: &[String]) -> anyhow::Result<Option<Docker>> {
    if containers.is_empty() {
        return Ok(None);
    }

    Docker::connect_with_local_defaults()
        .map(Some)
        .map_err(|err| anyhow::anyhow!("failed to connect to Docker: {err}"))
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
