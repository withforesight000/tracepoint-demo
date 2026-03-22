use bollard::{
    Docker,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerState},
};

fn main_pid_from_container_state(
    state: &ContainerState,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    if !state.running.unwrap_or(false) {
        return Ok(None);
    }

    let pid = state.pid.unwrap_or(0);
    if pid <= 0 {
        return Err(anyhow::anyhow!(
            "Container {} returned invalid PID.",
            name_or_id
        ));
    }

    Ok(Some(pid as u32))
}

fn main_pid_from_inspect(
    inspect: &ContainerInspectResponse,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    inspect.state.as_ref().map_or(Ok(None), |state| {
        main_pid_from_container_state(state, name_or_id)
    })
}

pub async fn query_container_main_pid(
    docker: &Docker,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    match docker.inspect_container(name_or_id, None).await {
        Ok(inspect) => main_pid_from_inspect(&inspect, name_or_id),
        Err(err) => match err {
            BollardError::DockerResponseServerError {
                status_code: 404, ..
            } => Ok(None),
            _ => Err(err.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(running: Option<bool>, pid: Option<i64>) -> ContainerState {
        ContainerState {
            running,
            pid,
            ..Default::default()
        }
    }

    #[test]
    fn main_pid_from_inspect_returns_none_when_state_is_missing() {
        let inspect = ContainerInspectResponse::default();

        assert_eq!(main_pid_from_inspect(&inspect, "demo").unwrap(), None);
    }

    #[test]
    fn main_pid_from_container_state_returns_none_when_not_running() {
        let container_state = state(Some(false), Some(1234));

        assert_eq!(
            main_pid_from_container_state(&container_state, "demo").unwrap(),
            None
        );
    }

    #[test]
    fn main_pid_from_container_state_returns_pid_for_running_container() {
        let container_state = state(Some(true), Some(4321));

        assert_eq!(
            main_pid_from_container_state(&container_state, "demo").unwrap(),
            Some(4321)
        );
    }

    #[test]
    fn main_pid_from_container_state_rejects_non_positive_pid() {
        let container_state = state(Some(true), Some(0));

        let err = main_pid_from_container_state(&container_state, "demo").unwrap_err();

        assert_eq!(err.to_string(), "Container demo returned invalid PID.");
    }
}
