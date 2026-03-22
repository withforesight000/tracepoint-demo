use bollard::{Docker, errors::Error as BollardError};

pub async fn query_container_main_pid(
    docker: &Docker,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    match docker.inspect_container(name_or_id, None).await {
        Ok(inspect) => {
            if let Some(state) = inspect.state {
                if state.running.unwrap_or(false) {
                    let pid = state.pid.unwrap_or(0);
                    if pid <= 0 {
                        return Err(anyhow::anyhow!(
                            "Container {} returned invalid PID.",
                            name_or_id
                        ));
                    }
                    return Ok(Some(pid as u32));
                }
            }
            Ok(None)
        }
        Err(err) => match err {
            BollardError::DockerResponseServerError { status_code, .. } if status_code == 404 => {
                Ok(None)
            }
            _ => Err(err.into()),
        },
    }
}
