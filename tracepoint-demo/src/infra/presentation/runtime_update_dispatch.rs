use crate::usecase::port::RuntimeUpdate;

pub(crate) trait RuntimeUpdateHandler {
    async fn apply_container_pid(
        &mut self,
        index: usize,
        pid: Option<u32>,
        force_refresh: bool,
    ) -> anyhow::Result<()>;

    async fn apply_systemd_status(
        &mut self,
        index: usize,
        pid: Option<u32>,
        running: bool,
    ) -> anyhow::Result<()>;
}

pub(crate) async fn handle_runtime_update<H: RuntimeUpdateHandler>(
    handler: &mut H,
    maybe_update: Option<RuntimeUpdate>,
) -> anyhow::Result<bool> {
    match maybe_update {
        Some(RuntimeUpdate::ContainerPid {
            index,
            pid,
            force_refresh,
        }) => {
            handler
                .apply_container_pid(index, pid, force_refresh)
                .await?;
            Ok(true)
        }
        Some(RuntimeUpdate::SystemdStatus {
            index,
            pid,
            running,
        }) => {
            handler.apply_systemd_status(index, pid, running).await?;
            Ok(true)
        }
        Some(RuntimeUpdate::MonitorError { label, error }) => {
            Err(anyhow::anyhow!("{label}: {error}"))
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeRuntimeUpdateHandler {
        container_calls: Vec<(usize, Option<u32>)>,
        systemd_calls: Vec<(usize, Option<u32>, bool)>,
        container_error: Option<&'static str>,
        systemd_error: Option<&'static str>,
    }

    impl RuntimeUpdateHandler for FakeRuntimeUpdateHandler {
        async fn apply_container_pid(
            &mut self,
            index: usize,
            pid: Option<u32>,
            _force_refresh: bool,
        ) -> anyhow::Result<()> {
            if let Some(message) = self.container_error {
                return Err(anyhow::anyhow!(message));
            }
            self.container_calls.push((index, pid));
            Ok(())
        }

        async fn apply_systemd_status(
            &mut self,
            index: usize,
            pid: Option<u32>,
            running: bool,
        ) -> anyhow::Result<()> {
            if let Some(message) = self.systemd_error {
                return Err(anyhow::anyhow!(message));
            }
            self.systemd_calls.push((index, pid, running));
            Ok(())
        }
    }

    #[tokio::test]
    async fn handle_runtime_update_dispatches_container_updates() {
        let mut handler = FakeRuntimeUpdateHandler::default();

        let keep_running = handle_runtime_update(
            &mut handler,
            Some(RuntimeUpdate::ContainerPid {
                index: 2,
                pid: Some(42),
                force_refresh: false,
            }),
        )
        .await
        .unwrap();

        assert!(keep_running);
        assert_eq!(handler.container_calls, vec![(2, Some(42))]);
        assert!(handler.systemd_calls.is_empty());
    }

    #[tokio::test]
    async fn handle_runtime_update_dispatches_systemd_updates() {
        let mut handler = FakeRuntimeUpdateHandler::default();

        let keep_running = handle_runtime_update(
            &mut handler,
            Some(RuntimeUpdate::SystemdStatus {
                index: 1,
                pid: Some(7),
                running: true,
            }),
        )
        .await
        .unwrap();

        assert!(keep_running);
        assert_eq!(handler.systemd_calls, vec![(1, Some(7), true)]);
        assert!(handler.container_calls.is_empty());
    }

    #[tokio::test]
    async fn handle_runtime_update_reports_monitor_errors() {
        let mut handler = FakeRuntimeUpdateHandler::default();

        let err = handle_runtime_update(
            &mut handler,
            Some(RuntimeUpdate::MonitorError {
                label: "container api".to_string(),
                error: "stream failed".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "container api: stream failed");
    }

    #[tokio::test]
    async fn handle_runtime_update_stops_when_channel_is_closed() {
        let mut handler = FakeRuntimeUpdateHandler::default();

        let keep_running = handle_runtime_update(&mut handler, None).await.unwrap();

        assert!(!keep_running);
        assert!(handler.container_calls.is_empty());
        assert!(handler.systemd_calls.is_empty());
    }

    #[tokio::test]
    async fn handle_runtime_update_propagates_handler_errors() {
        let mut handler = FakeRuntimeUpdateHandler {
            container_error: Some("refresh failed"),
            ..Default::default()
        };

        let err = handle_runtime_update(
            &mut handler,
            Some(RuntimeUpdate::ContainerPid {
                index: 0,
                pid: Some(11),
                force_refresh: false,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "refresh failed");
    }
}
