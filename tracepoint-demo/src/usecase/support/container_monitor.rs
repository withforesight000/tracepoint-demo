use tokio::sync::mpsc;

use super::runtime_update::RuntimeUpdate;

pub(crate) trait ContainerMonitorBackend {
    async fn query_main_pid(&mut self, name_or_id: &str) -> anyhow::Result<Option<u32>>;

    async fn wait_for_next_check(&mut self, name_or_id: &str) -> anyhow::Result<()>;
}

pub(crate) async fn monitor_container_runtime_with_backend<TBackend: ContainerMonitorBackend>(
    backend: &mut TBackend,
    name_or_id: &str,
    tx: &mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    let mut current_pid = backend.query_main_pid(name_or_id).await?;
    let _ = tx.send(RuntimeUpdate::ContainerPid {
        index,
        pid: current_pid,
    });

    loop {
        backend.wait_for_next_check(name_or_id).await?;

        let next_pid = backend.query_main_pid(name_or_id).await?;
        if next_pid != current_pid {
            current_pid = next_pid;
            let _ = tx.send(RuntimeUpdate::ContainerPid {
                index,
                pid: next_pid,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeContainerMonitorBackend {
        pids: VecDeque<anyhow::Result<Option<u32>>>,
        waits: VecDeque<anyhow::Result<()>>,
    }

    impl ContainerMonitorBackend for FakeContainerMonitorBackend {
        async fn query_main_pid(&mut self, _name_or_id: &str) -> anyhow::Result<Option<u32>> {
            self.pids
                .pop_front()
                .unwrap_or_else(|| Err(anyhow::anyhow!("missing pid response")))
        }

        async fn wait_for_next_check(&mut self, _name_or_id: &str) -> anyhow::Result<()> {
            self.waits
                .pop_front()
                .unwrap_or_else(|| Err(anyhow::anyhow!("missing wait response")))
        }
    }

    #[tokio::test]
    async fn monitor_container_runtime_with_backend_emits_initial_and_changed_pid_updates() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut backend = FakeContainerMonitorBackend {
            pids: VecDeque::from([Ok(Some(10)), Ok(Some(10)), Ok(Some(20))]),
            waits: VecDeque::from([Ok(()), Ok(()), Err(anyhow::anyhow!("stop monitoring"))]),
        };

        let err = monitor_container_runtime_with_backend(&mut backend, "web", &tx, 3)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "stop monitoring");
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::ContainerPid {
                index: 3,
                pid: Some(10),
            })
        ));
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::ContainerPid {
                index: 3,
                pid: Some(20),
            })
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn monitor_container_runtime_with_backend_skips_duplicate_pid_updates() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut backend = FakeContainerMonitorBackend {
            pids: VecDeque::from([Ok(Some(10)), Ok(Some(10))]),
            waits: VecDeque::from([Ok(()), Err(anyhow::anyhow!("stop monitoring"))]),
        };

        let err = monitor_container_runtime_with_backend(&mut backend, "web", &tx, 1)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "stop monitoring");
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::ContainerPid {
                index: 1,
                pid: Some(10),
            })
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn monitor_container_runtime_with_backend_propagates_initial_query_errors() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut backend = FakeContainerMonitorBackend {
            pids: VecDeque::from([Err(anyhow::anyhow!("inspect failed"))]),
            waits: VecDeque::new(),
        };

        let err = monitor_container_runtime_with_backend(&mut backend, "web", &tx, 0)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "inspect failed");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn monitor_container_runtime_with_backend_propagates_query_errors_after_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut backend = FakeContainerMonitorBackend {
            pids: VecDeque::from([Ok(Some(10)), Err(anyhow::anyhow!("inspect failed"))]),
            waits: VecDeque::from([Ok(())]),
        };

        let err = monitor_container_runtime_with_backend(&mut backend, "web", &tx, 4)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "inspect failed");
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::ContainerPid {
                index: 4,
                pid: Some(10),
            })
        ));
        assert!(rx.try_recv().is_err());
    }
}
