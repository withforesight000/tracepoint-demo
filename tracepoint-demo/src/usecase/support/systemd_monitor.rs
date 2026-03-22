use std::{future::Future, pin::Pin};

use tokio::sync::mpsc;

use super::runtime_update::RuntimeUpdate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SystemdMonitorStatus {
    pub pid: Option<u32>,
    pub running: bool,
}

pub(crate) async fn relay_systemd_status_updates<TState, TNext>(
    initial_status: SystemdMonitorStatus,
    mut state: TState,
    mut next_status: TNext,
    tx: &mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()>
where
    TState: Send,
    TNext: Send,
    TNext: for<'a> FnMut(
        &'a mut TState,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<SystemdMonitorStatus>>> + Send + 'a>>,
{
    let mut current = initial_status;
    let _ = tx.send(RuntimeUpdate::SystemdStatus {
        index,
        pid: current.pid,
        running: current.running,
    });

    loop {
        let Some(next) = next_status(&mut state).await? else {
            let _ = tx.send(RuntimeUpdate::SystemdStatus {
                index,
                pid: None,
                running: false,
            });
            return Ok(());
        };

        if next != current {
            current = next;
            let _ = tx.send(RuntimeUpdate::SystemdStatus {
                index,
                pid: next.pid,
                running: next.running,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::{Arc, Mutex}};

    #[tokio::test]
    async fn relay_systemd_status_updates_emits_changes_and_stop_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let responses = Arc::new(Mutex::new(VecDeque::from([
            Ok(Some(SystemdMonitorStatus {
                pid: Some(10),
                running: true,
            })),
            Ok(Some(SystemdMonitorStatus {
                pid: Some(20),
                running: true,
            })),
            Ok(None),
        ])));

        relay_systemd_status_updates(
            SystemdMonitorStatus {
                pid: Some(10),
                running: true,
            },
            (),
            |_| {
                let responses = Arc::clone(&responses);
                Box::pin(async move {
                    responses
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| Err(anyhow::anyhow!("missing status response")))
                })
            },
            &tx,
            2,
        )
        .await
        .unwrap();

        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::SystemdStatus {
                index: 2,
                pid: Some(10),
                running: true,
            })
        ));
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::SystemdStatus {
                index: 2,
                pid: Some(20),
                running: true,
            })
        ));
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::SystemdStatus {
                index: 2,
                pid: None,
                running: false,
            })
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn relay_systemd_status_updates_skips_duplicate_statuses() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let responses = Arc::new(Mutex::new(VecDeque::from([
            Ok(Some(SystemdMonitorStatus {
                pid: Some(10),
                running: true,
            })),
            Ok(None),
        ])));

        relay_systemd_status_updates(
            SystemdMonitorStatus {
                pid: Some(10),
                running: true,
            },
            (),
            |_| {
                let responses = Arc::clone(&responses);
                Box::pin(async move {
                    responses
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| Err(anyhow::anyhow!("missing status response")))
                })
            },
            &tx,
            1,
        )
        .await
        .unwrap();

        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::SystemdStatus {
                index: 1,
                pid: Some(10),
                running: true,
            })
        ));
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::SystemdStatus {
                index: 1,
                pid: None,
                running: false,
            })
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn relay_systemd_status_updates_propagates_stream_errors() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let responses = Arc::new(Mutex::new(VecDeque::from([Err(anyhow::anyhow!(
            "stream failed"
        ))])));

        let err = relay_systemd_status_updates(
            SystemdMonitorStatus {
                pid: Some(10),
                running: true,
            },
            (),
            |_| {
                let responses = Arc::clone(&responses);
                Box::pin(async move {
                    responses
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| Err(anyhow::anyhow!("missing status response")))
                })
            },
            &tx,
            4,
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "stream failed");
        assert!(matches!(
            rx.recv().await,
            Some(RuntimeUpdate::SystemdStatus {
                index: 4,
                pid: Some(10),
                running: true,
            })
        ));
        assert!(rx.try_recv().is_err());
    }
}
