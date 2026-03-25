use std::time::Duration;

use tokio::{select, signal, time::sleep};

use crate::usecase::port::{BoxFuture, WaitPort};

pub struct SignalAwareWaitPort;

impl WaitPort for SignalAwareWaitPort {
    fn wait<'a>(
        &'a mut self,
        duration: Duration,
        interrupted_message: String,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            select! {
                _ = sleep(duration) => Ok(()),
                _ = signal::ctrl_c() => Err(anyhow::anyhow!(interrupted_message)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_returns_after_sleep_when_not_interrupted() {
        let mut wait_port = SignalAwareWaitPort;

        wait_port
            .wait(Duration::from_millis(0), "interrupted".to_string())
            .await
            .unwrap();
    }
}
