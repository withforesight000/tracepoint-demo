use std::{collections::HashSet, time::Duration};

use crate::usecase::port::{ProcessSeedPort, StatusReporter, WaitPort};

pub async fn wait_pid_or_tty_targets<
    TReporter: StatusReporter + ?Sized,
    TWait: WaitPort + ?Sized,
>(
    process_seed: &mut dyn ProcessSeedPort,
    pids: &[u32],
    tty_filters: &HashSet<String>,
    tty_inputs: &[String],
    watch_flags: u32,
    reporter: &mut TReporter,
    wait_port: &mut TWait,
) -> anyhow::Result<Vec<u32>> {
    let mut announced = false;
    loop {
        let roots = process_seed.seed_from_task_iter(pids, tty_filters, watch_flags)?;
        if !roots.is_empty() {
            return Ok(roots);
        }

        if !announced {
            reporter.warn(format!(
                "No processes matched PID(s) {:?} or tty(s) {:?}. Waiting for a match...",
                pids, tty_inputs
            ));
            announced = true;
        }

        wait_port
            .wait(
                Duration::from_secs(1),
                "Interrupted while waiting for matching PID/TTY targets.".to_string(),
            )
            .await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usecase::port::BoxFuture;

    #[derive(Default)]
    struct FakeProcessSeedPort {
        results: Vec<anyhow::Result<Vec<u32>>>,
        calls: Vec<(Vec<u32>, HashSet<String>, u32)>,
    }

    impl ProcessSeedPort for FakeProcessSeedPort {
        fn seed_from_task_iter(
            &mut self,
            pid_roots: &[u32],
            tty_filters: &HashSet<String>,
            watch_flags: u32,
        ) -> anyhow::Result<Vec<u32>> {
            self.calls
                .push((pid_roots.to_vec(), tty_filters.clone(), watch_flags));
            self.results.remove(0)
        }

        fn seed_direct(&mut self, _pids: &[u32], _flags: u32) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeReporter {
        warnings: Vec<String>,
    }

    impl StatusReporter for FakeReporter {
        fn info(&mut self, _message: String) {}

        fn warn(&mut self, message: String) {
            self.warnings.push(message);
        }
    }

    #[derive(Default)]
    struct FakeWaitPort {
        calls: Vec<(Duration, String)>,
        fail_on_call: Option<usize>,
    }

    impl WaitPort for FakeWaitPort {
        fn wait<'a>(
            &'a mut self,
            duration: Duration,
            interrupted_message: String,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                self.calls.push((duration, interrupted_message));
                if self
                    .fail_on_call
                    .is_some_and(|fail_on_call| self.calls.len() >= fail_on_call)
                {
                    return Err(anyhow::anyhow!("wait interrupted"));
                }
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn wait_pid_or_tty_targets_returns_immediately_when_roots_are_found() {
        let mut process_seed = FakeProcessSeedPort {
            results: vec![Ok(vec![11, 22])],
            calls: Vec::new(),
        };
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

        let roots = wait_pid_or_tty_targets(
            &mut process_seed,
            &[11],
            &HashSet::from(["pts1".to_string()]),
            &["pts1".to_string()],
            0x2,
            &mut reporter,
            &mut wait_port,
        )
        .await
        .unwrap();

        assert_eq!(roots, vec![11, 22]);
        assert!(reporter.warnings.is_empty());
        assert!(wait_port.calls.is_empty());
    }

    #[tokio::test]
    async fn wait_pid_or_tty_targets_warns_once_before_retrying() {
        let mut process_seed = FakeProcessSeedPort {
            results: vec![Ok(Vec::new()), Ok(Vec::new()), Ok(vec![33])],
            calls: Vec::new(),
        };
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort::default();

        let roots = wait_pid_or_tty_targets(
            &mut process_seed,
            &[33],
            &HashSet::new(),
            &["pts2".to_string()],
            0x4,
            &mut reporter,
            &mut wait_port,
        )
        .await
        .unwrap();

        assert_eq!(roots, vec![33]);
        assert_eq!(reporter.warnings.len(), 1);
        assert_eq!(wait_port.calls.len(), 2);
    }

    #[tokio::test]
    async fn wait_pid_or_tty_targets_propagates_wait_errors() {
        let mut process_seed = FakeProcessSeedPort {
            results: vec![Ok(Vec::new())],
            calls: Vec::new(),
        };
        let mut reporter = FakeReporter::default();
        let mut wait_port = FakeWaitPort {
            calls: Vec::new(),
            fail_on_call: Some(1),
        };

        let err = wait_pid_or_tty_targets(
            &mut process_seed,
            &[44],
            &HashSet::new(),
            &["pts3".to_string()],
            0x8,
            &mut reporter,
            &mut wait_port,
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "wait interrupted");
        assert_eq!(reporter.warnings.len(), 1);
    }
}
