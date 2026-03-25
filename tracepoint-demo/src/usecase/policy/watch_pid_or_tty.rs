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
    use std::{collections::VecDeque, sync::{Arc, Mutex}};

    use super::*;
    use crate::test_support::{boxed_future, MockProcessSeedPort, MockStatusReporter, MockWaitPort};

    #[tokio::test]
    async fn wait_pid_or_tty_targets_returns_immediately_when_roots_are_found() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_from_task_iter()
            .times(1)
            .returning(|pid_roots, tty_filters, watch_flags| {
                assert_eq!(pid_roots, [11]);
                assert_eq!(tty_filters, &HashSet::from(["pts1".to_string()]));
                assert_eq!(watch_flags, 0x2);
                Ok(vec![11, 22])
            });
        let mut reporter = MockStatusReporter::new();
        let mut wait_port = MockWaitPort::new();

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
    }

    #[tokio::test]
    async fn wait_pid_or_tty_targets_warns_once_before_retrying() {
        let results = Arc::new(Mutex::new(VecDeque::from([
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(vec![33]),
        ])));
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_from_task_iter()
            .times(3)
            .returning({
                let results = Arc::clone(&results);
                move |pid_roots, tty_filters, watch_flags| {
                    assert_eq!(pid_roots, [33]);
                    assert!(tty_filters.is_empty());
                    assert_eq!(watch_flags, 0x4);
                    results.lock().unwrap().pop_front().unwrap()
                }
            });
        let mut reporter = MockStatusReporter::new();
        reporter
            .expect_warn()
            .times(1)
            .withf(|message| message.contains("No processes matched") && message.contains("pts2"))
            .return_const(());
        let mut wait_port = MockWaitPort::new();
        wait_port
            .expect_wait()
            .times(2)
            .withf(|duration, interrupted_message| {
                *duration == Duration::from_secs(1)
                    && interrupted_message == "Interrupted while waiting for matching PID/TTY targets."
            })
            .returning(|_, _| boxed_future(Ok(())));

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
    }

    #[tokio::test]
    async fn wait_pid_or_tty_targets_propagates_wait_errors() {
        let mut process_seed = MockProcessSeedPort::new();
        process_seed
            .expect_seed_from_task_iter()
            .times(1)
            .returning(|pid_roots, tty_filters, watch_flags| {
                assert_eq!(pid_roots, [44]);
                assert!(tty_filters.is_empty());
                assert_eq!(watch_flags, 0x8);
                Ok(Vec::new())
            });
        let mut reporter = MockStatusReporter::new();
        reporter.expect_warn().times(1).return_const(());
        let mut wait_port = MockWaitPort::new();
        wait_port
            .expect_wait()
            .times(1)
            .withf(|duration, interrupted_message| {
                *duration == Duration::from_secs(1)
                    && interrupted_message == "Interrupted while waiting for matching PID/TTY targets."
            })
            .returning(|_, _| boxed_future(Err(anyhow::anyhow!("wait interrupted"))));

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
    }
}
