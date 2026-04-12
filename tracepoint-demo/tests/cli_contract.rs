use clap::{Parser, error::ErrorKind};

use tracepoint_demo::infra::presentation::cli::CliArgs;

fn parse_error(args: &[&str]) -> clap::Error {
    match CliArgs::try_parse_from(args) {
        Ok(_) => panic!("expected parser error for {args:?}"),
        Err(err) => err,
    }
}

#[test]
fn parses_repeatable_pid_arguments_into_expected_trace_request() {
    let args =
        CliArgs::try_parse_from(["tracepoint-demo", "-p", "10", "-p", "20", "-p", "30"]).unwrap();

    let request = args.into_request();

    assert_eq!(request.pids, vec![10, 20, 30]);
    assert!(request.tty_inputs.is_empty());
    assert!(request.containers.is_empty());
    assert!(request.systemd_units.is_empty());
    assert!(request.watch_children);
}

#[test]
fn rejects_positional_pid_arguments() {
    let err = parse_error(&["tracepoint-demo", "11", "12", "13"]);

    assert_eq!(err.kind().clone(), ErrorKind::UnknownArgument, "{err}");
}

#[test]
fn parses_repeatable_tty_arguments_into_expected_trace_request() {
    let args = CliArgs::try_parse_from(["tracepoint-demo", "--tty", "/dev/pts/3", "--tty", "pts4"])
        .unwrap();

    let request = args.into_request();

    assert!(request.pids.is_empty());
    assert_eq!(
        request.tty_inputs,
        vec!["/dev/pts/3".to_string(), "pts4".to_string()]
    );
    assert!(request.containers.is_empty());
    assert!(request.systemd_units.is_empty());
    assert!(request.watch_children);
}

#[test]
fn parses_repeatable_container_and_systemd_arguments_into_expected_trace_request() {
    let args = CliArgs::try_parse_from([
        "tracepoint-demo",
        "--container",
        "web",
        "--container",
        "sidecar",
        "--all-container-processes",
        "--systemd-unit",
        "demo.service",
        "--systemd-unit",
        "user@1000.service",
        "--all-systemd-processes",
        "--no-watch-children",
    ])
    .unwrap();

    let request = args.into_request();

    assert!(request.pids.is_empty());
    assert!(request.tty_inputs.is_empty());
    assert_eq!(
        request.containers,
        vec!["web".to_string(), "sidecar".to_string()]
    );
    assert!(request.all_container_processes);
    assert_eq!(
        request.systemd_units,
        vec!["demo.service".to_string(), "user@1000.service".to_string()]
    );
    assert!(request.all_systemd_processes);
    assert!(!request.watch_children);
}

#[test]
fn parses_mixed_pid_tty_container_and_systemd_arguments_into_expected_trace_request() {
    let args = CliArgs::try_parse_from([
        "tracepoint-demo",
        "--tty",
        "/dev/pts/3",
        "--pid",
        "10",
        "--pid",
        "20",
        "--container",
        "web",
        "--systemd-unit",
        "sshd.service",
    ])
    .unwrap();

    let request = args.into_request();

    assert_eq!(request.pids, vec![10, 20]);
    assert_eq!(request.tty_inputs, vec!["/dev/pts/3".to_string()]);
    assert_eq!(request.containers, vec!["web".to_string()]);
    assert_eq!(request.systemd_units, vec!["sshd.service".to_string()]);
    assert!(request.watch_children);
}

#[test]
fn rejects_missing_target_arguments() {
    let err = parse_error(&["tracepoint-demo"]);

    assert!(matches!(
        err.kind().clone(),
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand | ErrorKind::MissingRequiredArgument
    ));
    assert!(err.to_string().contains("Usage: tracepoint-demo"));
}

#[test]
fn rejects_all_container_processes_without_container_target() {
    let err = parse_error(&[
        "tracepoint-demo",
        "--all-container-processes",
        "--systemd-unit",
        "demo.service",
    ]);

    assert_eq!(
        err.kind().clone(),
        ErrorKind::MissingRequiredArgument,
        "{err}"
    );
    assert!(
        err.to_string()
            .contains("one or more required arguments were not provided")
    );
}

#[test]
fn rejects_all_systemd_processes_without_systemd_target() {
    let err = parse_error(&[
        "tracepoint-demo",
        "--all-systemd-processes",
        "--container",
        "web",
    ]);

    assert_eq!(
        err.kind().clone(),
        ErrorKind::MissingRequiredArgument,
        "{err}"
    );
    assert!(
        err.to_string()
            .contains("one or more required arguments were not provided")
    );
}
