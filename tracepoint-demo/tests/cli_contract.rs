use clap::Parser;

use tracepoint_demo::infra::presentation::cli::CliArgs;

#[test]
fn parses_cli_into_expected_trace_request() {
    let args = CliArgs::try_parse_from([
        "tracepoint-demo",
        "--container",
        "web",
        "--all-container-processes",
        "--systemd-unit",
        "demo.service",
        "--all-systemd-processes",
        "--no-watch-children",
    ])
    .unwrap();

    let request = args.into_request();

    assert!(request.pids.is_empty());
    assert_eq!(request.containers, vec!["web".to_string()]);
    assert!(request.all_container_processes);
    assert_eq!(request.systemd_units, vec!["demo.service".to_string()]);
    assert!(request.all_systemd_processes);
    assert!(!request.watch_children);
}
