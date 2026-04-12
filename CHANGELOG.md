# Changelog

## Unreleased

- Nothing yet.

## Version 0.1.0 - 2026-04-12

### Initial Release

- First public release of `tracepoint-demo`.
- Traces `sys_enter_execve` and prints `execve` activity for selected processes.
- Supports PID, TTY, Docker container, and systemd unit target selection.
- Ships Linux release artifacts for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.
- Requires root privileges or capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE`.
