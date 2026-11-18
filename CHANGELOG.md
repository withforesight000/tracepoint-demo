# Changelog

## Unreleased

No entries yet.

## Version 0.1.0 - 2026-04-12

### Initial Release

The first public release of `tracepoint-demo` traces `sys_enter_execve` and prints `execve`
activity for processes selected by PID, TTY, Docker container, or systemd unit.

- Ships Linux release artifacts for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.
- Requires root privileges or capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE`.
