# tracepoint-demo operations

See the [README](../README.md) for installation and a first run.

## Build and toolchain

Install stable Rust for the daemon and nightly Rust with `rust-src` for the embedded eBPF
programs. In local builds and CI, `tracepoint-demo/build.rs` calls `aya-build` to compile the
eBPF crate with nightly and `build-std`. A separate `bpfel-unknown-none` rustup target is
unnecessary.

## Target selection

Combine repeated `-p` or `--pid` options with `--tty`, `--container`, or `--systemd-unit` in the
same invocation. Docker and systemd targets can also run together. TTY filters accept paths such as
`/dev/pts/9` and names such as `pts9`.

By default, tracing follows descendants. `--no-watch-children` limits tracing to the selected
roots. `--all-container-processes` and `--all-systemd-processes` override that limit for their
respective targets.

## When tracing starts

The daemon looks for PID and TTY roots at startup. If those are the only targets and the first
lookup finds no roots, it retries until a match appears.

The daemon seeds containers whose main PIDs are available at startup. If a container is stopped or
Docker reports a running container without a valid PID, tracing that container waits for a valid
PID. The monitor retries while the daemon runs.

The daemon starts without waiting for systemd units to become active. It can start tracing a unit
as soon as systemd exposes a usable `MainPID`, including during activation.

With `--all-container-processes`, the daemon seeds the current container processes when it has a
valid main PID. With `--all-systemd-processes`, it can also seed a running unit's processes
when the unit has no `MainPID`.

## What changes while tracing

Container and systemd monitors refresh the main PID and report state changes, including replacement
PIDs after a restart or recreation.

With `--all-container-processes`, the Docker monitor looks for new processes from `docker exec`
and `docker compose exec`. It probes the container cgroup on `exec_create` and asks Docker for the
exec PID on `exec_start` when the event supplies an exec ID. The first `execve` can happen before
the daemon seeds that PID. Commands launched from a watched shell can inherit its watch state,
which persists when a helper thread exits during the handoff.

Shell builtins such as `cd`, `pwd`, and `echo` do not call `execve` and produce no trace.
External commands launched from the shell do call `execve`.

## Startup banner

When the banner has a `PIDs:` list, it shows explicit PID inputs as supplied and groups resolved
TTY, Docker, and systemd PIDs by target. With either all-processes option, seeded PIDs appear in
the corresponding runtime group.

| Source | Example |
| --- | --- |
| Explicit PIDs | `pid:(pid=1111, 2222)` |
| TTY | `tty:/dev/pts/3:(pid=3333, 3334)` |
| Docker | `container:my-service:(main=1234)` |
| systemd | `systemd:sshd.service:(main=5678, pid=6789)` |

The banner adds `(all-container-processes=on)` and `(all-systemd-processes=on)` when the
corresponding options are enabled.

## Output and logging

An exec event produces a line like this.

```text
[0.123456] pid=1234 tid=1234 uid=1000 gid=1000 syscall_id=59 comm="bash" filename="/usr/bin/bash" argv="bash -lc ls -la"
```

`pid` is the thread-group ID, which most tools display as the process ID. `tid` is the kernel
thread ID.

`argv` shows up to the first five entries in the `execve` argument vector, including `argv[0]`.
It joins the nonempty entries with spaces. The example captures `ls -la` as part of a shell
command.

Set `RUST_LOG=tracepoint_demo=debug` to show the binary's debug logs.

## Examples

```bash
sudo cargo run --release -- --pid 1234 --pid 9012
sudo cargo run --release -- -p 1234 -p 9012 --no-watch-children
sudo cargo run --release -- --tty /dev/pts/9 --systemd-unit sshd.service
sudo cargo run --release -- --container my-service --systemd-unit sshd.service
sudo cargo run --release -- --systemd-unit sshd.service --systemd-unit user@1000.service --all-systemd-processes
```

## Testing and coverage

```bash
cargo test -p tracepoint-demo
cargo test -p tracepoint-demo-ebpf --lib
cargo clippy -- -D warnings
cargo fmt --all -- --check
cargo tarpaulin --skip-clean --lib \
  --exclude-files tracepoint-demo-ebpf/src/vmlinux.rs --out Stdout
```

### eBPF verifier smoke test

Build the smoke test on the Linux host whose kernel you want to check.

```bash
cargo test -p tracepoint-demo --test ebpf_verifier_smoke --no-run
```

Copy the executable path from Cargo's output. Substitute it for the placeholder below.

```bash
sudo env TRACEPOINT_DEMO_EBPF_SMOKE_TEST=1 /path/to/ebpf_verifier_smoke --nocapture
```

The test calls `program.load()` and surfaces verifier rejections. Run this load check manually.
GitHub Actions CI runs the tests without enabling the smoke check.

## Regenerating BTF bindings

`tracepoint-demo-ebpf/src/vmlinux.rs` contains the Aya-generated BTF definitions that the BPF
programs depend on. Regenerate them when the traced kernel types change or when you build against a
different kernel.

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```

## Releases

Push a tag in `major.minor.patch` format to start CI. If CI passes and GitHub has no release for
the tag, CI dispatches the release workflow.

```bash
git tag 0.1.0
git push origin 0.1.0
```

The release workflow builds Linux artifacts for `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` on GitHub-hosted Ubuntu 22.04 runners, then publishes them to GitHub
Releases. That baseline keeps the binaries usable on machines with older glibc than an Ubuntu
24.04 build would require.

For a manual release via `workflow_dispatch`, select the release tag as the workflow ref and pass
the same value in the `tag` input.

Release notes come from [CHANGELOG.md](../CHANGELOG.md). The 0.1.0 entry is titled
`Initial Release`. Add notes for later releases under the corresponding version heading.
