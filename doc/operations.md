# tracepoint-demo operations

This note collects runtime and maintenance details that are too specific for `README.md`.

## Build and toolchain

`tracepoint-demo/build.rs` uses `aya-build` to compile the embedded eBPF crate before the userspace
binary. The build path currently runs the eBPF crate through the nightly toolchain because
`aya-build` defaults to nightly for `build-std`-based eBPF compilation. Local builds and CI
therefore need the nightly toolchain with `rust-src` installed in addition to stable Rust. A
separate `bpfel-unknown-none` rustup target is not required.

## Target selection

- PID inputs and TTY filters are additive. You can combine repeated `-p/--pid` arguments and
  `--tty` in the same invocation, and you can also mix them with container or systemd targets.
- Container and systemd targets can be combined in the same invocation.
- `--no-watch-children` limits tracing to the selected roots.
- `--all-container-processes` and `--all-systemd-processes` override `--no-watch-children` for
  their respective seeds.

## Startup behavior

- PID and TTY targets wait and retry until matching roots appear.
- Containers wait until they are running.
- If Docker reports a running container with an invalid or missing PID, the daemon defers and
  retries instead of aborting startup.
- Systemd units do not block startup; the daemon starts monitoring immediately and picks up
  `MainPID` transitions even before the unit reports `active`.
- `--all-systemd-processes` and `--all-container-processes` seed the runtime target's current PID
  list at startup, and the startup banner folds those resolved PIDs into the main grouped
  `PIDs:` list.
- Startup banner segments are grouped by source. Explicit `-p/--pid` inputs appear as
  `pid:(pid=1111, 2222)`, TTY roots appear as `tty:/dev/pts/3:(pid=3333, 3334)`, and runtime
  targets keep their source labels such as `container:my-service:(main=1234)` or
  `systemd:sshd.service:(main=5678, pid=6789)`.
- `--all-container-processes` and `--all-systemd-processes` appear in the banner suffix as
  `(all-container-processes=on)` and `(all-systemd-processes=on)` when enabled.
- Container and systemd targets refresh their main PID while the daemon is running.
- Container and systemd targets print runtime state-change notices, including resolved replacement
  PIDs after restarts or recreation.
- For systemd targets, runtime monitoring also covers services started after `tracepoint-demo`
  itself, so the unit's early startup `execve` activity is still traced once systemd exposes a
  `MainPID`.
- `--all-container-processes` also refreshes container state when Docker reports exec activity
  inside the container. A fast cgroup probe seeds the new exec pid, and child commands launched
  from that shell inherit watch state at exec time, so direct `docker exec`, `docker compose exec`,
  and later commands from that shell are picked up. The watch cache is kept at process granularity,
  so helper-thread exits during the `docker exec` handoff do not drop that shell state.
- Shell builtins such as `cd`, `pwd`, and `echo` do not emit traces because they do not make an
  `execve` syscall. External commands launched from the shell do.
- TTY input accepts `/dev/` paths and normalized PTY names such as `pts9`.

## Output and logging

Each line of output looks like:

```text
[0.123456] pid=1234 tid=1234 uid=1000 gid=1000 syscall_id=59 comm="bash" filename="/usr/bin/bash" argv="bash -lc ls -la"
```

`argv` includes the first five captured `execve` arguments, so flag sequences such as `ls -la`
stay visible in the trace output.

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

To catch eBPF verifier regressions, run the optional smoke test on a kernel that can load the
programs:

```bash
TRACEPOINT_DEMO_EBPF_SMOKE_TEST=1 sudo cargo test -p tracepoint-demo --test ebpf_verifier_smoke
```

This exercises the real `program.load()` path, so any verifier rejection will surface there rather
than only at daemon startup.

This is a manual check and is not part of GitHub Actions CI.

## Regenerating BTF bindings

`tracepoint-demo-ebpf/src/vmlinux.rs` contains the Aya-generated BTF definitions that the BPF
programs depend on. Regenerate them when the traced kernel types change or when you build against a
different kernel:

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```

## Releases

Releases are cut from git tags. Push a semver tag such as `0.1.0`; the CI workflow runs first, and
if it succeeds it dispatches the GitHub release workflow:

```bash
git tag 0.1.0
git push origin 0.1.0
```

The release workflow builds Linux artifacts for `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` on GitHub-hosted Ubuntu 22.04 runners, then publishes them to GitHub
Releases. That baseline keeps the binaries usable on machines with older glibc than an Ubuntu
24.04 build would require. If you need to rerun the release step directly, the workflow is also
available as a manual `workflow_dispatch` with a `tag` input.

Release notes are generated from `CHANGELOG.md`. The 0.1.0 entry is intentionally labeled
`Initial Release`, and later releases can add version-specific notes under the matching heading.
