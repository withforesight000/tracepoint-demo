# tracepoint-demo

`tracepoint-demo` is a Rust + Aya workspace that traces `sys_enter_execve` and prints `execve`
activity for a configurable set of processes.

## Repository layout

- `tracepoint-demo/` builds the userspace daemon.
- `tracepoint-demo-ebpf/` contains the kernel eBPF programs.
- `tracepoint-demo-common/` contains the shared wire types and constants.
- Architecture notes live in `doc/design.md`.
- The userspace crate is split into `infra/`, `gateway/`, and `usecase/`; `doc/design.md`
  explains the ownership of each layer.

## Requirements

- Stable Rust toolchain: `rustup toolchain install stable`
- Nightly Rust toolchain for the embedded eBPF build: `rustup toolchain install nightly --profile minimal --component rust-src`
- BPF linker: `cargo install bpf-linker`
- `aya-tool` for BTF generation: `cargo install aya-tool`
- Root privileges or capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE`

## Build

`tracepoint-demo/build.rs` uses `aya-build` to compile the embedded eBPF crate before the userspace
binary. The final binary includes the BPF object.

That build path currently runs the eBPF crate through the nightly toolchain because `aya-build`
defaults to nightly for `build-std`-based eBPF compilation. Local builds and CI therefore need the
nightly toolchain with `rust-src` installed in addition to stable. A separate
`bpfel-unknown-none` rustup target is not required.

```bash
cargo build --release
```

## Run

Target rules:

- PID and TTY targets are standalone modes. They are not combined with container or systemd targets.
- Container and systemd targets can be combined in the same invocation.
- `--no-watch-children` limits tracing to the selected roots.
- `--all-container-processes` and `--all-systemd-processes` override `--no-watch-children` for
  their respective seeds.

Startup behavior:

- PID and TTY targets wait and retry until matching roots appear.
- Containers wait until they are running.
- If Docker reports a running container with an invalid or missing PID, the daemon defers and
  retries instead of aborting startup.
- Systemd units wait until they are active.
- `--all-systemd-processes` seeds the unit's current PID list at startup, and the startup banner
  shows the resolved PIDs when they are available.
- Container and systemd targets refresh their main PID while the daemon is running.
- `--all-container-processes` also refreshes container state when Docker reports exec activity
  inside the container. A fast cgroup probe seeds the new exec pid, so direct `docker exec` and
  `docker compose exec` launches are picked up.
- Shell builtins such as `cd`, `pwd`, and `echo` do not emit traces because they do not make an
  `execve` syscall. External commands launched from the shell do trace.
- TTY input accepts `/dev/` paths and normalized PTY names such as `pts9`.

Examples:

```bash
sudo cargo run --release -- --pid 1234 --pid 9012
sudo cargo run --release -- 1234 9012 --no-watch-children
sudo cargo run --release -- --tty /dev/pts/9
sudo cargo run --release -- --container my-service --container sidecar
sudo cargo run --release -- --container my-service --systemd-unit sshd.service
sudo cargo run --release -- --systemd-unit sshd.service --systemd-unit user@1000.service --all-systemd-processes
```

## Testing and coverage

Unit tests:

```bash
cargo test -p tracepoint-demo --lib
```

The crate keeps shared test support in `tracepoint-demo/src/test_support.rs` so repeated fakes
stay consistent across policy and orchestration tests.

Static checks:

```bash
cargo clippy -p tracepoint-demo -- -D warnings
cargo fmt --all -- --check
```

Coverage (tarpaulin) focuses on userspace logic and skips eBPF/gateway integration boilerplate:

```bash
cargo tarpaulin --skip-clean -p tracepoint-demo --lib \
  --exclude-files tracepoint-demo-ebpf/src/vmlinux.rs --out Stdout
```

Each line of output looks like:

```text
[0.123456] pid=1234 tid=1234 uid=1000 gid=1000 syscall_id=59 comm="bash" filename="/usr/bin/bash" argv0="bash"
```

Set `RUST_LOG=tracepoint_demo=debug` to show the binary's debug logs.

## Regenerating BTF bindings

`tracepoint-demo-ebpf/src/vmlinux.rs` contains the Aya-generated BTF definitions that the BPF
programs depend on. Regenerate them when the traced kernel types change or when you build against a
different kernel:

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```

## License

- Userspace code: MIT or Apache-2.0, at your option.
- eBPF code: MIT or GPL-2.0, at your option.

See `LICENSE-MIT`, `LICENSE-APACHE`, and `LICENSE-GPL2`.
