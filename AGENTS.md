# AGENTS.md

## Read first

- [README](README.md) covers usage, target combinations, builds, and example output.
- The [layered architecture skill](.agents/skills/tracepoint-demo-layered-architecture/SKILL.md)
  defines layer ownership, dependency rules, and where to make changes.
- The [eBPF implementation skill](.agents/skills/tracepoint-demo-ebpf-implementation/SKILL.md)
  covers kernel code, the shared ABI, and where to make changes in `tracepoint-demo-ebpf/`.
- [Design notes](doc/design.md) link to the rationale, module maps, and runtime flow.

Use the [layered architecture](.github/skills/tracepoint-demo-layered-architecture/SKILL.md) and
[eBPF implementation](.github/skills/tracepoint-demo-ebpf-implementation/SKILL.md) Copilot shims
only if your agent cannot discover skills under `.agents/skills`.

## Project overview

`tracepoint-demo` is a Rust daemon that uses Aya to attach to `sys_enter_execve`. It reports
`execve` calls for processes selected by PID, TTY, Docker container, or systemd unit.

## Repository layout

- `tracepoint-demo/` is the userspace daemon.
- `tracepoint-demo-ebpf/` contains the no_std kernel programs and generated `vmlinux.rs`.
- `tracepoint-demo-common/` contains the shared event types, map names, and flag constants.

## Working rules

- Keep `tracepoint-demo/src/main.rs` as a small entry point. Compose dependencies in
  `infra/bootstrap.rs`.
- Keep CLI parsing, startup/composition, output formatting, runtime-loop wiring, and concrete client initialization in `infra/`.
- Keep user-intent flows and watch-state coordination in `usecase/`.
- Keep eBPF, procfs/cgroup, Docker, and systemd I/O in `gateway/`.
- Treat `tracepoint-demo-common` as the ABI boundary between userspace and eBPF.
- If code behavior changes, update `README.md` for users and `doc/design.md` for architecture notes in the same change.

## Shared types and maps

- `ExecEvent`: event payload shared between eBPF and userspace.
- `TaskRel`: task-tree snapshot used during startup seeding.
- `WATCH_PIDS`: userspace-managed root watch set.
- `PROC_STATE`: kernel-side per-PID cache.
- `PROC_FLAG_WATCH_SELF`: watch the root PID's own execs.
- `PROC_FLAG_WATCH_CHILDREN`: also watch descendants.

## Build and verification

Install nightly with `rust-src` before building `tracepoint-demo` locally or in CI. The userspace
build uses it to compile the embedded eBPF program.

```bash
rustup toolchain install nightly --profile minimal --component rust-src
```

Run the workspace build and checks on Linux for the host target. `tracepoint-demo/build.rs` builds the
embedded `bpfel-unknown-none` target from source via `aya-build` and `build-std`.

```bash
cargo build --release
cargo clippy --all-targets
cargo fmt --check
cargo test
```

## Tests and coverage (recommended)

When behavior changes, cover edge cases and state transitions. Prefer scenario or integration tests
for monitor sequences such as a runtime target restart or a `MainPID` update before a unit becomes
active.

Unit tests and lints:

```bash
cargo test -p tracepoint-demo
cargo test -p tracepoint-demo-ebpf --lib
cargo clippy -- -D warnings
cargo fmt --all -- --check
```

Coverage:

```bash
cargo tarpaulin --skip-clean --lib \
  --exclude-files tracepoint-demo-ebpf/src/vmlinux.rs --out Stdout
```

## BTF bindings

When the traced kernel types change or the target kernel changes, regenerate `tracepoint-demo-ebpf/src/vmlinux.rs`:

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```
