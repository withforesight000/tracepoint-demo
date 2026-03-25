# AGENTS.md

This file is a guide for AI agents operating on this repository.

## Read first

- `README.md` for user-facing behavior, build, run, and output examples.
- `doc/design.md` for the current user-space layering and the reason it exists.

## Project overview

`tracepoint-demo` is an eBPF tracing daemon in Rust using Aya. It attaches to `sys_enter_execve`
and reports `execve` calls for a configurable set of processes.
Targets can be selected by PID, TTY, Docker container, or systemd unit.

## Repository layout

- `tracepoint-demo/` is the userspace daemon.
- `tracepoint-demo-ebpf/` contains the no_std kernel programs and generated `vmlinux.rs`.
- `tracepoint-demo-common/` contains the shared event types, map names, and flag constants.

## Working rules

- Keep `tracepoint-demo/src/main.rs` as a composition root.
- Keep CLI parsing, startup/composition, output formatting, runtime-loop wiring, and concrete client initialization in `infra/`.
- Keep user-intent flows and watch-state coordination in `usecase/`.
- Keep eBPF, procfs/cgroup, Docker, and systemd I/O in `gateway/`.
- Treat `tracepoint-demo-common` as the ABI boundary between userspace and eBPF.
- If code behavior changes, update `README.md` for users and `doc/design.md` for architecture notes in the same change.

## Architecture guardrails

- Follow the Dependency Rule strictly: inner layers know ports and request DTOs, not outer-layer module names or concrete library types.
- `usecase/` must not import `crate::infra::*` and must not depend directly on concrete external client types such as `bollard::Docker` or `zbus::Connection`.
- `gateway/` must not depend on `infra/`. If a helper is needed by both, move it to `usecase/` or another inner/shared seam only when that dependency direction still makes sense.
- Keep protocol-specific monitoring machinery in `gateway/`. Docker event streams, polling loops, D-Bus subscriptions, `PropertiesProxy`, and similar library/protocol details are gateway concerns, not usecase concerns.
- Keep user-intent and watch-policy decisions in `usecase/`. If the question is "what should we watch or when should we retry?", it likely belongs in `usecase/`. If the question is "how do we talk to Docker/systemd/eBPF?", it likely belongs in `gateway/`.
- Keep output and signal handling at the outer edge. User-visible formatting, stdout/stderr writes, Ctrl-C handling, and interruption-aware wait adapters belong in `infra/presentation/`.
- `gateway/` may decode raw events and return data, but it should not own presentation formatting.
- `usecase/orchestration/` runtime records may hold ports plus primitive/current state, but should not hold concrete infrastructure clients.
- Map CLI types to usecase request DTOs in `infra/presentation/` before entering `usecase/`.
- When adding a new seam, prefer a port in `usecase/` only if it improves dependency direction, testability, or boundary clarity. Do not introduce traits that merely rename concrete code.

## Architecture smell checks

- If a `usecase/` file imports `crate::infra::*`, `bollard`, or `zbus`, treat that as a likely architecture regression.
- If a `gateway/` file imports `crate::infra::*`, treat that as a likely architecture regression.
- If a `usecase/` or `gateway/` file adds `println!`, `eprintln!`, or `signal::ctrl_c()`, treat that as a likely boundary violation unless there is a very strong reason documented in the change.
- If Docker/systemd watch code starts to mix retry policy with protocol subscription details in one place, split the policy back to `usecase/` and the I/O mechanics back to `gateway/`.

## Shared types and maps

- `ExecEvent`: event payload shared between eBPF and userspace.
- `TaskRel`: task-tree snapshot used during startup seeding.
- `WATCH_PIDS`: userspace-managed root watch set.
- `PROC_STATE`: kernel-side per-PID cache.
- `PROC_FLAG_WATCH_SELF`: watch the root PID's own execs.
- `PROC_FLAG_WATCH_CHILDREN`: also watch descendants.

## Build and verification

```bash
cargo build --release
cargo clippy --all-targets
cargo fmt --check
cargo test
```

## Tests and coverage (recommended)

Unit tests and lints:

```bash
cargo test -p tracepoint-demo --lib
cargo clippy -p tracepoint-demo -- -D warnings
cargo fmt --all -- --check
```

Coverage:

```bash
cargo tarpaulin --skip-clean -p tracepoint-demo --lib \
  --exclude-files tracepoint-demo-ebpf/src/vmlinux.rs --out Stdout
```

## eBPF constraints

- `tracepoint-demo-ebpf` is built with `#![no_std]` and `#![no_main]`.
- Keep kernel-side code allocation-free.
- The BPF stack is small, so use `PerCpuArray` for larger temporary buffers.
- Rebuild for the BPF target after kernel-side changes, for example `bpfel-unknown-none`.

## BTF bindings

When the traced kernel types change or the target kernel changes, regenerate `tracepoint-demo-ebpf/src/vmlinux.rs`:

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```

## Runtime notes

- Root privileges or capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE` are required.
- Use `README.md` for run examples and target-combination rules.
