# AGENTS.md

This file is a guide for AI agents operating on this repository.

## Read first

- `README.md` for user-facing behavior, build, run, and output examples.
- `.agents/skills/tracepoint-demo-layered-architecture/SKILL.md` for the canonical layered-architecture rules and change-location shortcuts.
- `.agents/skills/tracepoint-demo-ebpf-implementation/SKILL.md` for kernel-side implementation rules, shared ABI guardrails, and change-location shortcuts inside `tracepoint-demo-ebpf/`.
- `.github/skills/tracepoint-demo-layered-architecture/SKILL.md` only for Copilot compatibility if the agent does not scan `.agents/skills`.
- `.github/skills/tracepoint-demo-ebpf-implementation/SKILL.md` only for Copilot compatibility if the agent does not scan `.agents/skills`.
- `doc/design.md` when you need architectural rationale, file mapping, or the runtime interaction trace.

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
- For dependency-direction and ownership questions, follow `.agents/skills/tracepoint-demo-layered-architecture/SKILL.md`.
- For kernel-side implementation questions, follow `.agents/skills/tracepoint-demo-ebpf-implementation/SKILL.md`.

## Architecture guardrails

- See `.agents/skills/tracepoint-demo-layered-architecture/SKILL.md`.

## Architecture smell checks

- See `.agents/skills/tracepoint-demo-layered-architecture/SKILL.md`.

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

For local or CI builds of `tracepoint-demo`, install nightly with `rust-src` for the embedded
eBPF build step:

```bash
rustup toolchain install nightly --profile minimal --component rust-src
```

Do not add `--target bpfel-unknown-none`; `tracepoint-demo/build.rs` builds that target from
source via `aya-build` and `build-std`.

## Tests and coverage (recommended)

- When behavior changes, add tests for edge cases and transitional states, not only straight-line
  success paths. Prefer scenario/integration tests for easy-to-miss cases such as runtime target
  restarts, pre-active `MainPID` updates, and other unusual but important monitor sequences.

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

## eBPF constraints

- See `.agents/skills/tracepoint-demo-ebpf-implementation/SKILL.md`.

## BTF bindings

When the traced kernel types change or the target kernel changes, regenerate `tracepoint-demo-ebpf/src/vmlinux.rs`:

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```

## Runtime notes

- Use `README.md` for run examples and target-combination rules.
