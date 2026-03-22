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
- Keep CLI parsing, output formatting, runtime-loop wiring, and concrete client initialization in `interface/`.
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

```bash
cargo build --release
cargo clippy --all-targets
cargo fmt --check
cargo test
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
