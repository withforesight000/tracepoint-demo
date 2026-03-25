---
name: tracepoint-demo layered architecture
description: Canonical layered-architecture guidance for tracepoint-demo. Use when deciding whether code belongs in infra, gateway, or usecase, or when adding seams and change-location shortcuts.
---

# Tracepoint Demo Layered Architecture

Use this skill when editing the userspace daemon or deciding where new logic should live.

## Canonical paths

- Canonical skill: `.agents/skills/tracepoint-demo-layered-architecture/SKILL.md`
- Copilot compatibility shim: `.github/skills/tracepoint-demo-layered-architecture/SKILL.md`
- Portable summary: `docs/ai-guidance.md`

## Core model

- `main.rs` stays tiny and acts as the entry point into bootstrap.
- `infra/` owns composition, initialization, CLI mapping, user-facing output, wait adapters, and runtime-loop wiring.
- `gateway/` owns concrete I/O against eBPF, procfs/cgroup, Docker, and systemd.
- `usecase/` owns user intent, watch-policy decisions, and usecase-internal orchestration.

The dependency direction is one way:

- `usecase` defines contracts and DTOs.
- `gateway` implements those contracts with concrete systems.
- `infra` composes everything and handles the outer user-facing edges.

## Decision rules

- What should we watch, retry, or merge? Put it in `usecase/`.
- How do we talk to Docker, systemd, procfs, or eBPF? Put it in `gateway/`.
- How do we parse CLI input, print output, or wire startup and the runtime loop? Put it in `infra/`.

## Ports and seams

- Define ports in `usecase/` when an inner layer needs an abstraction over an outer dependency.
- Keep request DTOs with the port or usecase that consumes them.
- Avoid introducing a trait that merely renames a concrete type or a thin wrapper with no architectural benefit.

## Guardrails

- Do not let `usecase/` depend on `crate::infra::*` or on concrete client types such as `bollard::Docker` or `zbus::Connection`.
- Do not let `gateway/` depend on `infra/`.
- Keep `println!`, `eprintln!`, and signal handling at the presentation edge in `infra/presentation/`.
- Keep protocol-specific monitoring machinery such as Docker event streams, polling loops, and D-Bus subscriptions in `gateway/`.
- Keep presentation formatting out of `gateway/`.
- Keep `usecase/orchestration/` focused on internal step decomposition and primitive/current state, not whole-program initialization.
- Map CLI types to usecase request DTOs in `infra/presentation/` before entering `usecase/`.

## Change workflow

- If behavior changes, update `README.md` for user-facing behavior and `doc/design.md` for architecture notes.
- If the change affects ownership boundaries or dependency direction, check this skill first and keep the code aligned with it.
- If the task is clearly about startup wiring, look in `tracepoint-demo/src/infra/bootstrap.rs` and `tracepoint-demo/src/infra/startup.rs` before moving logic elsewhere.

## File lookup shortcuts

- CLI parsing and input normalization: `tracepoint-demo/src/infra/presentation/cli.rs`
- Startup wiring and dependency setup: `tracepoint-demo/src/infra/bootstrap.rs` and `tracepoint-demo/src/infra/startup.rs`
- Runtime loop control: `tracepoint-demo/src/infra/runtime_loop.rs`
- Shared outbound traits and DTOs: `tracepoint-demo/src/usecase/port/definitions.rs` and `tracepoint-demo/src/usecase/port/runtime_update.rs`
- Usecase-internal orchestration: files under `tracepoint-demo/src/usecase/orchestration/`
- PID or TTY policy: `tracepoint-demo/src/usecase/policy/watch_pid_or_tty.rs`
- Container policy: `tracepoint-demo/src/usecase/policy/watch_container.rs`
- Systemd policy: `tracepoint-demo/src/usecase/policy/watch_systemd_unit.rs`
- Docker I/O and monitoring: `tracepoint-demo/src/gateway/docker.rs`
- Systemd I/O and monitoring: `tracepoint-demo/src/gateway/systemd.rs`
- eBPF loading, maps, and ring buffer handling: `tracepoint-demo/src/gateway/ebpf.rs`

## Project-specific notes

- `tracepoint-demo-common` is the ABI boundary between userspace and eBPF.
- `tracepoint-demo-ebpf` is built with `#![no_std]` and `#![no_main]`.
- Keep kernel-side code allocation-free.
- Root privileges or capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE` are required to run the daemon.
