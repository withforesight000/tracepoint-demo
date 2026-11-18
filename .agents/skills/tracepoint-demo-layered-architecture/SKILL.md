---
name: tracepoint-demo layered architecture
description: Canonical layered-architecture guidance for tracepoint-demo. Use when deciding whether code belongs in infra, gateway, or usecase, or when adding seams and change-location shortcuts.
---

# Tracepoint Demo Layered Architecture

Use this skill when editing the userspace daemon or deciding where new logic should live.

The [Copilot shim](../../../.github/skills/tracepoint-demo-layered-architecture/SKILL.md)
points here.

## Layer responsibilities

| Location | What belongs here |
| --- | --- |
| `main.rs` | Process entry point. Delegate startup to bootstrap. |
| `infra/` | Parse CLI arguments, set up dependencies, wire startup and the runtime loop, adapt waits, and print output. |
| `usecase/` | Decide what to watch, when to retry, and how to merge watch state. Define the ports and DTOs the policy needs. |
| `gateway/` | Implement the ports for eBPF, procfs/cgroup, Docker, and systemd. |

Production dependencies point inward. `infra` assembles `usecase` and `gateway`, and `gateway`
implements ports defined in `usecase`. Keep `usecase` independent of concrete adapters.

## Ports and seams

- Define a port in `usecase/` when policy needs to call an external system through an abstraction.
- Keep request DTOs with the port or usecase that consumes them.
- Introduce a trait when callers need an abstraction over the concrete dependency.

## Guardrails

- Do not let `usecase/` depend on `crate::infra::*` or on concrete client types such as `bollard::Docker` or `zbus::Connection`.
- Do not let `gateway/` depend on `infra/`.
- Keep `println!`, `eprintln!`, and signal handling at the presentation edge in `infra/presentation/`.
- Keep protocol-specific monitoring machinery such as Docker event streams, polling loops, and D-Bus subscriptions in `gateway/`.
- Keep presentation formatting out of `gateway/`.
- Keep usecase steps and their state in `usecase/orchestration/`. Initialize the program in `infra/`.
- Map CLI types to usecase request DTOs in `infra/presentation/` before entering `usecase/`.

## Change workflow

- If behavior changes, update `README.md` for user-facing behavior and `doc/design.md` for architecture notes.
- For startup wiring, start with `tracepoint-demo/src/infra/bootstrap.rs` and `tracepoint-demo/src/infra/startup.rs`.

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
