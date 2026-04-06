---
name: tracepoint-demo ebpf implementation
description: Implementation guidance for tracepoint-demo-ebpf. Use when editing the no_std kernel-side crate, changing maps or shared ABI structs, regenerating BTF bindings, or deciding where eBPF-side logic should live.
---

# Tracepoint Demo eBPF Implementation

Use this skill when editing `tracepoint-demo-ebpf/` or changing the ABI between eBPF and userspace.

## Canonical paths

- Canonical skill: `.agents/skills/tracepoint-demo-ebpf-implementation/SKILL.md`
- Copilot compatibility shim: `.github/skills/tracepoint-demo-ebpf-implementation/SKILL.md`
- User-facing behavior and run expectations: `README.md`
- Userspace architecture notes and runtime trace: `doc/design.md`

## Core model

- `tracepoint-demo-ebpf` is the kernel-side crate. Keep it `#![no_std]` and `#![no_main]`.
- `tracepoint-demo-common` is the ABI boundary. Shared structs, map names, and watch flags belong there.
- The eBPF crate is intentionally small and pragmatic. Prefer a few focused files over reintroducing one large `main.rs`.

## Module ownership

- `src/main.rs`: program entrypoints only. Keep `tracepoint`, `iter/task`, panic handler, and license here.
- `src/maps.rs`: BPF map declarations only.
- `src/exec_trace.rs`: `sys_enter_execve` event extraction and ring buffer writes.
- `src/watch.rs`: watch-flag lookup, lineage fallback, child-watch inheritance, and `PROC_STATE` updates.
- `src/task_iter.rs`: task iterator output for startup seeding.
- `src/lib.rs`: pure helpers that are worth unit-testing without BPF runtime dependencies.
- `src/vmlinux.rs`: generated BTF bindings. Do not hand-edit.

## Guardrails

- Treat process identity at process granularity. Use `tgid` for PID-level watch state and task iterator output, not per-thread `tid`.
- Keep `PROC_STATE` semantics consistent with that process granularity. Cleanup logic must not drop state on non-leader thread exit.
- Keep loops verifier-friendly: bounded, simple, and with explicit depth caps.
- Keep kernel-side code allocation-free and stack-aware. Reuse per-CPU buffers for larger temporary arrays such as pathname capture.
- Keep `unsafe` blocks tight and local. If a pointer walk or helper call can be isolated, isolate it.
- Do not rename maps or shared flags casually. `WATCH_PIDS`, `PROC_STATE`, `ExecEvent`, `TaskRel`, and the watch flags are userspace/eBPF contract points.
- Prefer extracting pure decision logic into `src/lib.rs` when it can be tested outside the eBPF runtime.

## Change rules

- If you change event payloads, map names, or watch-flag meanings, update `tracepoint-demo-common/` in the same change.
- If behavior visible to users changes, update `README.md` and `doc/design.md` in the same change.
- If kernel type usage changes, regenerate `tracepoint-demo-ebpf/src/vmlinux.rs` rather than editing it manually.
- Keep userspace assumptions in mind: container exec tracing depends on `PROC_STATE` inheriting watch flags correctly across fork/exec and on process-granularity cleanup.

## BTF bindings

Regenerate bindings when traced kernel types change or the target kernel changes:

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```

## Verification

- `cargo test -p tracepoint-demo-ebpf --lib`
- `cargo test -p tracepoint-demo --lib`
- `cargo fmt --all -- --check`

Run wider checks from `AGENTS.md` when the change reaches userspace behavior or build wiring.

## File lookup shortcuts

- eBPF entrypoints: `tracepoint-demo-ebpf/src/main.rs`
- Map declarations: `tracepoint-demo-ebpf/src/maps.rs`
- Exec event capture: `tracepoint-demo-ebpf/src/exec_trace.rs`
- Watch-state logic: `tracepoint-demo-ebpf/src/watch.rs`
- Task iterator output: `tracepoint-demo-ebpf/src/task_iter.rs`
- Pure helper seam and unit tests: `tracepoint-demo-ebpf/src/lib.rs`
- Shared ABI structs and flags: `tracepoint-demo-common/src/lib.rs`
