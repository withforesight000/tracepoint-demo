---
name: tracepoint-demo ebpf implementation
description: Implementation guidance for tracepoint-demo-ebpf. Use when editing the no_std kernel-side crate, changing maps or shared ABI structs, regenerating BTF bindings, or deciding where eBPF-side logic should live.
---

# Tracepoint Demo eBPF Implementation

Use this skill when editing `tracepoint-demo-ebpf/` or changing the ABI between eBPF and userspace.

The [Copilot shim](../../../.github/skills/tracepoint-demo-ebpf-implementation/SKILL.md)
points here. See the [README](../../../README.md) for usage and the
[design notes](../../../doc/design.md) for the runtime flow.

## Crate boundary

Keep `tracepoint-demo-ebpf` as `#![no_std]` and `#![no_main]`. Put shared structs, map names, and
watch flags in `tracepoint-demo-common`, the ABI boundary between userspace and the kernel programs.
Keep the entry points in `main.rs` and give each implementation module one responsibility.

## Module ownership in `tracepoint-demo-ebpf/`

- `src/main.rs`: program entrypoints only. Keep `tracepoint`, `iter/task`, panic handler, and license here.
- `src/maps.rs`: BPF map declarations only.
- `src/exec_trace.rs`: `sys_enter_execve` event extraction and ring buffer writes.
- `src/watch.rs`: watch-flag lookup, lineage fallback, child-watch inheritance, and `PROC_STATE` updates.
- `src/task_iter.rs`: task iterator output for startup seeding.
- `src/lib.rs`: pure helpers that are worth unit-testing without BPF runtime dependencies.
- `src/vmlinux.rs`: generated BTF bindings. Do not hand-edit.

## Guardrails

- Use `tgid` for process watch state and task iterator output. In `PROC_STATE`, retain the process entry when a non-leader thread exits.
- Use simple, bounded loops with explicit depth limits for the verifier.
- Keep kernel-side code allocation-free and stack-aware. Reuse per-CPU buffers for larger temporary arrays such as pathname capture.
- Limit each `unsafe` block to the pointer walk or helper call that needs it.
- Treat `WATCH_PIDS`, `PROC_STATE`, `ExecEvent`, `TaskRel`, and the watch flags as ABI contracts.
- Prefer extracting pure decision logic into `src/lib.rs` when it can be tested outside the eBPF runtime.

## Change rules

- If you change event payloads, map names, or watch-flag meanings, update `tracepoint-demo-common/` in the same change.
- If behavior visible to users changes, update `README.md` and `doc/design.md` in the same change.
- If kernel type usage changes, regenerate `tracepoint-demo-ebpf/src/vmlinux.rs` rather than editing it manually.
- Container exec tracing depends on `PROC_STATE` retaining inherited watch flags across fork and
  exec. Clear entries at process granularity.

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
