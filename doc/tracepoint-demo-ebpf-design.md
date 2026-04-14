# tracepoint-demo eBPF design

## Scope

This document describes the current design of the `tracepoint-demo-ebpf` crate and the shared ABI
points it uses with userspace.

For userspace orchestration, see `doc/tracepoint-demo-design.md`. For build and operational notes,
see `README.md` and `doc/operations.md`.

## Crate role

The eBPF crate is responsible for:

- tracing `sys_enter_execve`
- inheriting watch state across `sched_process_fork`
- clearing process watch state on `sched_process_exit`
- exposing a task iterator used by userspace startup seeding

It is built as `#![no_std]` and `#![no_main]`, and it relies on `tracepoint-demo-common` for
shared event payloads, map names, and watch flags.

## Shared ABI boundary

`tracepoint-demo-common/src/lib.rs` defines the userspace/eBPF contract:

- `ExecEvent`: event payload written into the ring buffer for each traced `execve`
- `TaskRel`: `(pid, ppid, tty)` snapshot entry emitted by the task iterator
- `EXEC_EVENTS_MAP`, `WATCH_PIDS_MAP`, `PROC_STATE_MAP`: stable map names
- `PROC_FLAG_WATCH_SELF`, `PROC_FLAG_WATCH_CHILDREN`: watch flag semantics

Changes to any of those fields must be coordinated with userspace in the same change.

## Current module map

- `src/main.rs`: tracepoint entrypoints, task iterator entrypoint, panic handler, and license
- `src/exec_trace.rs`: `sys_enter_execve` handling and `ExecEvent` population
- `src/watch.rs`: watch lookup, lineage fallback, child inheritance, and `PROC_STATE` cleanup
- `src/task_iter.rs`: task iterator output used for startup seeding in userspace
- `src/kernel_read.rs`: verifier-friendly kernel field reads for `task_struct`, iterator context,
  and TTY metadata
- `src/maps.rs`: map declarations
- `src/lib.rs`: pure helper logic with unit tests
- `src/vmlinux.rs`: generated BTF bindings

## Programs

### `tracepoint_demo`

Attached to `syscalls/sys_enter_execve`.

This program:

1. Reads the raw syscall context.
2. Splits `pid_tgid` into process ID (`tgid`) and thread ID (`tid`).
3. Resolves watch flags for the current process.
4. Reserves a ring-buffer slot in `EXEC_EVENTS`.
5. Populates `ExecEvent` with timestamps, credentials, command name, filename, and bounded `argv`
   capture.

If the current process is not watched, the program exits without emitting an event.

### `on_fork`

Attached to `sched/sched_process_fork`.

This program copies watch state from the parent process into the child when
`PROC_FLAG_WATCH_CHILDREN` is set. That keeps descendants visible without requiring userspace to
write every forked PID into `WATCH_PIDS`.

### `on_exit`

Attached to `sched/sched_process_exit`.

This program removes process-granularity state from `PROC_STATE`, but only when the exiting task is
the thread-group leader. Non-leader thread exits do not clear shared watch state for the process.

### `iter_tasks`

Exposed in the `iter/task` section.

Userspace attaches this iterator during startup to obtain a point-in-time task snapshot. Each item
contains:

- `pid`
- `ppid`
- TTY name data when available

Userspace uses that snapshot to seed roots from explicit PID and TTY selection and to expand child
processes when watch-children mode is enabled.

## Watch-state model

The kernel-side watch logic is split across two maps:

- `WATCH_PIDS`: userspace-managed root watch set
- `PROC_STATE`: kernel-side per-process cache used to keep watch state on descendants and already
  resolved processes

`watch.rs` resolves watch state in this order:

1. check `PROC_STATE`
2. check `WATCH_PIDS`
3. walk task lineage through `parent` and `real_parent`

When lineage resolution finds a watched ancestor with child watching enabled, the current process
is inserted into `PROC_STATE` so later lookups are cheap.

## Exec event capture

`exec_trace.rs` keeps capture bounded and verifier-friendly:

- filename is read from the syscall argument pointer with `bpf_probe_read_user_str_bytes`
- `argv` capture is limited to five slots
- the pointer array is copied first, then dereferenced slot-by-slot until the first NULL entry
- event memory is zeroed before population so missing fields stay deterministic

This keeps the userspace output informative without making the tracepoint program unbounded.

## Kernel-read helpers

`kernel_read.rs` centralizes the raw pointer access needed by `watch.rs` and `task_iter.rs`.

It wraps:

- iterator metadata reads
- `task_struct` field access such as `tgid`, `parent`, `real_parent`, and `signal`
- TTY name extraction

Keeping those helpers in one place keeps `unsafe` field walking local and makes the higher-level
logic easier to review.

## Pure helper layer

`src/lib.rs` contains pure logic that can be tested without the eBPF runtime:

- splitting `pid_tgid` and `uid_gid`
- deciding whether an exit belongs to the thread-group leader
- checking whether watch flags propagate to children
- lineage-matching and next-hop selection helpers

This layer exists to keep the policy-like parts of watch resolution unit-testable.

## Current design choices

- Process identity is handled at process granularity with `tgid`, not per-thread `tid`, for watch
  state and cleanup.
- Lineage walks are depth-bounded with `MAX_LINEAGE_DEPTH`.
- Older task helpers are preferred when they keep the tracepoint program loadable on more kernels.
- Generated BTF bindings stay in `src/vmlinux.rs` and are regenerated, not hand-edited.
- The crate stays small: entrypoints in `main.rs`, stateful logic in focused modules, pure helpers
  in `lib.rs`.

## Change map

Use these files as entry points when changing behavior:

- event payload capture: `src/exec_trace.rs`
- watch inheritance and cleanup: `src/watch.rs`
- startup task snapshot behavior: `src/task_iter.rs`
- kernel struct reads: `src/kernel_read.rs`
- shared pure logic: `src/lib.rs`
- ABI structs and flags: `tracepoint-demo-common/src/lib.rs`
