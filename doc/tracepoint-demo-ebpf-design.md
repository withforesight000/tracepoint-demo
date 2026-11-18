# tracepoint-demo eBPF design

`tracepoint-demo-ebpf` traces `execve` for watched processes. It follows forks, clears cached
watch state at process exit, and supplies the task snapshot userspace needs at startup. The crate
builds with `#![no_std]` and `#![no_main]`.

See the [userspace design](tracepoint-demo-design.md) for startup and event handling, the
[README](../README.md) for the build, and the [operations guide](operations.md) for runtime details.

## Shared ABI boundary

`tracepoint-demo-common/src/lib.rs` defines the userspace/eBPF contract:

- `ExecEvent`: record submitted to the `EXEC_EVENTS` ring buffer for a watched `execve` when space
  is available
- `TaskRel`: record from the task iterator with `pid`, `ppid`, and `tty_name`
- `EXEC_EVENTS_MAP`, `WATCH_PIDS_MAP`, `PROC_STATE_MAP`: stable map names
- `PROC_FLAG_WATCH_SELF`, `PROC_FLAG_WATCH_CHILDREN`: watch flag semantics

Coordinate ABI changes across `tracepoint-demo-common`, the userspace daemon, and the eBPF crate.

## Kernel module map

- `src/main.rs`: tracepoint entrypoints, task iterator entrypoint, panic handler, and license
- `src/exec_trace.rs`: `sys_enter_execve` handling and `ExecEvent` population
- `src/watch.rs`: watch lookup, lineage fallback, child inheritance, and `PROC_STATE` cleanup
- `src/task_iter.rs`: task iterator output used for startup seeding in userspace
- `src/maps.rs`: map declarations
- `src/lib.rs`: pure helper logic with unit tests
- `src/vmlinux.rs`: generated BTF bindings. Follow the
  [regeneration procedure](operations.md#regenerating-btf-bindings) to update them.

## Programs

### `tracepoint_demo`

At `syscalls/sys_enter_execve`, the program reads the syscall context and splits `pid_tgid` into
the process ID (`tgid`) and thread ID (`tid`). It resolves watch flags using the process ID. For
a watched process, if `EXEC_EVENTS` has room, it submits an `ExecEvent` with the kernel timestamp,
credentials, syscall ID, command name, filename, and bounded `argv` capture.

### `on_fork`

At `sched/sched_process_fork`, the program looks up the parent from the tracepoint payload in the
watch maps. If the parent's flags enable `PROC_FLAG_WATCH_CHILDREN`, the program attempts to
cache watch state for the child in `PROC_STATE`.

### `on_exit`

At `sched/sched_process_exit`, the program clears the entry in `PROC_STATE` only when the exiting
thread is the thread-group leader.

### `iter_tasks`

To seed watch state at startup, userspace attaches the program in the `iter/task` section to
walk the current tasks. Each record gives the task's thread-group ID (`pid`), its real parent's thread-group ID
(`ppid`, or zero if there is no real parent), and the TTY name when available. Userspace uses
these records to seed PID and TTY roots and to find existing descendants when child watching
is enabled.

## Watch-state model

The kernel-side watch logic is split across two maps:

- `WATCH_PIDS`: userspace-managed root watch set
- `PROC_STATE`: kernel-side per-process cache used to keep watch state on descendants and already
  resolved processes

`watch.rs` resolves watch state in this order:

1. check `PROC_STATE`
2. check `WATCH_PIDS`
3. walk task lineage through `parent` and `real_parent`, up to `MAX_LINEAGE_DEPTH`

The lookup attempts to cache a hit from `WATCH_PIDS` in `PROC_STATE`. It also attempts to cache
the current process there when the lineage walk finds a watched ancestor with child watching
enabled.

## Exec event capture

`exec_trace.rs` zeroes the ring-buffer record before filling it. It reads the filename with
`bpf_probe_read_user_str_bytes`. For `argv`, it copies the first five pointers, then reads the
pointed-to strings until it reaches a null pointer or fills the five slots.

## Kernel field reads

`watch.rs` uses `bpf_probe_read_kernel` to read the task fields needed for the lineage walk. It
uses the older `bpf_get_current_task` helper because some kernels reject
`bpf_get_current_task_btf` for this program type. `task_iter.rs` reads the iterator context,
task and parent IDs, and TTY metadata.

## Pure helper layer

`src/lib.rs` contains pure logic that can be tested without the eBPF runtime:

- splitting `pid_tgid` and `uid_gid`
- deciding whether an exit belongs to the thread-group leader
- checking whether watch flags propagate to children
- lineage-matching and next-hop selection helpers

## Change map

Use these files as entry points when changing behavior:

- event payload capture: `src/exec_trace.rs`
- watch inheritance and cleanup: `src/watch.rs`
- startup task snapshot behavior: `src/task_iter.rs`
- kernel struct reads: `src/watch.rs` and `src/task_iter.rs`
- shared pure logic: `src/lib.rs`
- ABI structs and flags: `tracepoint-demo-common/src/lib.rs`
