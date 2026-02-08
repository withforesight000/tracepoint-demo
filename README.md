# tracepoint-demo
tracepoint-demo is a Rust + Aya workspace that demonstrates how to attach eBPF tracepoints to
`sys_enter_execve` so you can observe every `execve` syscall issued by a configurable set of
processes. The user-space binary builds and loads the BPF object, manages the watch maps, seeds the
process tree with `iter_tasks` (including each task's controlling terminal), and prints the events
that the kernel program emits through a ring buffer in near real time.

## Repository layout

- `tracepoint-demo` builds the user-space daemon. It drives the `Aya` build integration, opens the
  `EXEC_EVENTS` ring buffer, pushes PIDs into `WATCH_PIDS`, seeds the `PROC_STATE` cache by running
  the `iter/task` helper (PID/PPID + controlling terminal), and reads the captured `ExecEvent`
  records asynchronously using Tokio.
- `tracepoint-demo-ebpf` houses the BPF programs: a `tracepoint_demo` handler attached to
  `syscalls:sys_enter_execve`, helpers for `sched:sched_process_fork`/`sched:sched_process_exit`, and
  an `iter_tasks` program that walks the live kernel task tree. All maps and structs are shared with
  the common crate.
- `tracepoint-demo-common` defines the wire format (`ExecEvent`, `TaskRel`), the map names, and the
  `PROC_FLAG` bits that indicate whether a PID should be watched for itself, its descendants, or both.

## Prerequisites

- Stable Rust toolchain: `rustup toolchain install stable`
- Nightly Rust with `rust-src`: `rustup toolchain install nightly --component rust-src`
- BPF linker (needed to compile the eBPF object): `cargo install bpf-linker`
- `aya-tool` for generating the BTF bindings: `cargo install aya-tool`
- Root privileges or the equivalent capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, etc.)
  to load, attach, and pin eBPF programs/maps.

## Building

The `tracepoint-demo` crate uses `tracepoint-demo/build.rs` to invoke `aya-build`, which compiles the
embedded eBPF crate before the user-space binary. Run:

```bash
cargo build --release
```

The resulting binary contains the pre-built BPF object and is ready to load the tracepoints.

## Running

Choose exactly one target kind: PID(s), TTY filter(s), a Docker container, or a systemd unit.

- PID(s): use repeated `--pid` flags or positional PID arguments.
- TTY filter(s): use repeated `--tty` values to select processes by controlling terminal.
- Container: use `--container <name-or-id>`.
- systemd unit: use `--systemd-unit <unit-name>`.

By default each root PID is watched along with any descendants discovered either during seeding or
via the `sched_process_fork` tracepoint. Use `--no-watch-children` to restrict tracing to the given
root process(es) without following forks.

When PID/TTY-based startup finds no matching roots, the tool waits and retries until a match
appears (or until interrupted with Ctrl-C).

If a container exists but is not running, the tool waits for a start event before proceeding.
Container seeding follows these rules:

- `--no-watch-children`: watch only the container's main PID.
- Default (`--no-watch-children` absent): seed the main PID plus descendants using `iter_tasks`.
- `--all-container-processes`: seed every PID currently in the container (from `cgroup.procs`), then
  rely on `sched_process_fork` to follow new processes. This overrides `--no-watch-children` for
  the container seed.

If a systemd unit exists but is not active, the tool waits until it becomes active before
proceeding. Systemd seeding follows these rules:

- `--no-watch-children`: watch only the unit's `MainPID`.
- Default (`--no-watch-children` absent): seed `MainPID` plus descendants using `iter_tasks`.
- `--all-systemd-processes`: seed every PID currently in the unit via systemd D-Bus
  (`GetUnitProcesses`), then rely on `sched_process_fork` to follow new processes. This overrides
  `--no-watch-children` for the unit seed.

```bash
sudo cargo run --release -- --pid 1234 --pid 9012
sudo cargo run --release -- 1234 9012 --no-watch-children
sudo cargo run --release -- --tty /dev/pts/9
sudo cargo run --release -- --tty pts9 --tty /dev/tty1
sudo cargo run --release -- --container my-service
sudo cargo run --release -- --container my-service --all-container-processes
sudo cargo run --release -- --systemd-unit sshd.service
sudo cargo run --release -- --systemd-unit sshd.service --all-systemd-processes
```

Each line of output looks like:

```
[0.123456] pid=1234 tid=1234 uid=1000 gid=1000 syscall_id=59 comm="bash" filename="/usr/bin/bash" argv0="bash"
```

`tracepoint-demo` first runs the `iter/task` helper to populate `PROC_STATE` with the live task
hierarchy and each task's controlling terminal, then writes discovered root PIDs into `WATCH_PIDS`
with flags=`PROC_FLAG_WATCH_SELF` (plus `PROC_FLAG_WATCH_CHILDREN` unless `--no-watch-children` is
used). When `--tty` is used, this startup snapshot is also used to discover root PIDs that own the
specified TTY. The filter accepts `/dev/`-prefixed values and normalizes PTY names (e.g.
`/dev/pts/9` and `pts9` are treated as the same terminal). If PID/TTY inputs resolve to no roots at
startup, the program waits and retries until matching tasks appear (or until interrupted).

When `--container` is used, the container's main PID is added to `WATCH_PIDS`, and `PROC_STATE` is
seeded either by `iter_tasks` (main PID + descendants) or by reading `cgroup.procs` when
`--all-container-processes` is set (falling back to `iter_tasks` if the cgroup lookup fails).

When `--systemd-unit` is used, the unit is resolved via systemd's D-Bus API. If the unit is not
active yet, startup waits until it is active. The unit's `MainPID` is added to `WATCH_PIDS` when
available, and `PROC_STATE` is seeded either by `iter_tasks` (MainPID + descendants) or via
`GetUnitProcesses` when `--all-systemd-processes` is set (falling back to `iter_tasks` if the D-Bus
lookup fails and `MainPID` is available).

The `tracepoint_demo` handler caches the watch flags in `PROC_STATE`, copies filename/argv0 strings
through per-CPU buffers, and reserves an `ExecEvent` slot on the `EXEC_EVENTS` ring buffer. The
`on_fork`/`on_exit` tracepoints maintain the cache for forks and exits. The user-space binary reads
the ring buffer via `AsyncFd` and prints each event with timestamp, IDs, credentials, and names. Set
`RUST_LOG=tracepoint_demo=debug` (or similar) to show the `env_logger` messages emitted by the
binary.

## Generating BTF bindings

`tracepoint-demo-ebpf/src/vmlinux.rs` contains the Aya-generated BTF definitions for the tracepoints
that the BPF programs depend on. Regenerate them when you change the traced event or build against a
different kernel:

```bash
cd tracepoint-demo-ebpf
aya-tool generate trace_event_raw_sys_enter trace_event_raw_sched_process_fork task_struct bpf_iter_meta bpf_iter__task > src/vmlinux.rs
```

`aya-tool` is supplied by the Aya toolchain (`cargo install aya-tool`).

## License

With the exception of eBPF code, tracepoint-demo is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
