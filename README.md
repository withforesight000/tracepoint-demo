# tracepoint-demo
tracepoint-demo is a Rust + Aya workspace that demonstrates how to attach eBPF tracepoints to
`sys_enter_execve` so you can observe every `execve` syscall issued by a configurable set of
processes. The user-space binary builds and loads the BPF object, manages the watch maps, seeds the
process tree with `iter_tasks` (including each task's controlling terminal), and prints the events
that the kernel program emits through a ring buffer in near real time.

## Repository layout

- `tracepoint-demo` builds the user-space daemon. It drives the `AYA` build integration, opens the
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
- BPF linker (needed to compile the eBPF object): `cargo install bpf-linker` (add `--no-default-features`
  on macOS)
- `aya-tool` for generating the BTF bindings: `cargo install aya-tool`
- Root privileges or the equivalent capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, etc.)
  to load, attach, and pin eBPF programs/maps.
- When cross-compiling from macOS, install the Linux musl target and the C toolchain for your target
  architecture.

## Building

The `tracepoint-demo` crate uses `tracepoint-demo/build.rs` to invoke `aya-build`, which compiles the
embedded eBPF crate before the user-space binary. Run:

```bash
cargo build --release
```

The resulting binary contains the pre-built BPF object and is ready to load the tracepoints.

## Running

Provide one or more PIDs to trace, or filter by controlling terminal. You can use the repeated
`--pid` flag or pass positional arguments. You can also use `--tty` to select processes whose
controlling terminal matches the given TTY; the value can be repeated to watch multiple terminals.
By default each root PID is watched along with any descendants discovered either during seeding or
via the `sched_process_fork` tracepoint. Use `--no-watch-children` to restrict tracing to the given
PID without following forks.

```bash
sudo cargo run --release -- --pid 1234 --pid 9012
sudo cargo run --release -- 1234 9012 --no-watch-children
sudo cargo run --release -- --tty /dev/pts/9
sudo cargo run --release -- --tty pts9 --tty /dev/tty1
```

Each line of output looks like:

```
[0.123456] pid=1234 tid=1234 uid=1000 gid=1000 syscall_id=59 comm="bash" filename="/usr/bin/bash" argv0="bash"
```

`tracepoint-demo` pushes every requested PID (flags=`PROC_FLAG_WATCH_SELF`, plus
`PROC_FLAG_WATCH_CHILDREN` unless `--no-watch-children` is used) into `WATCH_PIDS`. It then runs the
`iter/task` helper to populate `PROC_STATE` with the live task hierarchy and each task's controlling
terminal so the BPF programs can make fast decisions on the hot path without repeatedly probing
`WATCH_PIDS`. When `--tty` is used, the initial snapshot is also used to discover root PIDs that own
the specified TTY. The filter accepts `/dev/`-prefixed values and normalizes PTY names (e.g.
`/dev/pts/9` and `pts9` are treated as the same terminal).

The `tracepoint_demo` handler caches the watch flags in `PROC_STATE`, copies filename/argv0 strings
through per-CPU buffers, and reserves an `ExecEvent` slot on the `EXEC_EVENTS` ring buffer. The
`on_fork`/`on_exit` tracepoints maintain the cache for forks and exits. The user-space binary reads
the ring buffer via `AsyncFd` and prints each event with timestamp, IDs, credentials, and names. Set
`RUST_LOG=tracepoint_demo=debug` (or similar) to show the `env_logger` messages emitted by the
binary.

## Cross-compiling on macOS

Both Intel and Apple Silicon macOS hosts can cross-compile for Linux targets. Example for `x86_64`:

```bash
ARCH=x86_64
CC=${ARCH}-linux-musl-gcc cargo build --package tracepoint-demo --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker="${ARCH}-linux-musl-gcc"
```

Swap `ARCH`/linker to `aarch64` as needed. The produced binary is at
`target/${ARCH}-unknown-linux-musl/release/tracepoint-demo`.

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
