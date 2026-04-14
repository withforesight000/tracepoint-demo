# tracepoint-demo

`tracepoint-demo` is a Rust + Aya workspace that traces `sys_enter_execve` and prints `execve`
activity for selected processes.

## Project Layout

- `tracepoint-demo/`: userspace daemon
- `tracepoint-demo-ebpf/`: kernel eBPF programs
- `tracepoint-demo-common/`: shared wire types and constants
- `doc/design.md`: design-document index
- `doc/tracepoint-demo-design.md`: userspace daemon design
- `doc/tracepoint-demo-ebpf-design.md`: eBPF-side design
- `doc/operations.md`: runtime behavior, build notes, and other detailed usage notes

## Requirements

Install the Rust toolchains and build tools used by local builds and CI:

```bash
rustup toolchain install stable --profile minimal
rustup component add --toolchain stable rustfmt clippy
rustup toolchain install nightly --profile minimal --component rust-src
cargo install --locked bpf-linker
```

`aya-tool` is only required when regenerating `tracepoint-demo-ebpf/src/vmlinux.rs`:

```bash
cargo install --locked aya-tool
```

You do not need `rustup target add bpfel-unknown-none`; `tracepoint-demo/build.rs` builds the
embedded eBPF crate through `aya-build`.

Running the daemon requires root privileges or capabilities such as `CAP_BPF`, `CAP_PERFMON`, and
`CAP_SYS_RESOURCE`.

## Build

```bash
cargo build --release
```

## Run

```bash
sudo cargo run --release -- --pid 1234
sudo cargo run --release -- --container my-service
sudo cargo run --release -- --systemd-unit sshd.service
```

PID targets must be passed with repeated `-p/--pid` arguments; bare positional PIDs are not
supported.

See `doc/operations.md` for target-selection rules, startup behavior, output format, logging, and
more examples.

Exec lines label the process ID as `pid=` and the thread ID as `tid=` so multithreaded execs
stay unambiguous.

## Tests

```bash
cargo test -p tracepoint-demo
cargo test -p tracepoint-demo-ebpf --lib
cargo clippy -- -D warnings
cargo fmt --all -- --check
```

To exercise the kernel verifier on a live machine, run the optional smoke test as root:

```bash
TRACEPOINT_DEMO_EBPF_SMOKE_TEST=1 sudo cargo test -p tracepoint-demo --test ebpf_verifier_smoke
```

That test loads the embedded eBPF object against the current kernel, so it will fail with the
verifier log if the program stops loading on that host.

This is a manual check and is not part of GitHub Actions CI.

## License

- Userspace code: MIT or Apache-2.0, at your option.
- eBPF code: MIT or GPL-2.0, at your option.

See `LICENSE-MIT`, `LICENSE-APACHE`, and `LICENSE-GPL2`.
