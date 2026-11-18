# tracepoint-demo

`tracepoint-demo` is a Linux daemon built with Rust and Aya. It hooks `sys_enter_execve` to print
`execve` activity for processes selected by PID, TTY, Docker container, or systemd unit.

## Workspace and documentation

- `tracepoint-demo/`: userspace daemon
- `tracepoint-demo-ebpf/`: kernel eBPF programs
- `tracepoint-demo-common/`: shared wire types and constants
- [Design index](doc/design.md) links to the userspace and eBPF architecture notes.
- [Operations guide](doc/operations.md) covers target selection, output, troubleshooting, and releases.

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

`tracepoint-demo/build.rs` builds the embedded eBPF crate through `aya-build`. A separate
`rustup target add bpfel-unknown-none` step is unnecessary.

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

Pass each PID with its own `-p` or `--pid` option. Each event line shows the process ID as
`pid=` and the thread ID as `tid=`. See the [operations guide](doc/operations.md) for combinations
of targets, startup behavior, output, and logging.

A verifier error at load time can mean that Aya's CO-RE (Compile Once, Run Everywhere) support
cannot adapt the program to your kernel's BTF. Try
[regenerating the BTF bindings](doc/operations.md#regenerating-btf-bindings) with `aya-tool`, then
rebuild.

## Tests

```bash
cargo test -p tracepoint-demo
cargo test -p tracepoint-demo-ebpf --lib
cargo clippy -- -D warnings
cargo fmt --all -- --check
```

Run the optional [eBPF verifier smoke test](doc/operations.md#ebpf-verifier-smoke-test)
to check whether the current kernel can load the embedded programs.

## License

- Userspace code: MIT or Apache-2.0, at your option.
- eBPF code: MIT or GPL-2.0, at your option.

See `LICENSE-MIT`, `LICENSE-APACHE`, and `LICENSE-GPL2`.
