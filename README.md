# tracepoint-demo

`tracepoint-demo` is a Rust + Aya workspace that traces `sys_enter_execve` and prints `execve`
activity for selected processes.

## Project Layout

- `tracepoint-demo/`: userspace daemon
- `tracepoint-demo-ebpf/`: kernel eBPF programs
- `tracepoint-demo-common/`: shared wire types and constants
- `doc/design.md`: architecture and layer ownership
- `doc/operations.md`: runtime behavior, build notes, and other detailed usage notes

## Requirements

- Stable Rust toolchain
- Nightly Rust toolchain with `rust-src` for the embedded eBPF build
- `bpf-linker`
- `aya-tool`
- Root privileges or capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE`

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

See `doc/operations.md` for target-selection rules, startup behavior, output format, logging, and
more examples.

## Tests

```bash
cargo test -p tracepoint-demo
cargo test -p tracepoint-demo-ebpf --lib
```

## License

- Userspace code: MIT or Apache-2.0, at your option.
- eBPF code: MIT or GPL-2.0, at your option.

See `LICENSE-MIT`, `LICENSE-APACHE`, and `LICENSE-GPL2`.
