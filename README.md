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

## Releases

Tagged releases are published on GitHub Releases. Push a semver tag such as `0.1.0`; the CI
workflow runs first, and if it succeeds it dispatches the release workflow to produce Linux
archives for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. The release runners
are pinned to Ubuntu 22.04 so the published binaries stay compatible with older glibc releases
than an Ubuntu 24.04 build would require. The kernel-side code also avoids newer task helpers
where a stable older alternative is available, which helps the daemon load on older supported
Linux kernels. Exec events capture up to the first five argv entries from the NULL-terminated
argv pointer array, so the printed command line stays bounded even when later slots are missing or
invalid.

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

## Tests

```bash
cargo test -p tracepoint-demo
cargo test -p tracepoint-demo-ebpf --lib
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
