# tracepoint-demo userspace design

## Scope

This document describes the current design of the `tracepoint-demo` userspace crate. It focuses on
what the daemon does today, how responsibilities are split across layers, and which modules own the
main runtime flows.

For build, runtime examples, and operational details, see `README.md` and `doc/operations.md`.

## Crate role

The userspace daemon is responsible for:

- parsing CLI inputs into a tracing request
- loading and attaching the embedded eBPF programs
- seeding the initial watch state from explicit PID and TTY inputs
- initializing Docker and systemd runtimes when those targets are requested
- spawning runtime monitors for container and systemd target updates
- draining the eBPF ring buffer and rendering `execve` events

`tracepoint-demo-common` is the ABI boundary to the kernel-side crate. The userspace crate treats
`ExecEvent`, `TaskRel`, map names, and watch flags as shared contract points.

## Layering

The userspace crate follows the repository's layered-architecture rules:

- `main.rs`: tiny entry point that initializes logging and delegates to bootstrap
- `infra/`: outer adapters and composition, including CLI parsing, dependency setup, startup
  wiring, runtime-loop control, and console output
- `usecase/`: user-intent flows, watch-policy decisions, startup preparation, and runtime-state
  coordination
- `gateway/`: concrete I/O against eBPF, procfs/cgroup, Docker, and systemd

Dependency direction is one-way:

- `usecase` defines ports and depends only on abstractions and DTOs
- `gateway` implements those ports with concrete external systems
- `infra` composes concrete dependencies and connects them to the runtime

## Current module map

### Entry and composition

- `src/main.rs`: async process entry point
- `src/infra/bootstrap.rs`: composition root
- `src/infra/startup.rs`: startup preparation and conversion from boot resources to `PreparedApp`
- `src/infra/runtime_loop.rs`: top-level async event loop

### Presentation and outer adapters

- `src/infra/presentation/cli.rs`: `clap`-based CLI parsing and request mapping
- `src/infra/presentation/output.rs`: startup banners, runtime notices, and `execve` line output
- `src/infra/presentation/runtime_update_dispatch.rs`: dispatch for runtime update handling
- `src/infra/presentation/runtime_updates.rs`: runtime update application with user-facing output
- `src/infra/presentation/wait.rs`: signal-aware waiting used during startup retries
- `src/infra/docker.rs`: Docker client initialization
- `src/infra/systemd.rs`: systemd client initialization

### Usecase layer

- `src/usecase/policy/trace_selected_targets.rs`: top-level tracing request and monitor spawning
- `src/usecase/policy/watch_pid_or_tty.rs`: PID and TTY watch behavior
- `src/usecase/policy/watch_container.rs`: container target behavior and runtime update policy
- `src/usecase/policy/watch_systemd_unit.rs`: systemd target behavior and runtime update policy
- `src/usecase/orchestration/startup_prepare.rs`: startup planning and backend abstraction
- `src/usecase/orchestration/startup_runtime.rs`: startup seeding and runtime initialization
- `src/usecase/orchestration/watch_roots.rs`: merged watch-root collection and `WATCH_PIDS` sync
- `src/usecase/orchestration/tty.rs`: TTY normalization helpers
- `src/usecase/orchestration/state.rs`: `AppState`, `PreparedApp`, and startup banner grouping
- `src/usecase/port/*.rs`: ports and DTOs for the inner layer

### Gateway layer

- `src/gateway/ebpf.rs`: load/attach eBPF programs, task-iterator seeding, map access, and ring
  buffer draining
- `src/gateway/procfs.rs`: procfs/cgroup reads for container process seeding
- `src/gateway/docker.rs`: Docker queries and monitor integration
- `src/gateway/systemd.rs`: systemd queries and monitor integration

### Test seams

- `src/integration.rs`: re-exports used by tests without exposing those seams as public API intent
- `src/test_support.rs`: shared mocks, queued runtimes, and helpers for unit tests

## Runtime flow

### 1. Process entry

`src/main.rs` initializes `env_logger` and enters `infra::bootstrap::run()`.

### 2. Bootstrap

`infra/bootstrap.rs` owns the concrete startup sequence:

1. Parse `CliArgs`.
2. Connect Docker and systemd clients only if the request needs them.
3. Convert CLI input into `TraceRequest`.
4. Load and attach the embedded eBPF object through `gateway::ebpf::load_tracepoint_demo_ebpf()`.
5. Prepare the application state through `infra::startup::prepare_prepared_app()`.
6. Spawn container and systemd monitor tasks when runtime targets are present.
7. Enter `infra::runtime_loop::run()`.

### 3. Startup preparation

`infra/startup.rs` bridges concrete resources to usecase logic.

Its main responsibilities are:

- normalize TTY filters
- compute watch flags from `watch_children`
- adapt concrete resources into the `StartupPrepareBackend` interface
- collect startup watch groups for the banner
- build `PreparedApp`, which contains the loaded `Ebpf`, `AppState`, startup banner data, and the
  effective watch-mode flags

### 4. Usecase startup logic

`usecase/orchestration/startup_runtime.rs` contains the startup behavior that decides what should
be watched:

- static PID and TTY roots are seeded from the eBPF task iterator
- missing PID and TTY targets are retried through the wait port when there are no runtime targets
- container runtimes query the current main PID and optionally seed all container processes
- systemd runtimes query current status and can seed `MainPID` plus unit processes before the unit
  becomes fully active

`usecase/orchestration/watch_roots.rs` then merges static roots, container roots, and systemd
roots into the current `WATCH_PIDS` map contents.

## State model

The main userspace state lives in `usecase/orchestration/state.rs`.

- `AppState.static_watch_roots`: roots established from explicit startup inputs
- `AppState.current_watch_roots`: merged roots currently expected to be in `WATCH_PIDS`
- `AppState.watch_pids`: userspace handle to the kernel `WATCH_PIDS` map
- `AppState.container_runtimes`: runtime state for each requested container target
- `AppState.systemd_runtimes`: runtime state for each requested systemd target

`StartupWatchPidGroup` is a presentation-oriented structure used to render the startup `PIDs:`
banner in grouped form.

## Port model

The usecase layer defines ports under `src/usecase/port/`.

Important contracts are:

- `ProcessSeedPort`: seed watch state from the task iterator or by direct PID insertion
- `ContainerRuntimePort`: resolve container main PIDs and spawn monitor tasks
- `SystemdRuntimePort`: query unit status, list unit PIDs, and spawn monitor tasks
- `CgroupPort`: read cgroup paths and members for container process expansion
- `StatusReporter`: emit startup and runtime notices
- `WaitPort`: wait during startup retry loops with interrupt awareness

This keeps policy decisions in `usecase/` while the concrete Docker, systemd, procfs, and eBPF
implementations remain in `gateway/` and `infra/`.

## Runtime loop

`infra/runtime_loop.rs` owns the live daemon loop after startup.

- It prints the startup banner from `StartupWatchPidGroup`.
- It drains the `EXEC_EVENTS` ring buffer and prints each `ExecEvent`.
- If container or systemd monitors are running, it also receives `RuntimeUpdate` messages from an
  unbounded Tokio channel.
- Runtime updates are applied through `infra/presentation/runtime_updates.rs`, which updates
  `AppState`, synchronizes `WATCH_PIDS`, and emits transition notices.
- `Ctrl-C` prints a shutdown message and exits cleanly.

The runtime loop does not own target-selection policy. It owns event delivery and orchestration of
already-established runtime state.

## Current design choices

- The composition root stays in `infra/bootstrap.rs`; `main.rs` remains intentionally tiny.
- Startup preparation is split so `infra/` handles concrete resource ownership and `usecase/`
  decides watch behavior.
- `WATCH_PIDS` is treated as userspace-managed root state, while descendant tracking is delegated
  to the kernel-side `PROC_STATE`.
- Runtime updates are modeled explicitly rather than letting gateway tasks mutate watch state
  directly.
- Presentation formatting stays in `infra/presentation/`, not in `gateway/` or `usecase/`.

## Change map

Use these files as entry points when changing behavior:

- CLI and input mapping: `src/infra/presentation/cli.rs`
- startup composition: `src/infra/bootstrap.rs` and `src/infra/startup.rs`
- startup seeding policy: `src/usecase/orchestration/startup_runtime.rs`
- watch-root merge and map sync: `src/usecase/orchestration/watch_roots.rs`
- container behavior: `src/usecase/policy/watch_container.rs`
- systemd behavior: `src/usecase/policy/watch_systemd_unit.rs`
- runtime loop and presentation: `src/infra/runtime_loop.rs` and `src/infra/presentation/*.rs`
- eBPF userspace adapter: `src/gateway/ebpf.rs`
