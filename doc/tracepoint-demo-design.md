# tracepoint-demo userspace design

`tracepoint-demo` turns a CLI tracing request into watch roots, loads the embedded eBPF programs,
and prints the events they send. It starts Docker or systemd monitors when the request includes
those targets.

`tracepoint-demo-common` defines the shared ABI, including `ExecEvent`, `TaskRel`, map names, and
watch flags. See the [eBPF design](tracepoint-demo-ebpf-design.md) for the kernel side, the
[README](../README.md) for build commands, and the [operations guide](operations.md) for examples.

## Layering

- `main.rs`: tiny entry point that initializes logging and delegates to bootstrap
- `infra/`: CLI parsing, dependency setup, startup wiring, and runtime-loop control.
  `infra/presentation/` formats console output.
- `usecase/`: user-intent flows, watch-policy decisions, startup preparation, and runtime-state
  coordination
- `gateway/`: concrete I/O against eBPF, procfs/cgroup, Docker, and systemd

The `usecase` layer defines ports and data transfer objects. The `gateway` layer implements
those ports for external systems, and `infra` assembles the concrete dependencies for the daemon.
The [layered architecture skill](../.agents/skills/tracepoint-demo-layered-architecture/SKILL.md)
defines the dependency rules.

## Userspace module map

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

`infra/startup.rs` normalizes the TTY filters and computes flags from `watch_children`. It
adapts the concrete resources to `StartupPrepareBackend`, then groups the selected PIDs for the
startup banner. It returns `PreparedApp` with the loaded `Ebpf`, `AppState`, banner data, and
effective watch-mode flags.

### 4. Usecase startup logic

`usecase/orchestration/startup_runtime.rs` contains the startup behavior that decides what should
be watched:

- static PID and TTY roots are seeded from the eBPF task iterator
- if there are no runtime targets and the first lookup finds no PID or TTY roots, retry through
  the wait port
- container runtimes query the current main PID and optionally seed all container processes
- for systemd, seed a usable `MainPID` even before the unit is active. In all-processes mode,
  also query unit processes. A running unit can supply those processes without a `MainPID`.

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

The usecase layer defines these ports under `src/usecase/port/`.

- `ProcessSeedPort`: seed watch state from the task iterator or by direct PID insertion
- `ContainerRuntimePort`: resolve container main PIDs and spawn monitor tasks
- `SystemdRuntimePort`: query unit status, list unit PIDs, and spawn monitor tasks
- `CgroupPort`: read cgroup paths and members for container process expansion
- `StatusReporter`: emit startup and runtime notices
- `WaitPort`: wait during startup retry loops with interrupt awareness

## Runtime loop

`infra/runtime_loop.rs` owns the live daemon loop after startup.

- It prints the startup banner from `StartupWatchPidGroup`.
- It drains the `EXEC_EVENTS` ring buffer and prints each `ExecEvent`.
- If Docker or systemd monitors are running, it receives their `RuntimeUpdate` messages over an
  unbounded Tokio channel. `infra/presentation/runtime_updates.rs` calls the usecase handlers
  to update `AppState`, synchronizes `WATCH_PIDS`, and reports transitions.
- `Ctrl-C` prints a shutdown message and exits cleanly.

Userspace keeps roots in `WATCH_PIDS`, and the eBPF programs track descendants in `PROC_STATE`.

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
