# tracepoint-demo design

## Purpose

This note describes the agreed user-space architecture for `tracepoint-demo` and the current code
layout that implements it.

It is intentionally both a design note and a reading guide:

- it explains the layer boundaries we want to preserve
- it points at the current files that play each role today

## First orientation

Before diving into the layers, keep this mental model in mind:

- the CLI chooses target-selection modes such as PID, TTY, container, or systemd unit
- bootstrap code prepares concrete dependencies and starts the runtime
- usecases decide what should be watched and how updates should be applied
- gateways talk to eBPF, procfs, Docker, and systemd
- the eBPF side emits `execve` events for watched processes and userspace prints them

The workspace is split across three crates:

- `tracepoint-demo/`: userspace daemon and the main code discussed in this document
- `tracepoint-demo-ebpf/`: kernel-side eBPF programs attached by userspace
- `tracepoint-demo-common/`: structs and constants shared across the userspace/eBPF boundary

If you only want to understand the userspace architecture, start with `tracepoint-demo/` and come
back to the eBPF crate later.

## Build toolchain note

The workspace build path currently compiles the embedded eBPF crate from `tracepoint-demo/build.rs`
via `aya-build`. That helper defaults to the nightly toolchain for the eBPF build step, so the
current CI and local build instructions need a nightly toolchain with `rust-src` installed
alongside stable. A preinstalled `bpfel-unknown-none` rustup target is not required.

## Current directory layout

Today, the userspace crate has this directory structure:

```text
tracepoint-demo/src/
├── lib.rs
├── main.rs
├── gateway/
│   ├── docker.rs
│   ├── ebpf.rs
│   ├── mod.rs
│   ├── procfs.rs
│   └── systemd.rs
├── infra/
│   ├── bootstrap.rs
│   ├── docker.rs
│   ├── mod.rs
│   ├── runtime_loop.rs
│   ├── startup.rs
│   ├── systemd.rs
│   └── presentation/
│       ├── cli.rs
│       ├── mod.rs
│       ├── output.rs
│       ├── runtime_update_dispatch.rs
│       ├── runtime_updates.rs
│       └── wait.rs
└── usecase/
    ├── mod.rs
    ├── orchestration/
    │   ├── mod.rs
    │   ├── startup_prepare.rs
    │   ├── startup_runtime.rs
    │   ├── state.rs
    │   ├── tty.rs
    │   └── watch_roots.rs
    ├── policy/
    │   ├── mod.rs
    │   ├── trace_selected_targets.rs
    │   ├── watch_container.rs
    │   ├── watch_pid_or_tty.rs
    │   └── watch_systemd_unit.rs
    ├── port/
    │   ├── cgroup.rs
    │   ├── definitions.rs
    │   ├── mod.rs
    │   ├── process_seed.rs
    │   └── runtime_update.rs
```

There is also a `tracepoint-demo/src/target/` directory in the workspace at the moment, but that is
not part of the intended architecture and should be read as incidental build output rather than as
a design-level module.

## Target layering

The target user-space layering is:

- `main.rs`
- `infra/`
- `gateway/`
- `usecase/`

### `main.rs`

`main.rs` stays tiny. Its job is to initialize logging and hand control to bootstrap.

### `infra/`

`infra` is the outer entry side of the userspace daemon.

- `infra/bootstrap.rs` owns the composition root, concrete dependency creation, startup execution,
  runtime loop startup, and the top-level wiring between usecases, gateways, and presentation.
- `infra/startup.rs` owns startup preparation that still needs concrete dependency access but should
  stay outside the usecase layer.
- `infra/presentation/` owns user-facing input and output concerns such as CLI parsing, message
  formatting, signal-aware waits, and other edge adapters.

In other words, `infra` is where program initialization belongs.

### `gateway/`

`gateway` is a top-level layer that owns concrete operations against external systems.

- eBPF loading, attachment, map operations, and ring buffer reads
- procfs and cgroup file access
- Docker inspection and monitor loops
- systemd D-Bus queries and monitor loops

`gateway` implements the traits defined under `usecase/port/`.

### `usecase/`

`usecase` owns user intent and is split into three subareas:

- `policy/`: the user-visible behavior for each target mode
- `port/`: the traits and related DTOs that describe what the usecases need from the outside world
- `orchestration/`: internal usecase coordination helpers for multi-step flows that are still part
  of usecase behavior

Crate-local unit tests now share `tracepoint-demo/src/test_support.rs` for reusable mocks and test
fakes. `mockall` is used where it makes the tests simpler, while runtime ports that return
`BoxFuture<'a, ...>` still use shared manual fakes because that shape does not fit `mockall`
cleanly in this codebase.

The key rule is that `usecase/orchestration/` is not the place for whole-program initialization.
Initialization belongs to `infra/`. Orchestration exists only to keep individual
usecases small when they need internal step decomposition.

## Concrete module mapping

The current tree already follows the target layering:

- `infra/bootstrap.rs` is the composition root
- `infra/startup.rs` holds startup preparation that needs concrete dependencies
- `infra/runtime_loop.rs` owns the top-level async runtime loop
- `infra/presentation/*.rs` owns CLI, output, waits, and runtime-update presentation helpers
- `usecase/port/*.rs` owns the usecase-facing contracts and DTOs
- `usecase/orchestration/startup_prepare.rs` owns startup planning
- `usecase/orchestration/startup_runtime.rs` owns startup seeding and runtime initialization
- `usecase/orchestration/watch_roots.rs` owns watch-root merge and diff logic
- `usecase/orchestration/tty.rs` owns TTY normalization helpers
- `usecase/policy/*.rs` owns target-selection behavior
- `gateway/*.rs` owns concrete eBPF, procfs, Docker, and systemd I/O

## Suggested reading order

For a first pass through the code, read these files in order:

1. `tracepoint-demo/src/main.rs`: process entry point
2. `tracepoint-demo/src/infra/bootstrap.rs`: composition root
3. `tracepoint-demo/src/infra/presentation/cli.rs`: CLI mapping into usecase requests
4. `tracepoint-demo/src/infra/startup.rs`: startup preparation with concrete dependencies
5. `tracepoint-demo/src/usecase/policy/trace_selected_targets.rs`: user-intent entry point
6. `tracepoint-demo/src/usecase/port/definitions.rs`: port definitions and related DTOs
7. `tracepoint-demo/src/usecase/orchestration/startup_prepare.rs`: startup planning seam
8. `tracepoint-demo/src/usecase/orchestration/startup_runtime.rs`: startup seeding and runtime initialization
9. `tracepoint-demo/src/usecase/orchestration/watch_roots.rs`: watch-root merge and diff logic
10. `tracepoint-demo/src/usecase/policy/watch_*.rs`: target-mode-specific policy
11. `tracepoint-demo/src/infra/runtime_loop.rs`: top-level runtime control loop
12. `tracepoint-demo/src/gateway/*.rs`: concrete external operations

That path follows the same order the program follows at runtime.

## Key terms

Some terms appear repeatedly in the code and are easy to confuse on a first read:

- watch root: a PID that userspace explicitly asks the kernel-side logic to track
- static watch roots: roots discovered at startup from explicit PID or TTY selection
- runtime-derived roots: roots learned later from Docker or systemd monitoring
- watch set: the final merged PID set written into `WATCH_PIDS`
- `PROC_STATE`: kernel-side per-process cache used while following descendants
- runtime update: a userspace message saying that container or systemd state changed

## Why this split exists

This daemon grew beyond simple PID tracing. Userspace now has to coordinate:

- CLI parsing and normalization
- request mapping into the usecase layer
- eBPF loading and map operations
- PID and TTY target discovery
- Docker and systemd client initialization
- Docker and systemd monitoring
- runtime update handling
- event-loop control and output formatting

Keeping all of that in one entry file makes the flow harder to read and harder to test. The target
split is meant to keep three concerns separate:

- `infra`: entering the program, building dependencies, and handling user-facing edges
- `usecase`: deciding what the daemon should do for a given target selection
- `gateway`: talking to external systems

For container targets with `--all-container-processes`, Docker exec activity can trigger a
container reseed even when the container's main PID stays the same. That keeps the cgroup-backed
watch set aligned with `docker exec` and `docker compose exec` sessions.

This is intentionally clean-architecture-oriented, but still pragmatic for a daemon whose core
complexity is orchestration rather than rich business modeling.

## Target directory layout

The agreed target layout after the refactor is:

```text
tracepoint-demo/src/
├── lib.rs
├── main.rs
├── gateway/
│   ├── docker.rs
│   ├── ebpf.rs
│   ├── mod.rs
│   ├── procfs.rs
│   └── systemd.rs
├── infra/
│   ├── bootstrap.rs
│   ├── docker.rs
│   ├── mod.rs
│   ├── runtime_loop.rs
│   ├── startup.rs
│   ├── systemd.rs
│   └── presentation/
│       ├── cli.rs
│       ├── mod.rs
│       ├── output.rs
│       ├── runtime_update_dispatch.rs
│       ├── runtime_updates.rs
│       └── wait.rs
└── usecase/
    ├── mod.rs
    ├── orchestration/
    │   ├── mod.rs
    │   ├── startup_prepare.rs
    │   ├── startup_runtime.rs
    │   ├── state.rs
    │   ├── tty.rs
    │   └── watch_roots.rs
    ├── policy/
    │   ├── mod.rs
    │   ├── trace_selected_targets.rs
    │   ├── watch_container.rs
    │   ├── watch_pid_or_tty.rs
    │   └── watch_systemd_unit.rs
    └── port/
      ├── cgroup.rs
        ├── definitions.rs
        ├── mod.rs
      ├── process_seed.rs
        └── runtime_update.rs
```

This layout keeps initialization inside `infra`, concrete external operations inside `gateway`,
and user-intent behavior inside `usecase`.

## If you want to change

This section is the quickest file lookup guide for common changes.

- CLI flags or input normalization:
  - file: `tracepoint-demo/src/infra/presentation/cli.rs`
- startup wiring, dependency setup, and runtime startup:
  - files: `tracepoint-demo/src/infra/bootstrap.rs` and `tracepoint-demo/src/infra/startup.rs`
- startup seeding and runtime initialization policy:
  - file: `tracepoint-demo/src/usecase/orchestration/startup_runtime.rs`
- runtime loop control:
  - file: `tracepoint-demo/src/infra/runtime_loop.rs`
- shared outbound traits and related DTOs:
  - files: `tracepoint-demo/src/usecase/port/definitions.rs`, `tracepoint-demo/src/usecase/port/runtime_update.rs`, `tracepoint-demo/src/usecase/port/process_seed.rs`, and `tracepoint-demo/src/usecase/port/cgroup.rs`
- usecase-internal orchestration:
  - files under `tracepoint-demo/src/usecase/orchestration/`
- PID or TTY wait behavior:
  - file: `tracepoint-demo/src/usecase/policy/watch_pid_or_tty.rs`
- container runtime behavior:
  - file: `tracepoint-demo/src/usecase/policy/watch_container.rs`
- systemd runtime behavior:
  - file: `tracepoint-demo/src/usecase/policy/watch_systemd_unit.rs`
- Docker runtime I/O and monitoring:
  - file: `tracepoint-demo/src/gateway/docker.rs`
- systemd runtime I/O and monitoring:
  - file: `tracepoint-demo/src/gateway/systemd.rs`
- eBPF loading, maps, and ring buffer handling:
  - file: `tracepoint-demo/src/gateway/ebpf.rs`
- kernel-side event generation:
  - file: `tracepoint-demo-ebpf/src/main.rs`

If you are not sure where a behavior lives, start from `trace_selected_targets.rs` for policy, from
`usecase/port/` for boundaries, and from `infra/bootstrap.rs` for top-level wiring.

## What each layer owns in this repository

### Entry file

`main.rs` stays deliberately tiny. It exists only to start bootstrap.

### `infra/bootstrap`

`infra/bootstrap` owns whole-program startup and runtime control.

- build concrete dependencies only when needed
- load the eBPF object
- call the relevant usecase entry
- start monitors once state is prepared
- enter the top-level runtime loop

The current files are `infra/bootstrap.rs`, `infra/startup.rs`, and `infra/runtime_loop.rs`.

### `infra/presentation`

`infra/presentation` owns user-facing edges.

- parse CLI input and map it into usecase request DTOs
- format startup, warning, shutdown, and exec-event messages
- provide signal-aware wait behavior used by the usecases
- adapt runtime updates for presentation-side handling when needed

The current files are under `infra/presentation/`.

### `usecase/policy`

`usecase/policy` owns the question: "what should the daemon do for this target selection?"

- watch explicit PIDs
- watch processes attached to a TTY
- watch processes inside a container
- watch processes belonging to a systemd unit

These policies define waiting rules, watch-root behavior, and runtime-update behavior without
depending on concrete Docker, systemd, procfs, or eBPF APIs.

The current files are under `usecase/policy/`.

### `usecase/port`

`usecase/port` owns the boundaries the usecases depend on.

- container runtime queries and monitoring
- systemd status queries and monitoring
- process seeding into the kernel-side watch state
- cgroup path and `cgroup.procs` lookup
- reporter and wait seams
- any future tracing backend seams needed to remove direct runtime-loop or startup wiring from
  usecases

Those abstractions belong to `usecase`, not to `gateway`, because the inner layer should own the
contracts that outer layers implement.

The current files are under `usecase/port/`.

### `usecase/orchestration`

`usecase/orchestration` owns internal step decomposition for usecases.

It exists to keep policy entry points small when a usecase needs shared coordination such as:

- planning startup watch roots
- merging static and runtime-derived roots
- maintaining runtime update DTOs and state records tied to usecase behavior
- shared normalization helpers closely tied to usecase flows

It does not own whole-program initialization. If the question is "how does the process boot and
wire concrete dependencies together?", that belongs to `infra/bootstrap`, not here.

The current files are under `usecase/orchestration/`.

### `gateway`

`gateway` owns concrete external operations and protocol details.

- `ebpf.rs`: load and attach programs, expose maps and ring buffers, seed state, and synchronize
  `WATCH_PIDS`
- `procfs.rs`: procfs and cgroup helpers
- `docker.rs`: container inspection, main-PID queries, and Docker monitoring
- `systemd.rs`: unit resolution, status queries, process listing, and D-Bus monitoring

This layer keeps protocol quirks, API details, and system-specific I/O out of the usecase layer.

## How the layers interact

1. `main.rs` hands control to bootstrap.
2. `infra/bootstrap` gathers presentation input, constructs concrete dependencies, and prepares the
   usecase request.
3. `usecase/policy` executes the user-intent flow and relies only on `usecase/port` traits.
4. `usecase/orchestration` helps multi-step usecase flows stay small and testable.
5. `gateway` implements the required ports and performs the external operations.
6. `infra/bootstrap` starts monitors and runs the top-level loop once the usecase returns prepared
   state.
7. `infra/presentation` formats the user-visible output.

The dependency direction should stay one-way:

- `usecase` owns policies and ports
- `gateway` depends on `usecase/port` to implement those contracts
- `infra` depends on both because it is the outer composition root

## One concrete execution trace

For a concrete example, consider `--container my-service`.

In the target architecture, the flow is:

1. `main.rs` enters `infra/bootstrap`.
2. `infra/presentation` parses the CLI and builds the request DTO.
3. `infra/bootstrap` prepares the concrete Docker client, eBPF handle, and any other required
   dependencies.
4. `usecase/policy` decides how the selected container should be watched.
5. `usecase/orchestration` prepares shared startup plan details such as merged watch roots.
6. `gateway/docker.rs` performs the concrete container query and monitor work.
7. `gateway/ebpf.rs` performs the concrete map and ring buffer work.
8. `infra/bootstrap` starts the runtime loop and hands user-visible output to
   `infra/presentation`.

In the current code, that bootstrap role lives under `infra/`, while the shared usecase planning
helpers live under `usecase/orchestration/`.

## Why there is no `domain/` layer

This repository does not have a rich business domain in the usual application sense.
Its core concern is not pricing, approval rules, or account lifecycles. Its core concern is
coordinating tracing-related behavior across eBPF, procfs, Docker, and systemd.

That means the central code is better described as:

- policy: what to watch and how to react
- port: what the policy needs from the outside world
- orchestration: how multi-step usecase flows stay readable

The main data types are mostly transport, runtime state, or shared ABI structures:

- `ExecEvent` and `TaskRel` in `tracepoint-demo-common` are shared ABI structs between eBPF and
  userspace
- `SystemdUnitRuntimeStatus` is a projection of D-Bus state
- `AppState` is primarily a runtime holder for watch maps and current roots
- container/systemd runtime records are coordination state, not rich domain entities

Adding a separate `domain/` layer here would mostly add translation code without isolating a more
stable business model.

## Why there is no `repository/` layer

This repository also does not benefit from a separate `repository/` layer.

The abstractions that the inner layer needs are not mostly persistence repositories. They are
outbound ports such as:

- query a container main PID
- query a systemd unit status
- start a monitor
- wait with interruption handling
- report user-visible status
- eventually seed or synchronize tracing state through a tracing backend port

Those contracts are better modeled as `usecase/port`, with `gateway` implementing them.
That keeps the dependency rule straightforward:

- inner layer defines the contract
- outer layer implements the contract

## Why there is no controller layer

There is also no separate controller layer because the application has a single interaction style:

- parse one CLI invocation
- prepare runtime state
- enter one async event loop
- react to runtime updates until Ctrl-C

That flow is already naturally owned by `infra/bootstrap` plus `infra/presentation`.
Adding controllers would mostly rename existing bootstrap and runtime coordination without creating
new behavioral separation.

## Design guardrails

- Keep `main.rs` thin.
- Keep whole-program initialization in `infra`, not in `usecase/orchestration`.
- Keep user-facing input and output in `infra/presentation`.
- Keep port traits owned by `usecase`.
- Keep `gateway` as the only layer that knows concrete external protocol details.
- Keep `usecase/policy` focused on user intent.
- Use `usecase/orchestration` only for internal usecase step decomposition, not as a second
  bootstrap layer.
- Introduce traits only when they improve testability or boundary clarity.
- Keep `tracepoint-demo-common` compatible across eBPF and userspace.
- Add new target modes as new policy modules when possible.
- Add new external integrations under `gateway/`.
