# tracepoint-demo design

## Purpose

This note describes the current user-space split in `tracepoint-demo`. It is a snapshot of the
implemented architecture, not a plan for a future rewrite.

## Why the split exists

`main.rs` is now a thin composition root because the daemon grew beyond simple PID tracing:

- CLI parsing and normalization
- eBPF loading and map operations
- PID and TTY target discovery
- Docker and systemd client initialization
- Docker and systemd runtime monitoring
- event-loop control and output formatting

Keeping those concerns in one file made the code harder to extend once Docker and systemd support
were added. The current split keeps the project small while separating user intent, application
wiring, and external I/O.

## Current layering

- `main.rs`: initialize logging, delegate startup, and start the runtime.
- `interface/`: CLI parsing, output, runtime loop, and concrete client initialization.
- `usecase/`: watch flows organized by user intent and the logic that merges roots into one watch set.
- `gateway/`: all external I/O, including Aya/eBPF, procfs/cgroup, Docker, and systemd.

This is intentionally "clean-architecture-like", not a full clean architecture.
The split follows where the code's complexity actually lives:

- input normalization and runtime wiring
- target-specific watch decisions
- kernel and system integration

It does not introduce layers that only rename these same responsibilities.

## What each layer owns in this repository

### `main.rs`

`main.rs` is deliberately tiny. Its job is to initialize logging and hand control to the
application builder. That keeps the process entry point obvious and avoids rebuilding startup logic
there.

### `interface/`

`interface` is the program edge.

- `cli.rs` defines `CliArgs` and normalizes raw input such as TTY names.
- `app_builder.rs` parses CLI input, initializes Docker and systemd clients only when needed, loads
  the eBPF object, and hands prepared resources to the usecase layer.
- `runtime_loop.rs` owns the top-level `tokio::select!` loop that listens to the ring buffer,
  runtime updates, and Ctrl-C.
- `output.rs` formats the user-facing startup and shutdown messages.
- `docker.rs` and `systemd.rs` exist to construct concrete clients; they are not business logic.

This layer knows concrete libraries such as `clap`, `bollard`, `zbus`, `tokio`, and Aya runtime
types because it is the boundary where those libraries enter the program.

### `usecase/`

`usecase` owns the "what should the daemon do for this target selection?" decisions.

- `startup.rs` translates parsed CLI input into initial watch roots, seeds initial state, and
  prepares the runtime session.
- `watch_pid_or_tty.rs` handles "wait until matching PIDs or TTY owners appear".
- `watch_container.rs` decides how a container should be seeded and how runtime PID changes are
  applied.
- `watch_systemd_unit.rs` does the same for systemd units, including the fallback rules when
  `MainPID` is unavailable.
- `watch_roots.rs` merges static roots with runtime-derived roots and synchronizes the final
  `WATCH_PIDS` set.
- `runtime_session.rs` starts background monitors and then enters the runtime loop.

This layer is where the repository's main logic lives. It is coordinating watch strategy, not
modelling a rich business domain.

### `gateway/`

`gateway` owns the system-specific details.

- `ebpf.rs` loads and attaches programs, reads the task iterator, seeds `PROC_STATE`, updates
  `WATCH_PIDS`, and drains exec events.
- `procfs.rs` reads `/proc` and cgroup files.
- `docker.rs` translates Docker inspection into "current main PID or none".
- `systemd.rs` translates D-Bus calls into "unit exists or not", "running or not", and
  "main PID / process list".

This keeps protocol details, API quirks, and map operations out of the usecase layer.

## How the layers interact

1. `main.rs` calls into `interface/app_builder.rs`.
2. `interface` parses CLI args, normalizes inputs, and initializes concrete clients only when needed.
3. `usecase` resolves the initial roots for each selected target mode.
4. `gateway` loads the BPF object, seeds maps, and queries external systems.
5. `usecase/watch_roots.rs` merges static and dynamic roots into the final watch set.
6. `interface/runtime_loop.rs` runs the event loop, drains exec events, forwards runtime updates, and
   handles Ctrl-C.

## Intent-oriented usecases

The `usecase` layer is split around user intent, not internal mechanics.

- `watch_pid_or_tty.rs` handles explicit PID and TTY watching.
- `watch_container.rs` handles container-based watching and PID changes over time.
- `watch_systemd_unit.rs` handles systemd-unit-based watching and activity changes.
- `watch_roots.rs` merges roots and synchronizes the desired watch set.

Support modules such as `startup.rs`, `state.rs`, `runtime_update.rs`, and `runtime_session.rs`
exist to keep `app.rs` small.

The important point is that the user-visible modes already define the natural seams:

- watch explicit PIDs
- watch processes attached to a TTY
- watch processes inside a container
- watch processes belonging to a systemd unit

Those seams are more meaningful in this daemon than generic "service", "controller", or
"repository" categories.

## Gateway boundaries

The `gateway` layer owns the protocol-specific code and keeps it close to the external system it
talks to.

- `gateway/ebpf.rs`: load and attach programs, expose maps and ring buffers, seed `PROC_STATE`, and
  synchronize `WATCH_PIDS`.
- `gateway/procfs.rs`: procfs and cgroup helpers.
- `gateway/docker.rs`: container inspection, main-PID queries, and runtime monitoring.
- `gateway/systemd.rs`: unit resolution, `MainPID` queries, process listing, and runtime monitoring.

`interface/docker.rs` and `interface/systemd.rs` are the edge where concrete clients are
constructed.

## Why there is no `domain/` layer

This repository does not have a rich business domain in the usual application sense.
Its core concern is not "business rules independent of infrastructure"; it is "observe process
execution by coordinating eBPF, procfs, Docker, and systemd".

The central data types are mostly transport or runtime state:

- `ExecEvent` and `TaskRel` in `tracepoint-demo-common` are shared ABI structs between eBPF and
  userspace.
- `SystemdUnitStatus` is a projection of D-Bus state.
- `AppState` is mostly a holder for watch maps, runtime handles, and current root sets.
- `ContainerRuntime` and `SystemdRuntime` are runtime tracking records, not long-lived domain
  entities with business invariants.

The main complexity is orchestration across external systems:

- load and attach BPF programs
- read task relationships from the iterator
- inspect Docker containers
- query systemd state
- update watch maps when runtime state changes

That complexity is already captured by `usecase` plus `gateway`.
Those layers already describe the stable concepts in this repository: target selection, watch-root
merging, runtime updates, and system interaction.

Adding a `domain/` layer here would mostly create one of two outcomes:

- thin wrappers around existing structs like "WatchTarget", "UnitState", or "ContainerState"
  without adding new rules
- adapters that immediately unwrap back into `u32`, `Option<u32>`, `HashMap<u32, u32>`, or shared
  ABI structs when talking to Aya, Docker, or systemd

In other words, it would add translation cost without isolating a meaningful business model.

For a business application, a domain layer often earns its keep because the core rules outlive the
delivery mechanism or persistence choice. Here the opposite is true: the daemon exists to connect a
CLI, an event loop, and kernel/system integrations. The external boundaries are the point of the
program, so pushing them behind an extra `domain/` layer would not clarify the design.

## Why there is no controller layer

There is also no separate controller layer because the application has a single interaction style:

- parse one CLI invocation
- prepare watchers and runtime state
- enter one async event loop
- react to runtime updates until Ctrl-C

`interface/app_builder.rs` already handles the entry-point wiring, and
`interface/runtime_loop.rs` already handles the top-level dispatch loop.

Adding controllers would not separate different transports such as HTTP, gRPC, GUI, or batch jobs,
because those transports do not exist here. It would mainly split one straightforward flow into
extra request/response or command-dispatch objects.

The current code also already has an explicit runtime dispatch shape:

- background monitors send `RuntimeUpdate`
- `runtime_loop.rs` receives the update
- the relevant usecase applies the state change
- `watch_roots.rs` resynchronizes `WATCH_PIDS`

That is controller-like enough for this daemon's needs. Turning it into a named controller layer
would mostly rename coordination that is already clear in `interface` and `usecase`, while adding
another place to keep in sync with the same update flow.

## Why this tradeoff is reasonable for a non-business daemon

This project is not centered on account rules, pricing logic, workflow approvals, or other
business concepts that need to be preserved independently of infrastructure.

It is centered on:

- attaching to a tracepoint
- seeding process state
- watching a few target-selection modes
- reacting to Docker and systemd changes
- printing events

For that kind of daemon, the best return comes from keeping the code easy to trace from the CLI to
the kernel map update, with as few translation layers as possible.

That is why the current split stops at `interface` / `usecase` / `gateway`.
It gives clear ownership and testable seams without introducing abstract layers that this
repository does not currently need.

## Design guardrails

- Avoid over-abstraction.
- Introduce traits only when they improve tests or boundary clarity.
- Keep `main.rs` thin.
- Keep `tracepoint-demo-common` compatible across eBPF and userspace.
- Add new target modes as new `usecase/watch_*.rs` modules when possible.
- Add new external integrations under `gateway/`.
