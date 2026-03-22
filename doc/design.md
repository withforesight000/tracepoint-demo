# tracepoint-demo design

## Purpose

This note describes the current user-space split in `tracepoint-demo`. It is a snapshot of the
implemented architecture, not a plan for a future rewrite.

It is also meant to be a reading guide for contributors who do not yet know the repository well.
If you are opening this project for the first time, this document should help you answer two
questions quickly:

- where the main execution path starts
- which file to open next for the kind of change you want to make

## First orientation

Before diving into the layers, keep this mental model in mind:

- the CLI chooses target-selection modes such as PID, TTY, container, or systemd unit
- startup code resolves those selections into an initial watch set
- runtime monitors keep that watch set up to date while the daemon runs
- the eBPF side emits `execve` events for watched processes and userspace prints them

The workspace is split across three crates:

- `tracepoint-demo/`: userspace daemon and the main code discussed in this document
- `tracepoint-demo-ebpf/`: kernel-side eBPF programs attached by userspace
- `tracepoint-demo-common/`: structs and constants shared across the userspace/eBPF boundary

If you only want to understand the userspace architecture, start with `tracepoint-demo/` and come
back to the eBPF crate later.

## Suggested reading order

For a first pass through the code, read these files in order:

1. `tracepoint-demo/src/main.rs`: process entry point
2. `tracepoint-demo/src/interface/app_builder.rs`: CLI parsing and concrete dependency setup
3. `tracepoint-demo/src/usecase/trace_selected_targets.rs`: user-intent entry point
4. `tracepoint-demo/src/usecase/support/startup.rs`: initial target resolution and startup state
5. `tracepoint-demo/src/usecase/watch_*.rs`: target-mode-specific runtime behavior
6. `tracepoint-demo/src/interface/runtime_loop.rs`: main async loop while the daemon is running
7. `tracepoint-demo/src/gateway/*.rs`: actual system and eBPF integration details

That path follows the same order the program follows at runtime, so it is the fastest route to a
working mental model.

## Key terms

Some terms appear repeatedly in the code and are easy to confuse on a first read:

- watch root: a PID that userspace explicitly asks the kernel-side logic to track
- static watch roots: roots discovered at startup from explicit PID or TTY selection
- runtime-derived roots: roots learned later from Docker or systemd monitoring
- watch set: the final merged PID set written into `WATCH_PIDS`
- `PROC_STATE`: kernel-side per-process cache used while following descendants
- runtime update: a userspace message saying that container or systemd state changed

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
- `usecase/`: user-intent entry points at the top level, with shared orchestration helpers under `usecase/support/`.
- `gateway/`: all external I/O, including Aya/eBPF, procfs/cgroup, Docker, and systemd.

This is intentionally "clean-architecture-like", not a full clean architecture.
The split follows where the code's complexity actually lives:

- input normalization and runtime wiring
- target-specific watch decisions
- kernel and system integration

It does not introduce layers that only rename these same responsibilities.

## If you want to change...

This section is the quickest file lookup guide for common changes.

- CLI flags or input normalization: `tracepoint-demo/src/interface/cli.rs`
- startup wiring and concrete client creation: `tracepoint-demo/src/interface/app_builder.rs`
- startup target resolution: `tracepoint-demo/src/usecase/support/startup.rs`
- PID or TTY wait behavior: `tracepoint-demo/src/usecase/watch_pid_or_tty.rs`
- container runtime behavior: `tracepoint-demo/src/usecase/watch_container.rs`
- systemd runtime behavior: `tracepoint-demo/src/usecase/watch_systemd_unit.rs`
- watch-set merge logic: `tracepoint-demo/src/usecase/support/watch_roots.rs`
- runtime update dispatch: `tracepoint-demo/src/interface/runtime_updates.rs`
- main event loop: `tracepoint-demo/src/interface/runtime_loop.rs`
- eBPF program loading, maps, and ring buffer handling: `tracepoint-demo/src/gateway/ebpf.rs`
- kernel-side event generation: `tracepoint-demo-ebpf/src/main.rs`

If you are not sure where a behavior lives, start from `trace_selected_targets.rs` and follow the
call chain outward. In this repository, that is usually faster than searching for an abstract
architecture term like "service" or "controller".

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
- `runtime_updates.rs` adapts `AppState` mutations to the generic runtime update dispatcher.
- `runtime_update_dispatch.rs` contains the pure dispatch seam that routes `RuntimeUpdate` values.
- `output.rs` formats the user-facing startup and shutdown messages.
- `docker.rs` and `systemd.rs` exist to construct concrete clients; they are not business logic.

This layer knows concrete libraries such as `clap`, `bollard`, `zbus`, `tokio`, and Aya runtime
types because it is the boundary where those libraries enter the program.

### `usecase/`

`usecase` owns the "what should the daemon do for this target selection?" decisions.

- `trace_selected_targets.rs` is the usecase entry point for "trace execs for the selected
  targets".
- `support/startup.rs` translates parsed CLI input into initial watch roots, seeds initial state, and
  prepares the initial runtime state.
- `watch_pid_or_tty.rs` handles "wait until matching PIDs or TTY owners appear".
- `watch_container.rs` decides how a container should be seeded and how runtime PID changes are
  applied.
- `watch_systemd_unit.rs` does the same for systemd units, including the fallback rules when
  `MainPID` is unavailable.
- `support/watch_roots.rs` merges static roots with runtime-derived roots and synchronizes the final
  `WATCH_PIDS` set.
- `usecase/support/` contains `startup_prepare.rs`, `container_monitor.rs`, `systemd_monitor.rs`,
  `runtime_update.rs`, `state.rs`, and `watch_roots.rs` so the top-level usecases stay focused on
  user-visible actions while the shared orchestration stays testable.

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
5. `usecase/support/startup.rs` and the target-specific watch modules prepare the initial runtime state.
6. `usecase/support/watch_roots.rs` merges static and dynamic roots into the final watch set.
7. `usecase/trace_selected_targets.rs` starts target monitors and enters the runtime loop.
8. `interface/runtime_loop.rs` drains exec events, forwards runtime updates, and handles Ctrl-C.

## One concrete execution trace

For a concrete example, consider `--container my-service`:

1. `interface/app_builder.rs` parses the CLI and opens a Docker client.
2. `usecase/trace_selected_targets.rs` calls into startup preparation.
3. `usecase/support/startup.rs` queries the container's current main PID and seeds initial watch state.
4. `usecase/support/watch_roots.rs` builds the merged watch set and writes it into `WATCH_PIDS`.
5. `usecase/watch_container.rs` spawns a monitor for later container PID changes.
6. `interface/runtime_loop.rs` keeps draining exec events and applying runtime updates.
7. `gateway/ebpf.rs` remains the layer that actually talks to maps, programs, and the ring buffer.

If you can follow that path, the rest of the repository will feel much less opaque.

## Intent-oriented usecases

The main public entry in `usecase` is split around user intent, not internal mechanics.

- `trace_selected_targets.rs` represents the user-visible goal: start tracing execs for the chosen
  PID, TTY, container, and systemd selections.

- `watch_pid_or_tty.rs` handles explicit PID and TTY watching.
- `watch_container.rs` handles container-based watching and PID changes over time.
- `watch_systemd_unit.rs` handles systemd-unit-based watching and activity changes.

Support modules such as `support/startup.rs`, `support/startup_prepare.rs`,
`support/container_monitor.rs`, `support/systemd_monitor.rs`, `support/watch_roots.rs`,
`support/state.rs`, and `support/runtime_update.rs` exist to keep those intent-facing entries
small while isolating integration-heavy coordination.

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
- `gateway/docker.rs`: container inspection and main-PID queries.
- `gateway/systemd.rs`: unit resolution, `MainPID` queries, and process listing.

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
- `runtime_loop.rs` receives the update and delegates update application through
  `runtime_updates.rs`
- the relevant usecase applies the state change
- `support/watch_roots.rs` resynchronizes `WATCH_PIDS`

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
- Keep the public usecase entry named after user intent; keep extracted startup, root-merging, and
  monitor seams under `usecase/support/` rather than as new top-level architectural layers.
- Add new target modes as new `usecase/watch_*.rs` modules when possible.
- Add new external integrations under `gateway/`.
