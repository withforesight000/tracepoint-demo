# tracepoint-demo design docs

This directory now splits the design notes by crate so each document can describe the current
implementation without mixing userspace and eBPF details.

## Reading guide

- `README.md`: user-facing build, run, and test commands
- `doc/operations.md`: runtime behavior, operational notes, and release workflow
- `doc/tracepoint-demo-design.md`: userspace daemon architecture and runtime flow
- `doc/tracepoint-demo-ebpf-design.md`: kernel-side eBPF architecture and ABI notes

## Workspace map

- `tracepoint-demo/`: userspace daemon that parses CLI input, prepares watch state, loads the eBPF
  object, runs container/systemd monitors, and prints events
- `tracepoint-demo-ebpf/`: kernel-side programs attached to `sys_enter_execve`,
  `sched_process_fork`, `sched_process_exit`, and `iter/task`
- `tracepoint-demo-common/`: ABI boundary shared by userspace and eBPF, including `ExecEvent`,
  `TaskRel`, map names, and watch flags

Read the userspace and eBPF design notes together when you need the full end-to-end picture. Read
them separately when you are changing only one side of the boundary.
