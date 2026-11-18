# tracepoint-demo design docs

## Reading guide

- [README](../README.md) has the build, run, and test commands.
- [Operations](operations.md) covers runtime behavior and the release workflow.
- [Userspace design](tracepoint-demo-design.md) follows the daemon from startup to event output.
- [eBPF design](tracepoint-demo-ebpf-design.md) covers the kernel programs, watch state, and shared ABI.

## Workspace map

- `tracepoint-demo/`: userspace daemon that parses CLI input, prepares watch state, loads the eBPF
  object, runs container/systemd monitors, and prints events
- `tracepoint-demo-ebpf/`: kernel-side programs attached to `sys_enter_execve`,
  `sched_process_fork`, and `sched_process_exit`. It also supplies an `iter/task` program for
  startup seeding.
- `tracepoint-demo-common/`: ABI boundary shared by userspace and eBPF, including `ExecEvent`,
  `TaskRel`, map names, and watch flags
