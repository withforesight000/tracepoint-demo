use std::{
    collections::{HashMap as StdHashMap, HashSet, VecDeque},
    convert::TryFrom,
    fs,
    io::Read,
    mem,
    path::PathBuf,
    ptr,
};

use aya::{
    Btf, Ebpf,
    maps::{RingBuf, hash_map::HashMap as UserHashMap},
    programs::{Iter, ProgramError, TracePoint},
};
use bollard::{Docker, errors::Error as BollardError, query_parameters::EventsOptions};
use clap::Parser;
use futures_util::StreamExt;
use log::debug;
use tokio::{io::unix::AsyncFd, select, signal};

#[derive(Parser)]
#[command(author, version, about = "Traces execve syscalls for a set of processes", long_about = None)]
#[command(arg_required_else_help = true)]
struct CliArgs {
    /// Repeated `--pid` arguments keep the option-style interface used in earlier versions.
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pid: Vec<u32>,

    /// Positional PIDs can be used instead of `--pid`.
    #[arg(value_name = "PID")]
    positional_pids: Vec<u32>,

    /// Monitor processes that share the specified controlling terminal.
    #[arg(long = "tty", value_name = "TTY")]
    tty: Vec<String>,

    /// Monitor processes inside the specified Docker container (by name or ID).
    #[arg(long = "container", value_name = "NAME_OR_ID")]
    container: Option<String>,

    /// Seed all processes currently in the container at startup.
    #[arg(long = "all-container-processes", requires = "container")]
    all_container_processes: bool,

    /// Do not follow child processes when tracing (default traces children as well).
    #[arg(long = "no-watch-children")]
    no_watch_children: bool,
}

use tracepoint_demo_common::{
    EXEC_EVENTS_MAP, ExecEvent, PROC_FLAG_WATCH_CHILDREN, PROC_FLAG_WATCH_SELF, PROC_STATE_MAP,
    TaskRel, WATCH_PIDS_MAP,
};

fn cstr_from_u8(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn normalize_tty_name(tty: &str) -> String {
    let name = tty.strip_prefix("/dev/").unwrap_or(tty);
    if let Some(rest) = name.strip_prefix("pts/") {
        format!("pts{rest}")
    } else {
        name.to_string()
    }
}

/// Seed PROC_STATE map by iterating over all tasks and building a parent-child
/// relationship map. This allows seeding based on PID and TTY filters, including
/// optionally following child processes.
fn seed_proc_state_from_task_iter(
    ebpf: &mut Ebpf,
    pid_roots: &[u32], // Root PIDs to seed.
    tty_filters: &HashSet<String>,
    watch_flags: u32,
) -> anyhow::Result<Vec<u32>> {
    let btf = Btf::from_sys_fs()?;
    let program: &mut Iter = ebpf.program_mut("iter_tasks").unwrap().try_into()?;
    if let Err(err) = program.load("task", &btf)
        && !matches!(err, ProgramError::AlreadyLoaded)
    {
        return Err(err.into());
    }
    let link_id = program.attach()?;
    let link = program.take_link(link_id)?;
    let mut file = link.into_file()?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    // Build parent->children map.
    let mut children: StdHashMap<u32, Vec<u32>> = StdHashMap::new();
    // Build pid->tty map.
    let mut pid_tty: StdHashMap<u32, String> = StdHashMap::new();
    for chunk in buf.chunks_exact(mem::size_of::<TaskRel>()) {
        let rel: TaskRel = unsafe { ptr::read_unaligned(chunk.as_ptr() as *const TaskRel) };
        children.entry(rel.ppid).or_default().push(rel.pid);
        let tty_name = cstr_from_u8(&rel.tty_name);
        if !tty_name.is_empty() {
            let normalized = normalize_tty_name(&tty_name);
            if !normalized.is_empty() {
                pid_tty.insert(rel.pid, normalized);
            }
        }
    }

    let mut proc_state: UserHashMap<_, u32, u32> = UserHashMap::try_from(
        ebpf.map_mut(PROC_STATE_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?,
    )?;

    // Determine which root PIDs to seed based on PID and TTY filters.
    let mut root_flags = StdHashMap::new();
    for &pid in pid_roots {
        root_flags.insert(pid, watch_flags);
    }

    if !tty_filters.is_empty() {
        for (pid, tty_name) in pid_tty {
            if tty_filters.contains(&tty_name) {
                root_flags.entry(pid).or_insert(watch_flags);
            }
        }
    }

    if root_flags.is_empty() {
        return Ok(Vec::new());
    }

    // Seed PROC_STATE for root PIDs and optionally their descendants.
    // Return the list of seeded root PIDs.
    let mut seeded_roots = Vec::new();

    for (&root_pid, &flags) in &root_flags {
        proc_state.insert(root_pid, flags, 0)?;
        seeded_roots.push(root_pid);

        if (flags & PROC_FLAG_WATCH_CHILDREN) == 0 {
            continue;
        }

        let mut q = VecDeque::new();
        let mut seen = HashSet::new();

        q.push_back(root_pid);
        seen.insert(root_pid);

        while let Some(ppid) = q.pop_front() {
            if let Some(children) = children.get(&ppid) {
                for &cpid in children {
                    if seen.insert(cpid) {
                        // if not seen,
                        proc_state.insert(cpid, flags, 0)?;
                        q.push_back(cpid);
                    }
                }
            }
        }
    }

    seeded_roots.sort_unstable();
    Ok(seeded_roots)
}

/// Seed PROC_STATE map directly with the specified PIDs and flags.
/// The differences vs. `seed_proc_state_from_task_iter` are:
/// - No TTY filtering.
/// - No child process following.
///
/// This is useful when the exact set of PIDs is already known.
fn seed_proc_state_direct(ebpf: &mut Ebpf, pids: &[u32], flags: u32) -> anyhow::Result<()> {
    if pids.is_empty() {
        return Ok(());
    }

    let mut proc_state: UserHashMap<_, u32, u32> = UserHashMap::try_from(
        ebpf.map_mut(PROC_STATE_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?,
    )?;

    for pid in pids {
        if let Err(err) = proc_state.insert(*pid, flags, 0) {
            return Err(anyhow::anyhow!(
                "failed to seed PROC_STATE for pid {}: {err}",
                pid
            ));
        }
    }

    Ok(())
}

fn read_cgroup_v2_path(pid: u32) -> anyhow::Result<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = fs::read_to_string(&path)?;

    for line in content.lines() {
        // cgroup v2 line format: "0::/some/path"
        if let Some(rest) = line.strip_prefix("0::") {
            let trimmed = rest.trim();
            if trimmed.is_empty() {
                return Ok("/".to_string());
            }
            return Ok(trimmed.to_string());
        }
    }

    Err(anyhow::anyhow!("cgroup v2 path not found in {}", path))
}

/// path assumes a cgroup v2 path like "/some/path", not a full filesystem path.
fn read_cgroup_procs(path: &str) -> anyhow::Result<Vec<u32>> {
    let mut full_path = PathBuf::from("/sys/fs/cgroup");
    let relative = path.trim_start_matches('/');
    if !relative.is_empty() {
        // Append relative path components.
        full_path.push(relative);
    }
    full_path.push("cgroup.procs");

    // content: a whitespace-separated list of PIDs
    let content = fs::read_to_string(&full_path)?;
    let mut pids = Vec::new();
    for token in content.split_whitespace() {
        let pid: u32 = token.parse().map_err(|err| {
            anyhow::anyhow!("invalid pid {} in {}: {err}", token, full_path.display())
        })?;
        pids.push(pid);
    }

    Ok(pids)
}

async fn wait_for_docker_event(
    docker: &Docker,
    container_filter: &str,
    display_name: &str,
    event: &str,
    action: &str,
) -> anyhow::Result<()> {
    let mut filters = StdHashMap::new();
    filters.insert("container".to_string(), vec![container_filter.to_string()]);
    filters.insert("event".to_string(), vec![event.to_string()]);
    filters.insert("type".to_string(), vec!["container".to_string()]);

    let mut events = docker.events(Some(EventsOptions {
        since: None,
        until: None,
        filters: Some(filters),
    }));

    select! {
        maybe_event = events.next() => match maybe_event {
            Some(Ok(_)) => Ok(()),
            Some(Err(err)) => Err(err.into()),
            None => Err(anyhow::anyhow!(
                "Docker event stream ended while waiting for container {display_name} to {action}."
            )),
        },
        _ = signal::ctrl_c() => Err(anyhow::anyhow!(
            "Interrupted while waiting for container {display_name} to {action}."
        )),
    }
}

async fn wait_container_running(
    docker: &Docker,
    name_or_id: &str,
) -> anyhow::Result<(String, u32)> {
    loop {
        match docker.inspect_container(name_or_id, None).await {
            Ok(inspect) => {
                let id = inspect
                    .id
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("Container {} has no id.", name_or_id))?;

                if let Some(state) = inspect.state
                    && state.running.unwrap_or(false)
                {
                    let pid = state.pid.unwrap_or(0);
                    if pid <= 0 {
                        return Err(anyhow::anyhow!(
                            "Container {} returned invalid PID.",
                            name_or_id
                        ));
                    }
                    return Ok((id, pid as u32));
                }

                println!("Waiting for container {name_or_id} to start...");
                wait_for_docker_event(docker, &id, name_or_id, "start", "start").await?;
            }
            Err(err) => match err {
                BollardError::DockerResponseServerError { status_code, .. }
                    if status_code == 404 =>
                {
                    println!("Waiting for container {name_or_id} to exist...");
                    wait_for_docker_event(docker, name_or_id, name_or_id, "create", "exist")
                        .await?;
                }
                _ => {
                    return Err(err.into());
                }
            },
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let CliArgs {
        pid,
        positional_pids,
        tty: tty_inputs,
        container,
        all_container_processes,
        no_watch_children,
    } = CliArgs::parse();

    let mut pids = pid;
    pids.extend(positional_pids);

    if pids.is_empty() && tty_inputs.is_empty() && container.is_none() {
        eprintln!("At least one PID, TTY, or container must be specified.");
        std::process::exit(1);
    }

    let mut tty_filters = HashSet::new();
    for tty in &tty_inputs {
        let normalized = normalize_tty_name(tty);
        if !normalized.is_empty() {
            tty_filters.insert(normalized);
        }
    }

    let watch_children = !no_watch_children;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tracepoint-demo"
    )))?;

    {
        let program: &mut TracePoint = ebpf
            .program_mut("tracepoint_demo")
            .ok_or_else(|| anyhow::anyhow!("program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;
    }

    {
        let fork: &mut TracePoint = ebpf.program_mut("on_fork").unwrap().try_into()?;
        fork.load()?;
        fork.attach("sched", "sched_process_fork")?;
    }

    {
        let exit: &mut TracePoint = ebpf.program_mut("on_exit").unwrap().try_into()?;
        exit.load()?;
        exit.attach("sched", "sched_process_exit")?;
    }

    let watch_flags = PROC_FLAG_WATCH_SELF
        | if watch_children {
            PROC_FLAG_WATCH_CHILDREN
        } else {
            0
        };

    // Seed PROC_STATE for explicit PID/TTY inputs first (container seeds are merged later).
    let mut watched_roots = Vec::new();
    if !pids.is_empty() || !tty_filters.is_empty() {
        watched_roots =
            seed_proc_state_from_task_iter(&mut ebpf, &pids, &tty_filters, watch_flags)?;
        if watched_roots.is_empty() && container.is_none() {
            eprintln!(
                "No processes matched PID(s) {:?} or tty(s) {:?}.",
                &pids, &tty_inputs
            );
            std::process::exit(1);
        }
    }

    // Resolve container PID (wait for start if needed) and seed PROC_STATE based on mode.
    let mut container_pid = None;
    let mut container_watch_flags = None;
    let mut container_display = None;
    if let Some(container_name) = container.as_deref() {
        let docker = Docker::connect_with_local_defaults()?;
        let (_container_id, main_pid) = wait_container_running(&docker, container_name).await?;

        let container_watch_children = if all_container_processes {
            true
        } else {
            watch_children
        };
        let container_flags = PROC_FLAG_WATCH_SELF
            | if container_watch_children {
                PROC_FLAG_WATCH_CHILDREN
            } else {
                0
            };

        container_pid = Some(main_pid);
        container_watch_flags = Some(container_flags);
        container_display = Some(format!("container={container_name} pid={main_pid}"));

        if all_container_processes {
            match read_cgroup_v2_path(main_pid).and_then(|path| read_cgroup_procs(&path)) {
                Ok(pids) => seed_proc_state_direct(&mut ebpf, &pids, container_flags)?,
                Err(err) => {
                    eprintln!(
                        "Failed to read cgroup.procs for container {} (pid {}): {}. Falling back to task iterator seed.",
                        container_name, main_pid, err
                    );
                    let empty_tty_filters = HashSet::new();
                    let _ = seed_proc_state_from_task_iter(
                        &mut ebpf,
                        &[main_pid],
                        &empty_tty_filters,
                        container_flags,
                    )?;
                }
            }
        } else if container_watch_children {
            let empty_tty_filters = HashSet::new();
            let _ = seed_proc_state_from_task_iter(
                &mut ebpf,
                &[main_pid],
                &empty_tty_filters,
                container_flags,
            )?;
        } else {
            seed_proc_state_direct(&mut ebpf, &[main_pid], container_flags)?;
        }
    }

    {
        let map = ebpf
            .map_mut(WATCH_PIDS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map not found"))?;
        let mut watch_pids: UserHashMap<_, u32, u32> = UserHashMap::try_from(map)?;
        for pid in &watched_roots {
            watch_pids.insert(*pid, watch_flags, 0)?;
        }
        if let (Some(pid), Some(flags)) = (container_pid, container_watch_flags) {
            watch_pids.insert(pid, flags, 0)?;
        }
    }

    let ring_map = ebpf
        .take_map(EXEC_EVENTS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let ring = RingBuf::try_from(ring_map)?;
    let mut async_ring = AsyncFd::new(ring)?;

    let child_status = if watch_children {
        "watch_children=on"
    } else {
        "watch_children=off"
    };

    let container_suffix = if let Some(display) = container_display.as_deref() {
        if all_container_processes {
            format!(" {display} seed=all-procs")
        } else {
            format!(" {display}")
        }
    } else {
        String::new()
    };

    let has_roots = !watched_roots.is_empty();
    if tty_inputs.is_empty() {
        if has_roots {
            println!(
                "Watching execve syscalls for PIDs: {:?} ({}){} (Ctrl-C to exit)",
                &watched_roots, child_status, container_suffix
            );
        } else {
            println!(
                "Watching execve syscalls ({}){} (Ctrl-C to exit)",
                child_status, container_suffix
            );
        }
    } else if has_roots {
        println!(
            "Watching execve syscalls for PIDs: {:?} (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            &watched_roots, &tty_inputs, child_status, container_suffix
        );
    } else {
        println!(
            "Watching execve syscalls (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            &tty_inputs, child_status, container_suffix
        );
    }

    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();

                while let Some(item) = ring.next() {
                    let bytes = &item;
                    if bytes.len() != mem::size_of::<ExecEvent>() {
                        eprintln!("unexpected ExecEvent size: {} (expected {})", bytes.len(), mem::size_of::<ExecEvent>());
                        continue;
                    }

                    let event: ExecEvent = unsafe { *(bytes.as_ptr() as *const ExecEvent) };

                    println!(
                        "[{:.6}] pid={} tid={} uid={} gid={} syscall_id={} \
                         comm=\"{}\" filename=\"{}\" argv0=\"{}\"",
                        event.ktime_ns as f64 / 1e9,
                        event.pid,
                        event.tid,
                        event.uid,
                        event.gid,
                        event.syscall_id,
                        cstr_from_u8(&event.comm),
                        cstr_from_u8(&event.filename),
                        cstr_from_u8(&event.argv0),
                    );
                }

                guard.clear_ready();
            }

            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
