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
    maps::{MapData, RingBuf, hash_map::HashMap as UserHashMap},
    programs::{Iter, ProgramError, TracePoint},
};
use bollard::{Docker, errors::Error as BollardError, query_parameters::EventsOptions};
use clap::{ArgGroup, Parser};
use futures_util::StreamExt;
use log::debug;
use tokio::time::{Duration, sleep};
use tokio::{io::unix::AsyncFd, select, signal, sync::mpsc};
use zbus::Error as ZbusError;
use zbus::fdo::PropertiesProxy;
use zbus::zvariant::OwnedObjectPath;
use zbus_systemd::systemd1::{ManagerProxy, ServiceProxy, UnitProxy};

#[derive(Parser)]
#[command(author, version, about = "Traces execve syscalls for a set of processes", long_about = None)]
#[command(arg_required_else_help = true)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(true)
        .args(["pid", "positional_pids", "tty", "container", "systemd_unit"])
))]
struct CliArgs {
    /// Repeated `--pid` arguments keep the option-style interface used in earlier versions.
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pid: Vec<u32>,

    /// Positional PIDs can be used instead of `--pid`.
    #[arg(value_name = "PID", conflicts_with_all = ["pid", "tty", "container", "systemd_unit"])]
    positional_pids: Vec<u32>,

    /// Monitor processes that share the specified controlling terminal.
    #[arg(
        short = 't',
        long = "tty",
        value_name = "TTY",
        conflicts_with_all = ["pid", "positional_pids", "container", "systemd_unit"]
    )]
    tty: Vec<String>,

    /// Monitor processes inside the specified Docker container (by name or ID).
    #[arg(
        short = 'c',
        long = "container",
        value_name = "NAME_OR_ID",
        conflicts_with_all = ["pid", "positional_pids", "tty"]
    )]
    container: Vec<String>,

    /// Seed all processes currently in the container at startup.
    /// This is useful to processes to start with `docker exec`.
    #[arg(long = "all-container-processes", requires = "container")]
    all_container_processes: bool,

    /// Monitor processes inside the specified systemd unit.
    #[arg(
        short = 'u',
        long = "systemd-unit",
        value_name = "UNIT",
        conflicts_with_all = ["pid", "positional_pids", "tty"]
    )]
    systemd_unit: Vec<String>,

    /// Seed all processes currently in the systemd unit at startup.
    #[arg(long = "all-systemd-processes", requires = "systemd_unit")]
    all_systemd_processes: bool,

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

fn drain_exec_events(ring: &mut RingBuf<MapData>) {
    while let Some(item) = ring.next() {
        let bytes = &item;
        if bytes.len() != mem::size_of::<ExecEvent>() {
            eprintln!(
                "unexpected ExecEvent size: {} (expected {})",
                bytes.len(),
                mem::size_of::<ExecEvent>()
            );
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
}

fn normalize_tty_name(tty: &str) -> String {
    let name = tty.strip_prefix("/dev/").unwrap_or(tty);
    if let Some(rest) = name.strip_prefix("pts/") {
        format!("pts{rest}")
    } else {
        name.to_string()
    }
}

fn ensure_task_iter_program_loaded(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let btf = Btf::from_sys_fs()?;
    let program: &mut Iter = ebpf.program_mut("iter_tasks").unwrap().try_into()?;
    if let Err(err) = program.load("task", &btf) {
        if !matches!(err, ProgramError::AlreadyLoaded) {
            return Err(err.into());
        }
    }
    Ok(())
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
    let mut buf = Vec::new();
    {
        let program: &mut Iter = ebpf.program_mut("iter_tasks").unwrap().try_into()?;
        let link_id = program.attach()?;
        let link = program.take_link(link_id)?;
        let mut file = link.into_file()?;

        file.read_to_end(&mut buf)?;
    }

    let pid_roots_set: HashSet<u32> = pid_roots.iter().copied().collect();
    // Determine which root PIDs to seed based on PID and TTY filters.
    let mut root_flags = StdHashMap::new();
    // Build parent->children map.
    let mut children: StdHashMap<u32, Vec<u32>> = StdHashMap::new();
    // Build pid->tty map.
    let mut pid_tty: StdHashMap<u32, String> = StdHashMap::new();
    for chunk in buf.chunks_exact(mem::size_of::<TaskRel>()) {
        let rel: TaskRel = unsafe { ptr::read_unaligned(chunk.as_ptr() as *const TaskRel) };
        if pid_roots_set.contains(&rel.pid) {
            root_flags.entry(rel.pid).or_insert(watch_flags);
        }
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

fn ensure_non_root_cgroup_path(path: &str, label: &str) -> anyhow::Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Err(anyhow::anyhow!(
            "{label} is attached to the root cgroup, refusing to seed all host processes"
        ));
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
            ensure_non_root_cgroup_path(trimmed, "container")?;
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

#[derive(Debug)]
struct SystemdUnitStatus {
    active_state: String,
    sub_state: String,
    main_pid: Option<u32>,
}

impl SystemdUnitStatus {
    fn is_running(&self) -> bool {
        matches!(self.active_state.as_str(), "active" | "reloading")
    }
}

enum SystemdUnitLookupError {
    NotFound,
    Other(anyhow::Error),
}

struct ResolvedSystemdUnit<'a> {
    _unit_path: OwnedObjectPath,
    unit_proxy: UnitProxy<'a>,
    service_proxy: ServiceProxy<'a>,
}

struct ContainerRuntime {
    docker: Docker,
    name_or_id: String,
    watch_children: bool,
    all_processes: bool,
    flags: u32,
    current_pid: Option<u32>,
}

struct SystemdRuntime {
    conn: zbus::Connection,
    unit_name: String,
    watch_children: bool,
    all_processes: bool,
    flags: u32,
    current_pid: Option<u32>,
    current_running: bool,
}

enum RuntimeUpdate {
    ContainerPid {
        index: usize,
        pid: Option<u32>,
    },
    SystemdStatus {
        index: usize,
        pid: Option<u32>,
        running: bool,
    },
    MonitorError {
        label: String,
        error: String,
    },
}

const SYSTEMD_ERROR_NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
const DBUS_ERROR_UNKNOWN_INTERFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";
const DBUS_ERROR_UNKNOWN_PROPERTY: &str = "org.freedesktop.DBus.Error.UnknownProperty";

fn is_zbus_method_error(err: &ZbusError, expected: &str) -> bool {
    matches!(err, ZbusError::MethodError(name, _, _) if **name == expected)
}

/// Query the systemd unit status using the provided proxies.
/// Returns `SystemdUnitLookupError::NotFound` if the unit is not found, which can happen if the unit was removed
/// after being resolved. Other errors are returned as `SystemdUnitLookupError::Other`.
async fn query_systemd_unit_status(
    unit_proxy: &UnitProxy<'_>,
    service_proxy: &ServiceProxy<'_>,
) -> Result<SystemdUnitStatus, SystemdUnitLookupError> {
    let active_state = unit_proxy
        .active_state()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;
    let sub_state = unit_proxy
        .sub_state()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;

    let main_pid = match service_proxy.main_pid().await {
        Ok(0) => None,
        Ok(pid) => Some(pid),
        Err(err)
            if is_zbus_method_error(&err, DBUS_ERROR_UNKNOWN_INTERFACE)
                || is_zbus_method_error(&err, DBUS_ERROR_UNKNOWN_PROPERTY) =>
        {
            None
        }
        Err(err) => return Err(SystemdUnitLookupError::Other(err.into())),
    };

    Ok(SystemdUnitStatus {
        active_state,
        sub_state,
        main_pid,
    })
}

/// Resolve the systemd unit by name and return proxies for querying its status.
/// If the unit is not found, returns `SystemdUnitLookupError::NotFound`. Other errors are returned as
/// `SystemdUnitLookupError::Other`.
async fn resolve_systemd_unit<'a>(
    conn: &'a zbus::Connection,
    manager: &ManagerProxy<'a>,
    unit_name: &str,
) -> Result<ResolvedSystemdUnit<'a>, SystemdUnitLookupError> {
    let unit_path = manager
        .load_unit(unit_name.to_string())
        .await
        .map_err(|err| {
            if is_zbus_method_error(&err, SYSTEMD_ERROR_NO_SUCH_UNIT) {
                SystemdUnitLookupError::NotFound
            } else {
                SystemdUnitLookupError::Other(err.into())
            }
        })?;

    let unit_proxy = UnitProxy::builder(conn)
        .path(unit_path.clone())
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?
        .build()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;

    let service_proxy = ServiceProxy::builder(conn)
        .path(unit_path.clone())
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?
        .build()
        .await
        .map_err(|err| SystemdUnitLookupError::Other(err.into()))?;

    Ok(ResolvedSystemdUnit {
        _unit_path: unit_path,
        unit_proxy,
        service_proxy,
    })
}

async fn systemd_unit_pids(conn: &zbus::Connection, unit_name: &str) -> anyhow::Result<Vec<u32>> {
    let manager = ManagerProxy::new(conn).await?;
    let entries = manager.get_unit_processes(unit_name.to_string()).await?;
    let mut pids = Vec::new();
    let mut seen = HashSet::new();
    for (_, pid, _) in entries {
        if pid != 0 && seen.insert(pid) {
            pids.push(pid);
        }
    }
    Ok(pids)
}

async fn seed_systemd_unit_processes(
    ebpf: &mut Ebpf,
    conn: &zbus::Connection,
    unit_name: &str,
    main_pid: Option<u32>,
    unit_flags: u32,
    unit_watch_children: bool,
    all_systemd_processes: bool,
) -> anyhow::Result<()> {
    if all_systemd_processes {
        match systemd_unit_pids(conn, unit_name).await {
            Ok(pids) => seed_proc_state_direct(ebpf, &pids, unit_flags)?,
            Err(err) => {
                let main_pid = main_pid.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Failed to get all processes for systemd unit {}: {}. No MainPID is available for fallback.",
                        unit_name, err
                    )
                })?;
                eprintln!(
                    "Failed to get all processes for systemd unit {}: {}. Falling back to task iterator seed.",
                    unit_name, err
                );
                let empty_tty_filters = HashSet::new();
                let _ = seed_proc_state_from_task_iter(
                    ebpf,
                    &[main_pid],
                    &empty_tty_filters,
                    unit_flags,
                )?;
            }
        }
        return Ok(());
    }

    let main_pid = main_pid.ok_or_else(|| {
        anyhow::anyhow!(
            "systemd unit {} has no MainPID while active. \
             Use --all-systemd-processes for units without MainPID.",
            unit_name
        )
    })?;

    if unit_watch_children {
        let empty_tty_filters = HashSet::new();
        let _ = seed_proc_state_from_task_iter(ebpf, &[main_pid], &empty_tty_filters, unit_flags)?;
    } else {
        seed_proc_state_direct(ebpf, &[main_pid], unit_flags)?;
    }

    Ok(())
}

fn add_watch_root(watch_roots: &mut StdHashMap<u32, u32>, pid: u32, flags: u32) {
    watch_roots
        .entry(pid)
        .and_modify(|existing| *existing |= flags)
        .or_insert(flags);
}

fn collect_watch_roots(
    static_roots: &StdHashMap<u32, u32>,
    container_runtimes: &[ContainerRuntime],
    systemd_runtimes: &[SystemdRuntime],
) -> StdHashMap<u32, u32> {
    let mut roots = static_roots.clone();

    for runtime in container_runtimes {
        if let Some(pid) = runtime.current_pid {
            add_watch_root(&mut roots, pid, runtime.flags);
        }
    }

    for runtime in systemd_runtimes {
        if let Some(pid) = runtime.current_pid {
            add_watch_root(&mut roots, pid, runtime.flags);
        }
    }

    roots
}

fn sync_watch_pids(
    watch_pids: &mut UserHashMap<MapData, u32, u32>,
    current_roots: &mut StdHashMap<u32, u32>,
    desired_roots: &StdHashMap<u32, u32>,
) -> anyhow::Result<()> {
    let removals: Vec<u32> = current_roots
        .keys()
        .filter(|pid| !desired_roots.contains_key(pid))
        .copied()
        .collect();
    for pid in removals {
        watch_pids.remove(&pid)?;
    }

    for (&pid, &flags) in desired_roots {
        if current_roots.get(&pid).copied() != Some(flags) {
            watch_pids.insert(pid, flags, 0)?;
        }
    }

    *current_roots = desired_roots.clone();
    Ok(())
}

fn build_watch_pids_and_ring(
    ebpf: &mut Ebpf,
    watched_roots: &StdHashMap<u32, u32>,
) -> anyhow::Result<(UserHashMap<MapData, u32, u32>, AsyncFd<RingBuf<MapData>>)> {
    let map = ebpf
        .take_map(WATCH_PIDS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let mut watch_pids: UserHashMap<_, u32, u32> = UserHashMap::try_from(map)?;
    for (&pid, &flags) in watched_roots {
        watch_pids.insert(pid, flags, 0)?;
    }

    let ring_map = ebpf
        .take_map(EXEC_EVENTS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map not found"))?;
    let ring = RingBuf::try_from(ring_map)?;
    let async_ring = AsyncFd::new(ring)?;

    Ok((watch_pids, async_ring))
}

async fn run_plain_event_loop(async_ring: &mut AsyncFd<RingBuf<MapData>>) -> anyhow::Result<()> {
    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();
                drain_exec_events(ring);
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

/// Wait for the specified systemd unit to be active and return its status.
/// If the unit does not exist or is not active yet, this function will poll until it is.
/// The unit is considered active if its ActiveState is "active" or "reloading".
async fn wait_systemd_unit_running<'a>(
    conn: &'a zbus::Connection,
    unit_name: &str,
) -> anyhow::Result<(ResolvedSystemdUnit<'a>, SystemdUnitStatus)> {
    let mut last_notice = String::new();
    let manager = ManagerProxy::new(conn)
        .await
        .map_err(|err| anyhow::anyhow!("failed to create systemd manager proxy: {err}"))?;
    let mut resolved_unit: Option<ResolvedSystemdUnit<'_>> = None;

    loop {
        if resolved_unit.is_none() {
            match resolve_systemd_unit(conn, &manager, unit_name).await {
                Ok(unit) => {
                    resolved_unit = Some(unit);
                }
                Err(SystemdUnitLookupError::NotFound) => {
                    let notice = format!("Waiting for systemd unit {unit_name} to exist...");
                    if notice != last_notice {
                        println!("{notice}");
                        last_notice = notice;
                    }
                }
                Err(SystemdUnitLookupError::Other(err)) => return Err(err),
            }
        }

        if let Some(cached_unit) = resolved_unit.as_ref() {
            match query_systemd_unit_status(&cached_unit.unit_proxy, &cached_unit.service_proxy)
                .await
            {
                Ok(status) => {
                    if status.is_running() {
                        let resolved_unit = resolved_unit
                            .take()
                            .expect("resolved_unit should exist when status is running");
                        return Ok((resolved_unit, status));
                    }

                    let notice = format!(
                        "Waiting for systemd unit {unit_name} to start (state={} substate={})...",
                        status.active_state, status.sub_state
                    );
                    if notice != last_notice {
                        println!("{notice}");
                        last_notice = notice;
                    }
                }
                Err(SystemdUnitLookupError::NotFound) => {
                    resolved_unit = None;
                    let notice = format!("Waiting for systemd unit {unit_name} to exist...");
                    if notice != last_notice {
                        println!("{notice}");
                        last_notice = notice;
                    }
                }
                Err(SystemdUnitLookupError::Other(err)) => return Err(err),
            }
        }

        select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = signal::ctrl_c() => return Err(anyhow::anyhow!(
                "Interrupted while waiting for systemd unit {unit_name} state to change."
            )),
        }
    }
}

async fn query_container_main_pid(
    docker: &Docker,
    name_or_id: &str,
) -> anyhow::Result<Option<u32>> {
    match docker.inspect_container(name_or_id, None).await {
        Ok(inspect) => {
            if let Some(state) = inspect.state {
                if state.running.unwrap_or(false) {
                    let pid = state.pid.unwrap_or(0);
                    if pid <= 0 {
                        return Err(anyhow::anyhow!(
                            "Container {} returned invalid PID.",
                            name_or_id
                        ));
                    }
                    return Ok(Some(pid as u32));
                }
            }
            Ok(None)
        }
        Err(err) => match err {
            BollardError::DockerResponseServerError { status_code, .. } if status_code == 404 => {
                Ok(None)
            }
            _ => Err(err.into()),
        },
    }
}

async fn seed_container_processes(
    ebpf: &mut Ebpf,
    name_or_id: &str,
    main_pid: u32,
    container_flags: u32,
    container_watch_children: bool,
    all_container_processes: bool,
) -> anyhow::Result<()> {
    if all_container_processes {
        match read_cgroup_v2_path(main_pid).and_then(|path| read_cgroup_procs(&path)) {
            Ok(pids) => seed_proc_state_direct(ebpf, &pids, container_flags)?,
            Err(err) => {
                eprintln!(
                    "Failed to read cgroup.procs for container {} (pid {}): {}. Falling back to task iterator seed.",
                    name_or_id, main_pid, err
                );
                let empty_tty_filters = HashSet::new();
                let _ = seed_proc_state_from_task_iter(
                    ebpf,
                    &[main_pid],
                    &empty_tty_filters,
                    container_flags,
                )?;
            }
        }
        return Ok(());
    }

    if container_watch_children {
        let empty_tty_filters = HashSet::new();
        let _ =
            seed_proc_state_from_task_iter(ebpf, &[main_pid], &empty_tty_filters, container_flags)?;
    } else {
        seed_proc_state_direct(ebpf, &[main_pid], container_flags)?;
    }

    Ok(())
}

async fn apply_container_runtime_update(
    ebpf: &mut Ebpf,
    runtime: &mut ContainerRuntime,
    next_pid: Option<u32>,
) -> anyhow::Result<()> {
    if runtime.current_pid == next_pid {
        return Ok(());
    }

    if let Some(pid) = next_pid {
        seed_container_processes(
            ebpf,
            &runtime.name_or_id,
            pid,
            runtime.flags,
            runtime.watch_children,
            runtime.all_processes,
        )
        .await?;
    }

    runtime.current_pid = next_pid;
    Ok(())
}

async fn apply_systemd_runtime_update(
    ebpf: &mut Ebpf,
    runtime: &mut SystemdRuntime,
    next_pid: Option<u32>,
    running: bool,
) -> anyhow::Result<()> {
    if runtime.current_pid == next_pid && runtime.current_running == running {
        return Ok(());
    }

    if running && (runtime.all_processes || next_pid.is_some()) {
        seed_systemd_unit_processes(
            ebpf,
            &runtime.conn,
            &runtime.unit_name,
            next_pid,
            runtime.flags,
            runtime.watch_children,
            runtime.all_processes,
        )
        .await?;
    }

    runtime.current_pid = next_pid;
    runtime.current_running = running;
    Ok(())
}

async fn monitor_container_runtime(
    docker: Docker,
    name_or_id: String,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    let mut filters = StdHashMap::new();
    filters.insert("container".to_string(), vec![name_or_id.clone()]);
    filters.insert("type".to_string(), vec!["container".to_string()]);

    let mut events = docker.events(Some(EventsOptions {
        since: None,
        until: None,
        filters: Some(filters),
    }));

    let mut current_pid = query_container_main_pid(&docker, &name_or_id).await?;
    let _ = tx.send(RuntimeUpdate::ContainerPid {
        index,
        pid: current_pid,
    });

    loop {
        select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(err.into()),
                    None => return Err(anyhow::anyhow!(
                        "Docker event stream ended while monitoring container {name_or_id}."
                    )),
                }

                let next_pid = query_container_main_pid(&docker, &name_or_id).await?;
                if next_pid != current_pid {
                    current_pid = next_pid;
                    let _ = tx.send(RuntimeUpdate::ContainerPid { index, pid: next_pid });
                }
            }

            _ = sleep(Duration::from_secs(1)) => {
                let next_pid = query_container_main_pid(&docker, &name_or_id).await?;
                if next_pid != current_pid {
                    current_pid = next_pid;
                    let _ = tx.send(RuntimeUpdate::ContainerPid { index, pid: next_pid });
                }
            }
        }
    }
}

async fn monitor_systemd_runtime(
    conn: zbus::Connection,
    unit_name: String,
    tx: mpsc::UnboundedSender<RuntimeUpdate>,
    index: usize,
) -> anyhow::Result<()> {
    loop {
        let (resolved_unit, status) = wait_systemd_unit_running(&conn, &unit_name).await?;
        let mut current_pid = status.main_pid;
        let mut current_running = status.is_running();
        let _ = tx.send(RuntimeUpdate::SystemdStatus {
            index,
            pid: current_pid,
            running: current_running,
        });

        let properties_proxy = PropertiesProxy::builder(&conn)
            .destination("org.freedesktop.systemd1")
            .map_err(|err| anyhow::anyhow!("failed to set systemd destination: {err}"))?
            .path(resolved_unit._unit_path.clone())
            .map_err(|err| anyhow::anyhow!("failed to set systemd unit path: {err}"))?
            .build()
            .await
            .map_err(|err| anyhow::anyhow!("failed to build systemd properties proxy: {err}"))?;
        let mut main_pid_changes = properties_proxy
            .receive_properties_changed()
            .await
            .map_err(|err| {
                anyhow::anyhow!("failed to subscribe to systemd property changes: {err}")
            })?;

        let _ = main_pid_changes.next().await;

        loop {
            let Some(changed) = main_pid_changes.next().await else {
                let _ = tx.send(RuntimeUpdate::SystemdStatus {
                    index,
                    pid: None,
                    running: false,
                });
                break;
            };

            let _ = changed.args().map_err(|err| {
                anyhow::anyhow!("failed to decode systemd properties change: {err}")
            })?;

            let status =
                query_systemd_unit_status(&resolved_unit.unit_proxy, &resolved_unit.service_proxy)
                    .await
                    .map_err(|err| match err {
                        SystemdUnitLookupError::NotFound => {
                            anyhow::anyhow!("systemd unit {unit_name} disappeared while monitoring")
                        }
                        SystemdUnitLookupError::Other(err) => err,
                    })?;
            let next_pid = status.main_pid;
            let next_running = status.is_running();

            if next_pid != current_pid || next_running != current_running {
                current_pid = next_pid;
                current_running = next_running;
                let _ = tx.send(RuntimeUpdate::SystemdStatus {
                    index,
                    pid: next_pid,
                    running: next_running,
                });
            }
        }
    }
}

async fn wait_pid_or_tty_targets(
    ebpf: &mut Ebpf,
    pids: &[u32],
    tty_filters: &HashSet<String>,
    tty_inputs: &[String],
    watch_flags: u32,
) -> anyhow::Result<Vec<u32>> {
    let mut announced = false;
    loop {
        let roots = seed_proc_state_from_task_iter(ebpf, pids, tty_filters, watch_flags)?;
        if !roots.is_empty() {
            return Ok(roots);
        }

        if !announced {
            eprintln!(
                "No processes matched PID(s) {:?} or tty(s) {:?}. Waiting for a match...",
                pids, tty_inputs
            );
            announced = true;
        }

        select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = signal::ctrl_c() => return Err(anyhow::anyhow!(
                "Interrupted while waiting for matching PID/TTY targets."
            )),
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
        systemd_unit,
        all_systemd_processes,
        no_watch_children,
    } = CliArgs::parse();

    let mut pids = pid;
    pids.extend(positional_pids);

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

    ensure_task_iter_program_loaded(&mut ebpf)?;

    let watch_flags = PROC_FLAG_WATCH_SELF
        | if watch_children {
            PROC_FLAG_WATCH_CHILDREN
        } else {
            0
        };

    // Seed PROC_STATE for explicit PID/TTY inputs first (container/systemd seeds are merged later).
    let mut static_watch_roots: StdHashMap<u32, u32> = StdHashMap::new();
    if !pids.is_empty() || !tty_filters.is_empty() {
        let roots = seed_proc_state_from_task_iter(&mut ebpf, &pids, &tty_filters, watch_flags)?;
        for pid in roots {
            add_watch_root(&mut static_watch_roots, pid, watch_flags);
        }
        if static_watch_roots.is_empty() && container.is_empty() && systemd_unit.is_empty() {
            let roots =
                wait_pid_or_tty_targets(&mut ebpf, &pids, &tty_filters, &tty_inputs, watch_flags)
                    .await?;
            for pid in roots {
                add_watch_root(&mut static_watch_roots, pid, watch_flags);
            }
        }
    }

    let mut container_runtimes = Vec::new();
    if !container.is_empty() {
        let docker = Docker::connect_with_local_defaults()?;
        for container_name in &container {
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

            let current_pid = query_container_main_pid(&docker, container_name).await?;
            if let Some(main_pid) = current_pid {
                seed_container_processes(
                    &mut ebpf,
                    container_name,
                    main_pid,
                    container_flags,
                    container_watch_children,
                    all_container_processes,
                )
                .await?;
            }

            container_runtimes.push(ContainerRuntime {
                docker: docker.clone(),
                name_or_id: container_name.clone(),
                watch_children: container_watch_children,
                all_processes: all_container_processes,
                flags: container_flags,
                current_pid,
            });
        }
    }

    let mut systemd_runtimes = Vec::new();
    if !systemd_unit.is_empty() {
        let conn = zbus::Connection::system()
            .await
            .map_err(|err| anyhow::anyhow!("failed to connect to system bus: {err}"))?;
        let manager = ManagerProxy::new(&conn)
            .await
            .map_err(|err| anyhow::anyhow!("failed to create systemd manager proxy: {err}"))?;

        for unit_name in &systemd_unit {
            let unit_watch_children = if all_systemd_processes {
                true
            } else {
                watch_children
            };
            let unit_flags = PROC_FLAG_WATCH_SELF
                | if unit_watch_children {
                    PROC_FLAG_WATCH_CHILDREN
                } else {
                    0
                };

            let (current_pid, current_running) =
                match resolve_systemd_unit(&conn, &manager, unit_name).await {
                    Ok(resolved_unit) => {
                        let status = query_systemd_unit_status(
                            &resolved_unit.unit_proxy,
                            &resolved_unit.service_proxy,
                        )
                        .await
                        .map_err(|err| match err {
                            SystemdUnitLookupError::NotFound => {
                                anyhow::anyhow!(
                                    "systemd unit {unit_name} disappeared during startup"
                                )
                            }
                            SystemdUnitLookupError::Other(err) => err,
                        })?;

                        let status = if status.is_running() {
                            status
                        } else {
                            let (_, status) = wait_systemd_unit_running(&conn, unit_name).await?;
                            status
                        };

                        let current_running = status.is_running();
                        seed_systemd_unit_processes(
                            &mut ebpf,
                            &conn,
                            unit_name,
                            status.main_pid,
                            unit_flags,
                            unit_watch_children,
                            all_systemd_processes,
                        )
                        .await?;

                        (status.main_pid, current_running)
                    }
                    Err(SystemdUnitLookupError::NotFound) => (None, false),
                    Err(SystemdUnitLookupError::Other(err)) => return Err(err.into()),
                };

            systemd_runtimes.push(SystemdRuntime {
                conn: conn.clone(),
                unit_name: unit_name.clone(),
                watch_children: unit_watch_children,
                all_processes: all_systemd_processes,
                flags: unit_flags,
                current_pid,
                current_running,
            });
        }
    }

    let mut current_watch_roots =
        collect_watch_roots(&static_watch_roots, &container_runtimes, &systemd_runtimes);
    let (mut watch_pids, mut async_ring) =
        build_watch_pids_and_ring(&mut ebpf, &current_watch_roots)?;

    let child_status = if watch_children {
        "watch_children=on"
    } else {
        "watch_children=off"
    };

    let mut target_descriptions = Vec::new();
    if !container_runtimes.is_empty() {
        let container_list = container_runtimes
            .iter()
            .map(|runtime| runtime.name_or_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if all_container_processes {
            target_descriptions.push(format!("containers=[{}] seed=all-procs", container_list));
        } else {
            target_descriptions.push(format!("containers=[{}]", container_list));
        }
    }
    if !systemd_runtimes.is_empty() {
        let unit_list = systemd_runtimes
            .iter()
            .map(|runtime| runtime.unit_name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if all_systemd_processes {
            target_descriptions.push(format!("systemd-units=[{}] seed=all-procs", unit_list));
        } else {
            target_descriptions.push(format!("systemd-units=[{}]", unit_list));
        }
    }
    let target_suffix = if target_descriptions.is_empty() {
        String::new()
    } else {
        format!(" {}", target_descriptions.join(" "))
    };

    let watched_root_pids: Vec<u32> = current_watch_roots.keys().copied().collect();
    let has_roots = !watched_root_pids.is_empty();
    if tty_inputs.is_empty() {
        if has_roots {
            println!(
                "Watching execve syscalls for PIDs: {:?} ({}){} (Ctrl-C to exit)",
                &watched_root_pids, child_status, target_suffix
            );
        } else {
            println!(
                "Watching execve syscalls ({}){} (Ctrl-C to exit)",
                child_status, target_suffix
            );
        }
    } else if has_roots {
        println!(
            "Watching execve syscalls for PIDs: {:?} (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            &watched_root_pids, &tty_inputs, child_status, target_suffix
        );
    } else {
        println!(
            "Watching execve syscalls (TTY filters: {:?}) ({}){} (Ctrl-C to exit)",
            &tty_inputs, child_status, target_suffix
        );
    }

    let (update_tx, mut update_rx) = mpsc::unbounded_channel::<RuntimeUpdate>();
    let mut monitor_handles = Vec::new();
    for (index, runtime) in container_runtimes.iter().enumerate() {
        let tx = update_tx.clone();
        let docker = runtime.docker.clone();
        let name_or_id = runtime.name_or_id.clone();
        monitor_handles.push(tokio::spawn(async move {
            if let Err(err) =
                monitor_container_runtime(docker, name_or_id.clone(), tx.clone(), index).await
            {
                let _ = tx.send(RuntimeUpdate::MonitorError {
                    label: format!("container {name_or_id}"),
                    error: err.to_string(),
                });
            }
        }));
    }
    for (index, runtime) in systemd_runtimes.iter().enumerate() {
        let tx = update_tx.clone();
        let conn = runtime.conn.clone();
        let unit_name = runtime.unit_name.clone();
        monitor_handles.push(tokio::spawn(async move {
            if let Err(err) =
                monitor_systemd_runtime(conn, unit_name.clone(), tx.clone(), index).await
            {
                let _ = tx.send(RuntimeUpdate::MonitorError {
                    label: format!("systemd unit {unit_name}"),
                    error: err.to_string(),
                });
            }
        }));
    }
    drop(update_tx);

    if monitor_handles.is_empty() {
        run_plain_event_loop(&mut async_ring).await?;
        return Ok(());
    }

    loop {
        select! {
            res = async_ring.readable_mut() => {
                let mut guard = res?;
                let ring = guard.get_inner_mut();
                drain_exec_events(ring);
                guard.clear_ready();
            }

            maybe_update = update_rx.recv() => {
                match maybe_update {
                    Some(RuntimeUpdate::ContainerPid { index, pid }) => {
                        let runtime = container_runtimes.get_mut(index).ok_or_else(|| {
                            anyhow::anyhow!("container runtime index {index} out of range")
                        })?;
                        apply_container_runtime_update(&mut ebpf, runtime, pid).await?;
                        let desired_roots = collect_watch_roots(
                            &static_watch_roots,
                            &container_runtimes,
                            &systemd_runtimes,
                        );
                        sync_watch_pids(&mut watch_pids, &mut current_watch_roots, &desired_roots)?;
                    }
                    Some(RuntimeUpdate::SystemdStatus { index, pid, running }) => {
                        let runtime = systemd_runtimes.get_mut(index).ok_or_else(|| {
                            anyhow::anyhow!("systemd runtime index {index} out of range")
                        })?;
                        apply_systemd_runtime_update(&mut ebpf, runtime, pid, running).await?;
                        let desired_roots = collect_watch_roots(
                            &static_watch_roots,
                            &container_runtimes,
                            &systemd_runtimes,
                        );
                        sync_watch_pids(&mut watch_pids, &mut current_watch_roots, &desired_roots)?;
                    }
                    Some(RuntimeUpdate::MonitorError { label, error }) => {
                        return Err(anyhow::anyhow!("{label}: {error}"));
                    }
                    None => break,
                }
            }

            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
