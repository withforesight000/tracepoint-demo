use std::collections::HashMap as StdHashMap;

use aya::Ebpf;
use aya::maps::hash_map::HashMap as UserHashMap;

use crate::{
    usecase::watch_container::ContainerRuntime, usecase::watch_systemd_unit::SystemdRuntime,
};

pub struct AppState {
    pub static_watch_roots: StdHashMap<u32, u32>,
    pub current_watch_roots: StdHashMap<u32, u32>,
    pub watch_pids: UserHashMap<aya::maps::MapData, u32, u32>,
    pub container_runtimes: Vec<ContainerRuntime>,
    pub systemd_runtimes: Vec<SystemdRuntime>,
}

pub struct PreparedApp {
    pub ebpf: Ebpf,
    pub state: AppState,
    pub tty_inputs: Vec<String>,
    pub watch_children: bool,
    pub target_descriptions: Vec<String>,
}
