use std::collections::{HashMap as StdHashMap, HashSet};

#[derive(Debug)]
pub struct StartupRuntimePlan<TContainerRuntime, TSystemdRuntime> {
    pub static_watch_roots: StdHashMap<u32, u32>,
    pub current_watch_roots: StdHashMap<u32, u32>,
    pub container_runtimes: Vec<TContainerRuntime>,
    pub systemd_runtimes: Vec<TSystemdRuntime>,
}

pub struct StartupPrepareInputs<'a> {
    pub pids: &'a [u32],
    pub tty_inputs: &'a [String],
    pub tty_filters: &'a HashSet<String>,
    pub containers: &'a [String],
    pub systemd_units: &'a [String],
    pub watch_children: bool,
    pub all_container_processes: bool,
    pub all_systemd_processes: bool,
    pub watch_flags: u32,
    pub container_runtime_available: bool,
    pub systemd_runtime_available: bool,
}
#[allow(async_fn_in_trait)]
pub trait StartupPrepareBackend {
    type ContainerRuntime;
    type SystemdRuntime;

    async fn collect_static_watch_roots(
        &mut self,
        pids: &[u32],
        tty_filters: &HashSet<String>,
        tty_inputs: &[String],
        watch_flags: u32,
        has_runtime_targets: bool,
    ) -> anyhow::Result<StdHashMap<u32, u32>>;

    async fn initialize_container_runtimes(
        &mut self,
        containers: &[String],
        watch_children: bool,
        all_container_processes: bool,
    ) -> anyhow::Result<Vec<Self::ContainerRuntime>>;

    async fn initialize_systemd_runtimes(
        &mut self,
        systemd_units: &[String],
        watch_children: bool,
        all_systemd_processes: bool,
    ) -> anyhow::Result<Vec<Self::SystemdRuntime>>;

    fn collect_watch_roots(
        &self,
        static_watch_roots: &StdHashMap<u32, u32>,
        container_runtimes: &[Self::ContainerRuntime],
        systemd_runtimes: &[Self::SystemdRuntime],
    ) -> StdHashMap<u32, u32>;
}

pub async fn prepare_runtime_plan<TBackend: StartupPrepareBackend>(
    backend: &mut TBackend,
    inputs: StartupPrepareInputs<'_>,
) -> anyhow::Result<StartupRuntimePlan<TBackend::ContainerRuntime, TBackend::SystemdRuntime>> {
    let has_runtime_targets = !inputs.containers.is_empty() || !inputs.systemd_units.is_empty();

    let static_watch_roots = backend
        .collect_static_watch_roots(
            inputs.pids,
            inputs.tty_filters,
            inputs.tty_inputs,
            inputs.watch_flags,
            has_runtime_targets,
        )
        .await?;

    let container_runtimes = match inputs.containers.is_empty() {
        true => Vec::new(),
        false if inputs.container_runtime_available => {
            backend
                .initialize_container_runtimes(
                    inputs.containers,
                    inputs.watch_children,
                    inputs.all_container_processes,
                )
                .await?
        }
        false => return Err(anyhow::anyhow!("container runtime is not initialized")),
    };

    let systemd_runtimes = match inputs.systemd_units.is_empty() {
        true => Vec::new(),
        false if inputs.systemd_runtime_available => {
            backend
                .initialize_systemd_runtimes(
                    inputs.systemd_units,
                    inputs.watch_children,
                    inputs.all_systemd_processes,
                )
                .await?
        }
        false => return Err(anyhow::anyhow!("systemd runtime is not initialized")),
    };

    let current_watch_roots =
        backend.collect_watch_roots(&static_watch_roots, &container_runtimes, &systemd_runtimes);

    Ok(StartupRuntimePlan {
        static_watch_roots,
        current_watch_roots,
        container_runtimes,
        systemd_runtimes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeContainerRuntime(&'static str);

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeSystemdRuntime(&'static str);

    #[derive(Default)]
    struct FakeStartupPrepareBackend {
        static_watch_roots: StdHashMap<u32, u32>,
        current_watch_roots: StdHashMap<u32, u32>,
        container_runtimes: Vec<FakeContainerRuntime>,
        systemd_runtimes: Vec<FakeSystemdRuntime>,
        observed_has_runtime_targets: Vec<bool>,
        container_init_calls: usize,
        systemd_init_calls: usize,
    }

    impl StartupPrepareBackend for FakeStartupPrepareBackend {
        type ContainerRuntime = FakeContainerRuntime;
        type SystemdRuntime = FakeSystemdRuntime;

        async fn collect_static_watch_roots(
            &mut self,
            _pids: &[u32],
            _tty_filters: &HashSet<String>,
            _tty_inputs: &[String],
            _watch_flags: u32,
            has_runtime_targets: bool,
        ) -> anyhow::Result<StdHashMap<u32, u32>> {
            self.observed_has_runtime_targets.push(has_runtime_targets);
            Ok(self.static_watch_roots.clone())
        }

        async fn initialize_container_runtimes(
            &mut self,
            _containers: &[String],
            _watch_children: bool,
            _all_container_processes: bool,
        ) -> anyhow::Result<Vec<Self::ContainerRuntime>> {
            self.container_init_calls += 1;
            Ok(self.container_runtimes.clone())
        }

        async fn initialize_systemd_runtimes(
            &mut self,
            _systemd_units: &[String],
            _watch_children: bool,
            _all_systemd_processes: bool,
        ) -> anyhow::Result<Vec<Self::SystemdRuntime>> {
            self.systemd_init_calls += 1;
            Ok(self.systemd_runtimes.clone())
        }

        fn collect_watch_roots(
            &self,
            _static_watch_roots: &StdHashMap<u32, u32>,
            _container_runtimes: &[Self::ContainerRuntime],
            _systemd_runtimes: &[Self::SystemdRuntime],
        ) -> StdHashMap<u32, u32> {
            self.current_watch_roots.clone()
        }
    }

    #[tokio::test]
    async fn prepare_runtime_plan_validates_container_runtime_availability() {
        let mut backend = FakeStartupPrepareBackend::default();

        let err = prepare_runtime_plan(
            &mut backend,
            StartupPrepareInputs {
                pids: &[],
                tty_inputs: &[],
                tty_filters: &HashSet::new(),
                containers: &["web".to_string()],
                systemd_units: &[],
                watch_children: true,
                all_container_processes: false,
                all_systemd_processes: false,
                watch_flags: 0x1,
                container_runtime_available: false,
                systemd_runtime_available: true,
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "container runtime is not initialized");
        assert_eq!(backend.container_init_calls, 0);
    }

    #[tokio::test]
    async fn prepare_runtime_plan_validates_systemd_runtime_availability() {
        let mut backend = FakeStartupPrepareBackend::default();

        let err = prepare_runtime_plan(
            &mut backend,
            StartupPrepareInputs {
                pids: &[],
                tty_inputs: &[],
                tty_filters: &HashSet::new(),
                containers: &[],
                systemd_units: &["sshd.service".to_string()],
                watch_children: true,
                all_container_processes: false,
                all_systemd_processes: false,
                watch_flags: 0x1,
                container_runtime_available: true,
                systemd_runtime_available: false,
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "systemd runtime is not initialized");
        assert_eq!(backend.systemd_init_calls, 0);
    }

    #[tokio::test]
    async fn prepare_runtime_plan_skips_runtime_initializers_when_no_runtime_targets() {
        let mut backend = FakeStartupPrepareBackend {
            static_watch_roots: StdHashMap::from([(10, 0x1)]),
            current_watch_roots: StdHashMap::from([(10, 0x1)]),
            ..Default::default()
        };

        let plan = prepare_runtime_plan(
            &mut backend,
            StartupPrepareInputs {
                pids: &[10],
                tty_inputs: &[],
                tty_filters: &HashSet::new(),
                containers: &[],
                systemd_units: &[],
                watch_children: true,
                all_container_processes: false,
                all_systemd_processes: false,
                watch_flags: 0x1,
                container_runtime_available: false,
                systemd_runtime_available: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(backend.observed_has_runtime_targets, vec![false]);
        assert_eq!(backend.container_init_calls, 0);
        assert_eq!(backend.systemd_init_calls, 0);
        assert_eq!(plan.static_watch_roots, StdHashMap::from([(10, 0x1)]));
    }

    #[tokio::test]
    async fn prepare_runtime_plan_passes_runtime_target_context_and_collects_outputs() {
        let mut backend = FakeStartupPrepareBackend {
            static_watch_roots: StdHashMap::from([(10, 0x1)]),
            current_watch_roots: StdHashMap::from([(10, 0x1), (20, 0x2), (30, 0x4)]),
            container_runtimes: vec![FakeContainerRuntime("web")],
            systemd_runtimes: vec![FakeSystemdRuntime("sshd.service")],
            ..Default::default()
        };

        let plan = prepare_runtime_plan(
            &mut backend,
            StartupPrepareInputs {
                pids: &[10],
                tty_inputs: &[],
                tty_filters: &HashSet::new(),
                containers: &["web".to_string()],
                systemd_units: &["sshd.service".to_string()],
                watch_children: true,
                all_container_processes: false,
                all_systemd_processes: false,
                watch_flags: 0x1,
                container_runtime_available: true,
                systemd_runtime_available: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(backend.observed_has_runtime_targets, vec![true]);
        assert_eq!(backend.container_init_calls, 1);
        assert_eq!(backend.systemd_init_calls, 1);
        assert_eq!(plan.container_runtimes, vec![FakeContainerRuntime("web")]);
        assert_eq!(
            plan.systemd_runtimes,
            vec![FakeSystemdRuntime("sshd.service")]
        );
        assert_eq!(
            plan.current_watch_roots,
            StdHashMap::from([(10, 0x1), (20, 0x2), (30, 0x4)])
        );
    }
}
