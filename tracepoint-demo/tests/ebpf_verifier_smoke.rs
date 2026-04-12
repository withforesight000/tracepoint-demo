use tracepoint_demo::gateway::ebpf::{
    load_embedded_tracepoint_demo_ebpf, load_tracepoint_programs,
};

#[test]
fn tracepoint_demo_ebpf_verifier_smoke_test() -> anyhow::Result<()> {
    if std::env::var_os("TRACEPOINT_DEMO_EBPF_SMOKE_TEST").is_none() {
        eprintln!(
            "skipping eBPF verifier smoke test: set TRACEPOINT_DEMO_EBPF_SMOKE_TEST=1 to run"
        );
        return Ok(());
    }

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping eBPF verifier smoke test: requires root or equivalent capabilities");
        return Ok(());
    }

    let mut ebpf = load_embedded_tracepoint_demo_ebpf()?;
    load_tracepoint_programs(&mut ebpf)?;

    Ok(())
}
