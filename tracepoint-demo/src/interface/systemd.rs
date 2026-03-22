pub async fn connect_if_needed(
    systemd_units: &[String],
) -> anyhow::Result<Option<zbus::Connection>> {
    if systemd_units.is_empty() {
        return Ok(None);
    }

    zbus::Connection::system()
        .await
        .map(Some)
        .map_err(|err| anyhow::anyhow!("failed to connect to system bus: {err}"))
}
