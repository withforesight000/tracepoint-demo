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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_if_needed_returns_none_when_no_units() {
        assert!(connect_if_needed(&[]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn connect_if_needed_with_units_err_or_some() {
        let result = connect_if_needed(&["dummy.service".to_string()]).await;
        assert!(result.is_err() || result.unwrap().is_some());
    }
}
