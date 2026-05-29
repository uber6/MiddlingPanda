use std::sync::Arc;

use anyhow::Context;
use russh::server::{self, Config};
use russh::Preferred;
use tokio::net::TcpListener;

use crate::data_dir::{parse_host_port, DataDir};
use crate::handler::ProxyHandler;
use crate::stdio_stream::StdioStream;

pub async fn run_proxy_stdio(
    host: &str,
    port: u16,
    data_dir: DataDir,
    verify_upstream: bool,
    upstream_identity: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let (host, port) = parse_host_port(host, port);
    let config = server_config(&data_dir)?;
    let handler = ProxyHandler::new(host, port, data_dir, verify_upstream, upstream_identity);
    let session = server::run_stream(config, StdioStream::new(), handler).await?;
    session.await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub async fn run_proxy_listen(
    bind: &str,
    data_dir: DataDir,
    verify_upstream: bool,
) -> anyhow::Result<()> {
    let config = server_config(&data_dir)?;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!(%bind, "listening (use ProxyCommand with %h %p to this host)");

    loop {
        let (socket, peer) = listener.accept().await?;
        let data_dir = data_dir.clone();
        let config = config.clone();
        tokio::spawn(async move {
            // listen mode without per-connection target still needs host/port from client;
            // for MVP log and reject non-ProxyCommand use.
            let handler = ProxyHandler::new(
                "127.0.0.1".into(),
                22,
                data_dir,
                verify_upstream,
                None,
            );
            tracing::warn!(?peer, "accepted TCP connection; use `proxy` stdio mode with ProxyCommand");
            let _ = server::run_stream(config, socket, handler).await;
        });
    }
}

fn server_config(data_dir: &DataDir) -> anyhow::Result<Arc<Config>> {
    let key = data_dir.load_or_create_host_key()?;
    Ok(Arc::new(Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        preferred: Preferred::default(),
        ..Default::default()
    }))
}
