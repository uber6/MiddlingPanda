use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{anyhow, Context};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Pty};
use ssh2::Session as Ssh2Session;
use ssh_key::{Certificate, PublicKey};
use tokio::sync::mpsc::{self as tokio_mpsc, UnboundedSender};

use crate::data_dir::DataDir;
use crate::upstream::{
    connect_and_auth_identity, connect_and_auth_password, connect_and_auth_publickey,
    run_upstream_channel, ChannelMessage, PtyConfig, UpstreamSession,
};

pub struct ProxyHandler {
    pub upstream_host: String,
    pub upstream_port: u16,
    pub data_dir: DataDir,
    pub verify_upstream: bool,
    /// Fixed private key for upstream (e.g. DSA when the client cannot load id_dsa).
    pub upstream_identity: Option<PathBuf>,
    upstream: Option<Arc<Mutex<Ssh2Session>>>,
    channels: HashMap<ChannelId, ChannelState>,
    first_channel: Option<ChannelId>,
}

struct ChannelState {
    pty: Option<PtyConfig>,
    exec: Option<String>,
    env: Vec<(String, String)>,
    /// Local-only channel (e.g. OpenSSH ControlMaster mux); no upstream leg.
    local_only: bool,
    bridge_tx: Option<UnboundedSender<ChannelMessage>>,
    bridge_abort: Option<tokio_mpsc::Sender<()>>,
}

impl ProxyHandler {
    pub fn new(
        upstream_host: String,
        upstream_port: u16,
        data_dir: DataDir,
        verify_upstream: bool,
        upstream_identity: Option<PathBuf>,
    ) -> Self {
        Self {
            upstream_host,
            upstream_port,
            data_dir,
            verify_upstream,
            upstream_identity,
            upstream: None,
            channels: HashMap::new(),
            first_channel: None,
        }
    }
}

impl server::Handler for ProxyHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        if self.upstream_identity.is_none() {
            return Ok(Auth::reject());
        }
        match self.establish_upstream(user, None).await {
            Ok(()) => Ok(Auth::Accept),
            Err(e) => {
                tracing::warn!(error = %e, "auth_none upstream failed");
                Ok(Auth::reject())
            }
        }
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<Auth, Self::Error> {
        self.establish_upstream(user, Some(password)).await?;
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_publickey_upstream(user, public_key).await
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        let public_key = PublicKey::new(certificate.public_key().clone(), "");
        self.auth_publickey_upstream(user, &public_key).await
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.first_channel.is_none() {
            self.first_channel = Some(channel.id());
        }
        self.channels.insert(
            channel.id(),
            ChannelState {
                pty: None,
                exec: None,
                env: Vec::new(),
                local_only: false,
                bridge_tx: None,
                bridge_abort: None,
            },
        );
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get_mut(&channel) {
            state.pty = Some(PtyConfig {
                term: term.to_string(),
                width: col_width,
                height: row_height,
                env: Vec::new(),
            });
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get_mut(&channel) {
            if let Some(ref mut pty) = state.pty {
                pty.env
                    .push((variable_name.to_string(), variable_value.to_string()));
            } else {
                state
                    .env
                    .push((variable_name.to_string(), variable_value.to_string()));
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.should_bridge_channel(channel) {
            // Reply before opening the upstream channel so the client can send window/data.
            session.channel_success(channel)?;
            self.start_bridge(channel, session, None).await?;
        } else {
            tracing::debug!(
                ?channel,
                "shell accepted locally (no upstream); typical for SSH ControlMaster mux"
            );
            if let Some(state) = self.channels.get_mut(&channel) {
                state.local_only = true;
            }
            session.channel_success(channel)?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        if self.should_bridge_channel(channel) {
            session.channel_success(channel)?;
            self.start_bridge(channel, session, Some(cmd)).await?;
        } else {
            tracing::debug!(?channel, cmd = %cmd, "exec accepted locally (no upstream)");
            if let Some(state) = self.channels.get_mut(&channel) {
                state.local_only = true;
            }
            session.channel_success(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get(&channel) {
            if let Some(ref tx) = state.bridge_tx {
                let _ = tx.send(ChannelMessage::Data(data.to_vec()));
            }
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get(&channel) {
            if let Some(ref tx) = state.bridge_tx {
                let _ = tx.send(ChannelMessage::Extended {
                    code,
                    data: data.to_vec(),
                });
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get(&channel) {
            if let Some(ref tx) = state.bridge_tx {
                let _ = tx.send(ChannelMessage::Eof);
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(mut state) = self.channels.remove(&channel) {
            if let Some(ref tx) = state.bridge_tx {
                let _ = tx.send(ChannelMessage::Close);
            }
            if let Some(abort) = state.bridge_abort.take() {
                let _ = abort.send(());
            }
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get_mut(&channel) {
            if let Some(ref mut pty) = state.pty {
                pty.width = col_width;
                pty.height = row_height;
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }
}

impl ProxyHandler {
    /// Connect and authenticate to the legacy host.
    async fn establish_upstream(
        &mut self,
        user: &str,
        password: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let host = self.upstream_host.clone();
        let port = self.upstream_port;
        let data_dir = self.data_dir.clone();
        let verify = self.verify_upstream;
        let user = user.to_string();
        let upstream_identity = self.upstream_identity.clone();
        let password = password.map(|s| s.to_string());

        let UpstreamSession { session } = tokio::task::spawn_blocking(move || {
            if let Some(ref id_path) = upstream_identity {
                match connect_and_auth_identity(&host, port, &user, id_path, &data_dir, verify) {
                    Ok(session) => return Ok(session),
                    Err(e) => {
                        if password.is_none() {
                            return Err(e);
                        }
                        tracing::warn!(
                            error = %e,
                            "upstream identity auth failed, trying password"
                        );
                    }
                }
            }
            let pw = password.as_deref().context("no password for upstream")?;
            connect_and_auth_password(
                &host,
                port,
                &user,
                pw,
                &data_dir,
                verify,
                upstream_identity.as_deref(),
            )
        })
        .await
        .map_err(|e| anyhow!("upstream task join: {e}"))??;

        self.upstream = Some(Arc::new(Mutex::new(session)));
        Ok(())
    }

    async fn auth_publickey_upstream(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, anyhow::Error> {
        // Client may use Ed25519 to the panda; upstream uses --upstream-identity only.
        if self.upstream_identity.is_some() {
            return match self.establish_upstream(user, None).await {
                Ok(()) => Ok(Auth::Accept),
                Err(e) => {
                    tracing::warn!(error = %e, "upstream identity auth failed (after client pubkey)");
                    Ok(Auth::reject())
                }
            };
        }

        let host = self.upstream_host.clone();
        let port = self.upstream_port;
        let data_dir = self.data_dir.clone();
        let verify = self.verify_upstream;
        let user = user.to_string();
        let public_key = public_key.clone();

        let result = tokio::task::spawn_blocking(move || {
            connect_and_auth_publickey(
                &host,
                port,
                &user,
                &public_key,
                &data_dir,
                verify,
                None,
            )
        })
        .await
        .map_err(|e| anyhow!("upstream task join: {e}"))?;

        match result {
            Ok(UpstreamSession { session }) => {
                self.upstream = Some(Arc::new(Mutex::new(session)));
                Ok(Auth::Accept)
            }
            Err(e) => {
                tracing::warn!(error = %e, "upstream public-key auth failed");
                Ok(Auth::reject())
            }
        }
    }

    /// Skip upstream for OpenSSH ControlMaster mux control (first channel, no PTY/exec,
    /// while another channel is also open). Bridging mux to libssh2 breaks the real session.
    fn is_mux_control_channel(&self, channel: ChannelId) -> bool {
        let Some(state) = self.channels.get(&channel) else {
            return false;
        };
        if state.pty.is_some() || state.exec.is_some() {
            return false;
        }
        Some(channel) == self.first_channel && self.channels.len() > 1
    }

    fn should_bridge_channel(&self, channel: ChannelId) -> bool {
        let Some(state) = self.channels.get(&channel) else {
            return false;
        };
        !state.local_only && !self.is_mux_control_channel(channel)
    }

    /// Build upstream PTY settings. OpenSSH often omits a PTY on ControlMaster (-M)
    /// connections; legacy devices still need one for a login shell.
    fn upstream_pty_config(
        client_pty: Option<PtyConfig>,
        channel_env: Vec<(String, String)>,
        is_exec: bool,
    ) -> Option<PtyConfig> {
        if is_exec {
            return None;
        }
        let mut pty = client_pty.unwrap_or_else(|| PtyConfig {
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            env: Vec::new(),
        });
        if pty.width == 0 {
            pty.width = 80;
        }
        if pty.height == 0 {
            pty.height = 24;
        }
        if pty.term.is_empty() {
            pty.term = "xterm-256color".into();
        }
        pty.env.extend(channel_env);
        Some(pty)
    }

    async fn start_bridge(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
        exec: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let upstream = self
            .upstream
            .clone()
            .ok_or_else(|| anyhow!("no upstream session"))?;

        let state = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow!("unknown channel"))?;

        if state.bridge_tx.is_some() {
            return Ok(());
        }

        let exec = exec.or_else(|| state.exec.clone());
        let channel_env = std::mem::take(&mut state.env);
        let pty = Self::upstream_pty_config(state.pty.clone(), channel_env, exec.is_some());

        let (to_upstream_tx, to_upstream_rx) = tokio_mpsc::unbounded_channel();
        let (to_downstream_tx, mut to_downstream_rx) = tokio_mpsc::unbounded_channel();
        state.bridge_tx = Some(to_upstream_tx);

        let (abort_tx, mut abort_rx) = tokio_mpsc::channel(1);
        state.bridge_abort = Some(abort_tx);

        let handle = session.handle();
        let downstream_handle = handle.clone();
        let cid = channel_id;

        tracing::info!(?channel_id, "starting upstream channel bridge");

        tokio::spawn(async move {
            while let Some(msg) = to_downstream_rx.recv().await {
                match msg {
                    ChannelMessage::Data(data) => {
                        if downstream_handle.data(cid, data).await.is_err() {
                            tracing::debug!(?cid, "downstream data send failed");
                            break;
                        }
                    }
                    ChannelMessage::Extended { code, data } => {
                        if downstream_handle
                            .extended_data(cid, code, data)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    ChannelMessage::Eof => {
                        let _ = downstream_handle.eof(cid).await;
                        break;
                    }
                    ChannelMessage::Close => break,
                }
            }
        });

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        thread::spawn(move || {
            let code = {
                let guard = upstream.lock().unwrap();
                match run_upstream_channel(&guard, pty, exec, to_upstream_rx, to_downstream_tx) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %e, "upstream channel bridge failed");
                        1
                    }
                }
            };
            let _ = done_tx.send(code);
        });

        tokio::spawn(async move {
            let code = done_rx.await.unwrap_or(1);
            let _ = handle.exit_status_request(cid, code).await;
            let _ = handle.close(cid).await;
            let _ = abort_rx.recv().await;
        });

        Ok(())
    }
}

impl server::Server for ProxyHandler {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let mut h = ProxyHandler::new(
            self.upstream_host.clone(),
            self.upstream_port,
            self.data_dir.clone(),
            self.verify_upstream,
            self.upstream_identity.clone(),
        );
        h.upstream = self.upstream.clone();
        h
    }
}
