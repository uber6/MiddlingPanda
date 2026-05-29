use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use anyhow::Context;
use ssh2::{
    CheckResult, HostKeyType, KnownHostFileKind, KnownHostKeyFormat, Session, EXTENDED_DATA_STDERR,
};

use crate::data_dir::{known_hosts_lookup_key, resolve_socket_addr, DataDir};
use crate::legacy::{apply_legacy_prefs_extended, negotiated_summary, supported_algs_report};
use crate::upstream_auth::{userauth_identity_file, userauth_publickey};

pub struct UpstreamSession {
    pub session: Session,
}

fn hostkey_supports_ssh_dss(session: &Session) -> bool {
    session
        .supported_algs(ssh2::MethodType::HostKey)
        .map(|algs| algs.iter().any(|a| *a == "ssh-dss"))
        .unwrap_or(false)
}

fn handshake_failure_hint(session: &Session, err: &ssh2::Error) -> String {
    let msg = err.to_string();
    let kex_or_keys = msg.contains("exchange encryption keys") || msg.contains("key exchange");

    if !hostkey_supports_ssh_dss(session) {
        return "\nHint: this binary's libssh2 was built without ssh-dss (libssh2 1.11+ \
                requires LIBSSH2_DSA_ENABLE at compile time). Rebuild from this repo \
                (see README \"Building with ssh-dss\") and run `cargo clean -p libssh2-sys` \
                if you rebuilt before."
            .to_string();
    }

    if kex_or_keys {
        return "\nHint: upstream may only offer ssh-dss host keys. OpenSSL 3 disables DSA \
                unless the legacy provider is active. Try:\n  \
                OPENSSL_CONF=$PWD/config/openssl-legacy.cnf middling-panda probe HOST PORT\n  \
                (see README \"OpenSSL 3 and ssh-dss\")"
            .to_string();
    }

    String::new()
}

fn handshake_upstream(session: &mut Session, addr_label: &str) -> anyhow::Result<()> {
    session.handshake().map_err(|e| {
        let hint = handshake_failure_hint(session, &e);
        anyhow::anyhow!("SSH handshake with {addr_label}: {e}{hint}")
    })
}

pub fn connect_upstream(
    host: &str,
    port: u16,
    data_dir: &DataDir,
    verify_host: bool,
) -> anyhow::Result<Session> {
    let addr = resolve_socket_addr(host, port)?;
    let addr_label = format!("{host}:{port}");
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(30))
        .with_context(|| format!("TCP connect to {addr_label}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(60)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(60)))?;

    let mut session = Session::new().context("create libssh2 session")?;
    session.set_blocking(true);
    apply_legacy_prefs_extended(&session)?;
    session.set_tcp_stream(tcp);
    handshake_upstream(&mut session, &addr_label)?;

    if verify_host {
        verify_known_host(&session, host, port, &data_dir.known_hosts_path())?;
    } else {
        tracing::warn!("upstream host key verification disabled");
    }

    Ok(session)
}

pub fn connect_and_auth_identity(
    host: &str,
    port: u16,
    user: &str,
    identity_path: &Path,
    data_dir: &DataDir,
    verify_host: bool,
) -> anyhow::Result<UpstreamSession> {
    let addr_label = format!("{host}:{port}");
    let session = connect_upstream(host, port, data_dir, verify_host)?;

    if !userauth_identity_file(&session, user, identity_path)? {
        anyhow::bail!(
            "upstream pubkey auth failed for {user}@{addr_label} with {} \
             (check authorized_keys has matching ssh-dss line, OPENSSL_CONF for DSA)",
            identity_path.display()
        );
    }

    log_upstream_established(&addr_label, user, &session);
    Ok(UpstreamSession { session })
}

pub fn probe_auth(
    host: &str,
    port: u16,
    user: &str,
    identity_path: &Path,
    data_dir: &DataDir,
    verify_host: bool,
    verbose: bool,
) -> anyhow::Result<String> {
    let mut report = if verbose {
        let session = connect_upstream(host, port, data_dir, verify_host)?;
        let mut out = String::new();
        if let Ok(conf) = std::env::var("OPENSSL_CONF") {
            out.push_str(&format!("OPENSSL_CONF={conf}\n"));
        }
        out.push_str(&supported_algs_report(&session));
        out
    } else {
        String::new()
    };

    connect_and_auth_identity(host, port, user, identity_path, data_dir, verify_host)?;
    report.push_str(&format!(
        "upstream_identity: ok user={user} key={}\n",
        identity_path.display()
    ));
    Ok(report)
}

pub fn connect_and_auth_password(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    data_dir: &DataDir,
    verify_host: bool,
    upstream_identity: Option<&Path>,
) -> anyhow::Result<UpstreamSession> {
    let addr_label = format!("{host}:{port}");
    let session = connect_upstream(host, port, data_dir, verify_host)?;

    if let Some(path) = upstream_identity {
        if userauth_identity_file(&session, user, path)? {
            log_upstream_established(&addr_label, user, &session);
            return Ok(UpstreamSession { session });
        }
        tracing::warn!(
            path = %path.display(),
            "upstream identity file auth failed, trying password"
        );
    }

    session
        .userauth_password(user, password)
        .with_context(|| format!("password auth as {user}@{addr_label}"))?;

    if !session.authenticated() {
        anyhow::bail!("upstream authentication failed for {user}@{addr_label}");
    }

    log_upstream_established(&addr_label, user, &session);
    Ok(UpstreamSession { session })
}

pub fn connect_and_auth_publickey(
    host: &str,
    port: u16,
    user: &str,
    public_key: &ssh_key::PublicKey,
    data_dir: &DataDir,
    verify_host: bool,
    upstream_identity: Option<&Path>,
) -> anyhow::Result<UpstreamSession> {
    let addr_label = format!("{host}:{port}");
    let session = connect_upstream(host, port, data_dir, verify_host)?;

    // Fixed upstream identity wins over client key passthrough (DSA-only servers).
    if let Some(path) = upstream_identity {
        if userauth_identity_file(&session, user, path)? {
            log_upstream_established(&addr_label, user, &session);
            return Ok(UpstreamSession { session });
        }
        anyhow::bail!(
            "upstream identity auth failed for {user}@{addr_label} with {}",
            path.display()
        );
    }

    if userauth_publickey(&session, user, public_key)? {
        log_upstream_established(&addr_label, user, &session);
        return Ok(UpstreamSession { session });
    }

    anyhow::bail!(
        "upstream public-key auth failed for {user}@{addr_label} \
         (no matching key in ssh-agent or ~/.ssh)"
    );
}

fn log_upstream_established(addr_label: &str, user: &str, session: &Session) {
    tracing::info!(
        target = %addr_label,
        user = %user,
        negotiated = %negotiated_summary(session),
        "upstream session established"
    );
}

pub fn probe_handshake(
    host: &str,
    port: u16,
    data_dir: &DataDir,
    verify_host: bool,
    verbose: bool,
) -> anyhow::Result<String> {
    let addr = resolve_socket_addr(host, port)?;
    let addr_label = format!("{host}:{port}");
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(30))
        .with_context(|| format!("TCP connect to {addr_label}"))?;

    let mut session = Session::new().context("create libssh2 session")?;
    session.set_blocking(true);
    apply_legacy_prefs_extended(&session)?;

    let mut report = String::new();
    if verbose {
        if let Ok(conf) = std::env::var("OPENSSL_CONF") {
            report.push_str(&format!("OPENSSL_CONF={conf}\n"));
        }
        report.push_str(&supported_algs_report(&session));
    }

    session.set_tcp_stream(tcp);
    if let Err(e) = handshake_upstream(&mut session, &addr_label) {
        if verbose {
            report.push_str(&supported_algs_report(&session));
        }
        return Err(e.context(report));
    }

    if verify_host {
        verify_known_host(&session, host, port, &data_dir.known_hosts_path())?;
    }

    let banner = session.banner().unwrap_or("").to_string();
    let summary = negotiated_summary(&session);
    let auth_methods = session.auth_methods("none").unwrap_or("").to_string();

    Ok(format!(
        "{report}target: {addr_label}\nbanner: {banner}\nnegotiated: {summary}\nauth_methods: {auth_methods}\n"
    ))
}

fn host_key_format(key_type: HostKeyType) -> KnownHostKeyFormat {
    key_type.into()
}

fn verify_known_host(
    session: &Session,
    host: &str,
    port: u16,
    known_hosts_path: &Path,
) -> anyhow::Result<()> {
    let (key, key_type) = session
        .host_key()
        .context("no upstream host key from handshake")?;

    let mut kh = session.known_hosts().context("known_hosts handle")?;
    if known_hosts_path.exists() {
        kh.read_file(known_hosts_path, KnownHostFileKind::OpenSSH)
            .with_context(|| format!("read {}", known_hosts_path.display()))?;
    }

    let lookup = known_hosts_lookup_key(host, port);
    match kh.check_port(&lookup, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => anyhow::bail!(
            "upstream host key mismatch for {lookup} (stored key in {} does not match server). \
             Remove the stale line, e.g.:\n  \
             ssh-keygen -R '{lookup}' -f {}\n  \
             Or use --no-verify-upstream for lab-only probes.",
            known_hosts_path.display(),
            known_hosts_path.display(),
        ),
        CheckResult::NotFound => {
            kh.add(
                &lookup,
                key,
                "auto-added by middling-panda",
                host_key_format(key_type),
            )?;
            if let Some(parent) = known_hosts_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            kh.write_file(known_hosts_path, KnownHostFileKind::OpenSSH)?;
            tracing::warn!(
                path = %known_hosts_path.display(),
                host = %lookup,
                "pinned upstream host key (first connect)"
            );
            Ok(())
        }
        CheckResult::Failure => anyhow::bail!("known_hosts check failed for {lookup}"),
    }
}

/// Run interactive or exec session on upstream; pump I/O via std channels.
pub fn run_upstream_channel(
    session: &Session,
    pty: Option<PtyConfig>,
    exec: Option<String>,
    mut to_upstream_rx: UnboundedReceiver<ChannelMessage>,
    to_downstream_tx: UnboundedSender<ChannelMessage>,
) -> anyhow::Result<u32> {
    session.set_blocking(true);
    session.set_timeout(0);
    let mut channel = session
        .channel_session()
        .map_err(|e| anyhow::anyhow!("open upstream channel: {e}"))?;
    session.set_timeout(50);

    if let Some(ref p) = pty {
        if let Err(e) = channel.request_pty(&p.term, None, Some((p.width, p.height, 0, 0))) {
            tracing::warn!(error = %e, "upstream PTY request failed; continuing without PTY");
        } else {
            for (name, value) in &p.env {
                if let Err(e) = channel.setenv(name, value) {
                    tracing::debug!(name = %name, error = %e, "upstream setenv skipped");
                }
            }
        }
    }

    if let Some(cmd) = exec {
        channel.exec(&cmd).context("upstream exec")?;
    } else {
        channel.shell().context("upstream shell")?;
    }

    pump_channel(&mut channel, &mut to_upstream_rx, &to_downstream_tx)
}

#[derive(Clone, Debug)]
pub struct PtyConfig {
    pub term: String,
    pub width: u32,
    pub height: u32,
    pub env: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum ChannelMessage {
    Data(Vec<u8>),
    Extended { code: u32, data: Vec<u8> },
    Eof,
    Close,
}

fn is_read_would_wait(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn pump_channel(
    channel: &mut ssh2::Channel,
    to_upstream_rx: &mut UnboundedReceiver<ChannelMessage>,
    to_downstream_tx: &UnboundedSender<ChannelMessage>,
) -> anyhow::Result<u32> {
    let mut stderr = channel.stream(EXTENDED_DATA_STDERR);
    let mut buf = [0u8; 8192];
    let mut stderr_buf = [0u8; 4096];
    let mut exit_code = 0u32;

    loop {
        while let Ok(msg) = to_upstream_rx.try_recv() {
            match msg {
                ChannelMessage::Data(data) => {
                    channel.write_all(&data)?;
                }
                ChannelMessage::Extended { code, data } if code == 1 => {
                    stderr.write_all(&data)?;
                }
                ChannelMessage::Extended { .. } => {}
                ChannelMessage::Eof => {
                    channel.eof();
                }
                ChannelMessage::Close => {
                    channel.close()?;
                }
            }
        }

        match channel.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                if to_downstream_tx
                    .send(ChannelMessage::Data(buf[..n].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
            Err(e) if is_read_would_wait(&e) => {}
            Err(e) => return Err(e.into()),
        }

        match stderr.read(&mut stderr_buf) {
            Ok(0) => {}
            Ok(n) => {
                if to_downstream_tx
                    .send(ChannelMessage::Extended {
                        code: 1,
                        data: stderr_buf[..n].to_vec(),
                    })
                    .is_err()
                {
                    break;
                }
            }
            Err(e) if is_read_would_wait(&e) => {}
            Err(e) => return Err(e.into()),
        }

        if channel.eof() {
            if let Ok(status) = channel.exit_status() {
                exit_code = status.max(0) as u32;
            }
            break;
        }

        std::thread::sleep(Duration::from_millis(1));
    }

    let _ = to_downstream_tx.send(ChannelMessage::Eof);
    Ok(exit_code)
}
