#[cfg(not(target_os = "linux"))]
compile_error!("middling-panda supports Linux and WSL2 only (build inside WSL, not native Windows)");

mod data_dir;
mod handler;
mod legacy;
mod proxy;
mod stdio_stream;
mod upstream;
mod upstream_auth;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::data_dir::DataDir;

#[derive(Parser)]
#[command(
    name = "middling-panda",
    about = "SSH crypto bridge: modern OpenSSH clients to legacy devices (ssh-dss, weak KEX)"
)]
struct Cli {
    /// Directory for host key and upstream known_hosts
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Skip verifying legacy device host keys (lab only)
    #[arg(long, global = true)]
    no_verify_upstream: bool,

    /// Private key file for upstream login (e.g. DSA when OpenSSH cannot load id_dsa).
    /// Falls back to password if set together with password auth. Env: MPANDA_UPSTREAM_IDENTITY.
    #[arg(long, global = true, env = "MPANDA_UPSTREAM_IDENTITY")]
    upstream_identity: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// ProxyCommand entrypoint: bridge stdio SSH to upstream HOST PORT
    Proxy {
        host: String,
        #[arg(default_value_t = 22)]
        port: u16,
    },
    /// Print upstream algorithm negotiation for HOST PORT
    Probe {
        host: String,
        #[arg(default_value_t = 22)]
        port: u16,
        /// Test upstream login with --upstream-identity (requires -u)
        #[arg(short, long)]
        user: Option<String>,
        /// Print libssh2 supported algorithms (and OPENSSL_CONF) before connecting
        #[arg(short, long)]
        verbose: bool,
    },
    /// Listen on ADDR (optional); prefer `proxy` with ProxyCommand
    Listen {
        #[arg(default_value = "127.0.0.1:2222")]
        addr: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("middling_panda=info".parse()?))
        .with_writer(std::io::stderr)
        .init();

    let mut upstream_identity = cli.upstream_identity;
    if let Some(ref path) = upstream_identity {
        upstream_identity = Some(resolve_identity_path(path)?);
    }

    let data_dir = DataDir::new(cli.data_dir)?;
    let verify = !cli.no_verify_upstream;

    match cli.command {
        Command::Proxy { host, port } => {
            proxy::run_proxy_stdio(&host, port, data_dir, verify, upstream_identity).await?;
        }
        Command::Probe {
            host,
            port,
            user,
            verbose,
        } => {
            let (host, port) = data_dir::parse_host_port(&host, port);
            let identity = upstream_identity.clone();
            let report = tokio::task::spawn_blocking(move || {
                if let (Some(user), Some(id_path)) = (user, identity) {
                    upstream::probe_auth(&host, port, &user, &id_path, &data_dir, verify, verbose)
                } else {
                    upstream::probe_handshake(&host, port, &data_dir, verify, verbose)
                }
            })
            .await
            .context("probe task")??;
            print!("{report}");
        }
        Command::Listen { addr } => {
            proxy::run_proxy_listen(&addr, data_dir, verify).await?;
        }
    }

    Ok(())
}

/// Turn a user-supplied identity path into an absolute path (ProxyCommand cwd varies).
fn resolve_identity_path(path: &std::path::Path) -> anyhow::Result<PathBuf> {
    let candidate = if path.is_relative() {
        let cwd = std::env::current_dir().context("current directory for --upstream-identity")?;
        cwd.join(path)
    } else {
        path.to_path_buf()
    };
    if !candidate.is_file() {
        anyhow::bail!("upstream identity not found: {}", path.display());
    }
    std::fs::canonicalize(&candidate)
        .with_context(|| format!("resolve identity path {}", path.display()))
}
