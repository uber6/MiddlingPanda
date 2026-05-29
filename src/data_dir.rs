use std::net::ToSocketAddrs;
use std::path::PathBuf;
use anyhow::Context;
use russh::keys::{load_secret_key, Algorithm, PrivateKey};
use ssh_key::LineEnding;

#[derive(Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    pub fn new(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let root = path.unwrap_or_else(default_data_dir);
        std::fs::create_dir_all(&root)
            .with_context(|| format!("create data dir {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn host_key_path(&self) -> PathBuf {
        self.root.join("id_ed25519")
    }

    pub fn known_hosts_path(&self) -> PathBuf {
        self.root.join("known_hosts")
    }

    pub fn load_or_create_host_key(&self) -> anyhow::Result<PrivateKey> {
        let path = self.host_key_path();
        let key = if path.exists() {
            load_secret_key(&path, None)
                .with_context(|| format!("load host key {}", path.display()))?
        } else {
            let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .context("generate host key")?;
            let pem = key.to_openssh(LineEnding::LF).context("encode host key")?;
            std::fs::write(&path, pem.as_bytes())
                .with_context(|| format!("write host key {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&path, perms)?;
            }
            tracing::info!(path = %path.display(), "generated new MiddlingPanda host key");
            key
        };
        Ok(key)
    }
}

fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".middling-panda")
}

pub fn parse_host_port(host: &str, port: u16) -> (String, u16) {
    if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(p) = p.parse::<u16>() {
            return (h.to_string(), p);
        }
    }
    (host.to_string(), port)
}

pub fn resolve_socket_addr(host: &str, port: u16) -> anyhow::Result<std::net::SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .context("resolve upstream address")?
        .next()
        .context("no addresses resolved")
}

pub fn known_hosts_lookup_key(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}
