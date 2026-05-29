use std::path::{Path, PathBuf};

use anyhow::Context;
use ssh2::Session;
use ssh_key::{HashAlg, PublicKey};
use tracing::debug;

const SSH_DIR_KEY_CANDIDATES: &[&str] = &[
    "id_ed25519",
    "id_rsa",
    "id_ecdsa",
    "id_dsa",
    "id_ed25519_sk",
    "id_ecdsa_sk",
];

pub fn public_keys_match(expected: &PublicKey, candidate: &PublicKey) -> bool {
    expected.fingerprint(HashAlg::Sha256) == candidate.fingerprint(HashAlg::Sha256)
}

/// Authenticate upstream with an explicit private key file (no client key match required).
pub fn userauth_identity_file(session: &Session, user: &str, private_path: &Path) -> anyhow::Result<bool> {
    if !private_path.is_file() {
        anyhow::bail!("upstream identity not found: {}", private_path.display());
    }
    try_key_file(session, user, None, private_path).map_err(|e| {
        anyhow::anyhow!("{e}{}", dsa_auth_hint())
    })
}

/// Authenticate upstream with the same public key the SSH client used locally.
pub fn userauth_publickey(
    session: &Session,
    user: &str,
    client_key: &PublicKey,
) -> anyhow::Result<bool> {
    if try_agent(session, user, client_key)? {
        return Ok(true);
    }
    if try_ssh_dir_keys(session, user, client_key)? {
        return Ok(true);
    }
    Ok(false)
}

fn try_agent(session: &Session, user: &str, client_key: &PublicKey) -> anyhow::Result<bool> {
    if std::env::var_os("SSH_AUTH_SOCK").is_none() {
        return Ok(false);
    }

    let mut agent = match session.agent() {
        Ok(a) => a,
        Err(e) => {
            debug!(error = %e, "ssh-agent unavailable");
            return Ok(false);
        }
    };

    agent.connect().context("connect ssh-agent")?;
    agent.list_identities().context("list ssh-agent identities")?;

    for identity in agent.identities().context("read ssh-agent identities")? {
        let Ok(agent_key) = PublicKey::from_bytes(identity.blob()) else {
            continue;
        };
        if !public_keys_match(client_key, &agent_key) {
            continue;
        }
        match agent.userauth(user, &identity) {
            Ok(()) if session.authenticated() => {
                debug!("upstream authenticated via ssh-agent");
                return Ok(true);
            }
            Ok(()) => {}
            Err(e) => {
                debug!(error = %e, "ssh-agent userauth failed for matching identity");
            }
        }
    }

    Ok(false)
}

fn try_ssh_dir_keys(session: &Session, user: &str, client_key: &PublicKey) -> anyhow::Result<bool> {
    let Some(ssh_dir) = ssh_dir() else {
        return Ok(false);
    };

    for name in SSH_DIR_KEY_CANDIDATES {
        let path = ssh_dir.join(name);
        if !path.is_file() {
            continue;
        }
        if try_key_file(session, user, Some(client_key), &path)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn try_key_file(
    session: &Session,
    user: &str,
    must_match: Option<&PublicKey>,
    private_path: &Path,
) -> anyhow::Result<bool> {
    let secret = match russh::keys::load_secret_key(private_path, None) {
        Ok(k) => k,
        Err(e) => {
            debug!(path = %private_path.display(), error = %e, "skip private key");
            return Ok(false);
        }
    };

    let disk_public = secret.public_key();
    if let Some(client_key) = must_match {
        if !public_keys_match(client_key, &disk_public) {
            return Ok(false);
        }
    }

    // Prefer letting libssh2 read the private key; only pass .pub if it looks valid.
    let public_path = public_key_path(private_path);
    session
        .userauth_pubkey_file(user, public_path.as_deref(), private_path, None)
        .or_else(|_| {
            session.userauth_pubkey_file(user, None, private_path, None)
        })
        .map_err(|e| anyhow::anyhow!("pubkey auth with {}: {e}", private_path.display()))?;

    if session.authenticated() {
        debug!(
            path = %private_path.display(),
            algorithm = %disk_public.algorithm(),
            "upstream authenticated via local private key"
        );
        Ok(true)
    } else {
        debug!(path = %private_path.display(), "pubkey auth ok but not authenticated");
        Ok(false)
    }
}

fn ssh_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

/// `id_dsa` → `id_dsa.pub` beside the private key (must look like an OpenSSH one-line key).
fn public_key_path(private_path: &Path) -> Option<PathBuf> {
    let parent = private_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = private_path.file_stem()?;
    let candidate = parent.join(format!("{}.pub", stem.to_string_lossy()));
    if !candidate.is_file() {
        return None;
    }
    let Ok(contents) = std::fs::read_to_string(&candidate) else {
        return None;
    };
    let line = contents.lines().next()?.trim();
    if line.len() < 80 || !(line.starts_with("ssh-rsa ") || line.starts_with("ssh-dss ") || line.starts_with("ssh-ed25519 ") || line.starts_with("ecdsa-sha2-")) {
        return None;
    }
    Some(candidate)
}

fn dsa_auth_hint() -> &'static str {
    "\nHint: for ssh-dss keys you may need OPENSSL_CONF=config/openssl-legacy.cnf (OpenSSL 3). \
     If id_dsa.pub is invalid, remove it or regenerate with ssh-keygen on a host that supports DSA."
}
