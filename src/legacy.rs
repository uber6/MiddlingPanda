use ssh2::{MethodType, Session};

/// Union of modern + legacy algorithms so libssh2 can talk to both old-only and
/// "hybrid" servers (e.g. curve25519 KEX + ssh-dss host key only).
pub fn apply_legacy_prefs(session: &Session) -> anyhow::Result<()> {
    const KEX: &str = concat!(
        "curve25519-sha256,",
        "curve25519-sha256@libssh.org,",
        "ecdh-sha2-nistp256,",
        "ecdh-sha2-nistp384,",
        "ecdh-sha2-nistp521,",
        "diffie-hellman-group-exchange-sha256,",
        "diffie-hellman-group-exchange-sha1,",
        "diffie-hellman-group14-sha256,",
        "diffie-hellman-group14-sha1,",
        "diffie-hellman-group1-sha1"
    );
    // ssh-dss first; keep modern host keys for servers that offer them
    const HOST_KEY: &str = "ssh-dss,ssh-rsa,rsa-sha2-512,rsa-sha2-256,ssh-ed25519";
    const CRYPT: &str = concat!(
        "aes256-gcm@openssh.com,",
        "aes128-gcm@openssh.com,",
        "chacha20-poly1305@openssh.com,",
        "aes256-ctr,",
        "aes192-ctr,",
        "aes128-ctr,",
        "aes256-cbc,",
        "aes192-cbc,",
        "aes128-cbc,",
        "3des-cbc"
    );
    const MAC: &str = concat!(
        "hmac-sha2-256-etm@openssh.com,",
        "hmac-sha2-256,",
        "hmac-sha2-512,",
        "hmac-sha1,",
        "hmac-md5"
    );

    session.method_pref(MethodType::Kex, KEX)?;
    session.method_pref(MethodType::HostKey, HOST_KEY)?;
    session.method_pref(MethodType::CryptCs, CRYPT)?;
    session.method_pref(MethodType::CryptSc, CRYPT)?;
    session.method_pref(MethodType::MacCs, MAC)?;
    session.method_pref(MethodType::MacSc, MAC)?;
    Ok(())
}

pub fn apply_legacy_prefs_extended(session: &Session) -> anyhow::Result<()> {
    apply_legacy_prefs(session)
}

pub fn supported_algs_report(session: &Session) -> String {
    fn list(session: &Session, ty: MethodType, label: &str) -> String {
        match session.supported_algs(ty) {
            Ok(v) if v.is_empty() => format!("{label}: (none)\n"),
            Ok(v) => format!("{label}: {}\n", v.join(", ")),
            Err(e) => format!("{label}: error {e}\n"),
        }
    }
    let mut out = String::from("libssh2 supported algorithms:\n");
    out.push_str(&list(session, MethodType::Kex, "  kex"));
    out.push_str(&list(session, MethodType::HostKey, "  hostkey"));
    out.push_str(&list(session, MethodType::CryptCs, "  cipher"));
    out.push_str(&list(session, MethodType::MacCs, "  mac"));
    out
}

pub fn negotiated_summary(session: &Session) -> String {
    let kex = session.methods(MethodType::Kex).unwrap_or("?");
    let host = session.methods(MethodType::HostKey).unwrap_or("?");
    let crypt = session
        .methods(MethodType::CryptCs)
        .or_else(|| session.methods(MethodType::CryptSc))
        .unwrap_or("?");
    let mac = session
        .methods(MethodType::MacCs)
        .or_else(|| session.methods(MethodType::MacSc))
        .unwrap_or("?");
    format!("kex={kex} hostkey={host} cipher={crypt} mac={mac}")
}
