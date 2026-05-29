# MiddlingPanda

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

SSH crypto bridge written in Rust. Connect with a **modern** OpenSSH client; MiddlingPanda negotiates **legacy** algorithms (including `ssh-dss`) to the real device via libssh2.

**Platforms: Linux and WSL2.** Build and run on a Linux machine or inside WSL2 (not native Windows). OpenSSL development libraries are required.

No server-side config file. The target host and port come from your SSH command (`%h` / `%p`).

## Build

Install build dependencies so `cargo` can compile vendored **libssh2** against **OpenSSL**:

**Fedora / RHEL (e.g. WSL Fedora 44):**

```bash
sudo dnf install gcc make pkgconf-pkg-config openssl-devel
```

**Debian / Ubuntu:**

```bash
sudo apt install build-essential pkg-config libssl-dev
```

Then:

```bash
cargo build --release
```

The binary is `target/release/middling-panda`.

libssh2 is compiled with **OpenSSL** from your system.

### Static musl binary

For a fully static Linux binary (e.g. portable deploy), install the musl target and build:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The binary is `target/x86_64-unknown-linux-musl/release/middling-panda`. For musl, `ssh2` enables **vendored OpenSSL** automatically (system `pkg-config` cannot cross-link OpenSSL to musl). The first musl build compiles OpenSSL from source and takes longer; you still need `gcc`, `make`, and `perl` on the host.

### Building with `ssh-dss`

**libssh2 1.11+ disables `ssh-dss` by default.** This repo sets `CFLAGS=-DLIBSSH2_DSA_ENABLE` in [`.cargo/config.toml`](.cargo/config.toml) so the vendored libssh2 from `ssh2` includes DSA host keys.

If you previously built without that flag, force a relink:

```bash
cargo clean -p libssh2-sys
cargo build --release
```

After building, `probe -v` should list `ssh-dss` under `hostkey`. If it does not, the libssh2 crate was not rebuilt.

## Usage

### One-liner (no `~/.ssh/config`)

```bash
ssh -o ProxyCommand="middling-panda proxy %h %p" admin@legacy-device.example
```

`middling-panda` must be on your `PATH`. All logging goes to **stderr** so stdout stays clean for SSH.

### Optional `~/.ssh/config`

```ssh-config
Host legacy-*
  ProxyCommand middling-panda proxy %h %p
```

Then:

```bash
ssh admin@legacy-device.example
```

### Probe upstream

Handshake and negotiated algorithms:

```bash
middling-panda probe legacy-device.example 22
middling-panda probe -v legacy-device.example 22
```

Test upstream login with a fixed identity (useful for DSA-only `sshd`):

```bash
middling-panda --upstream-identity ~/.ssh/id_dsa \
  probe -u admin -v legacy-device.example 22
```

## Artifacts

MiddlingPanda only writes under its **data directory** (default `~/.middling-panda/`, override with `--data-dir`). It does not modify `~/.ssh/` or your shell history.

| Path | Created when | Purpose |
|------|----------------|---------|
| `id_ed25519` | First `proxy` session (or first use of `server_config`) | **Downstream** Ed25519 host key. This is what your OpenSSH client pins when you connect through the proxy. Regenerated only if you delete the file. Mode `0600` on Unix. |
| `known_hosts` | First successful upstream connect to a host (unless `--no-verify-upstream`) | **Upstream** trust store in OpenSSH `known_hosts` format. Pins the **real** legacy device keys (e.g. `ssh-dss`). Grows as you reach new `host:port` pairs. |

Example layout after use:

```text
~/.middling-panda/
├── id_ed25519      # private key, PEM (MiddlingPanda as SSH "server")
└── known_hosts     # legacy device host keys (MiddlingPanda as SSH client)
```

### What MiddlingPanda does *not* write

| Item | Notes |
|------|--------|
| Your `~/.ssh/known_hosts` | OpenSSH updates this when **you** accept the proxy’s host key (the `id_ed25519` fingerprint), not MiddlingPanda itself. |
| `~/.ssh/authorized_keys` | Unchanged; configure keys on the **legacy** server as usual. |
| `--upstream-identity` key files | Read-only; typically `~/.ssh/id_dsa` or a path you pass on the command line. |
| Logs | Diagnostics go to **stderr** only (no log files by default). |

### Managing artifacts

**Custom data directory** (per user, lab, or project):

```bash
middling-panda --data-dir /var/lib/middling-panda proxy legacy-device.example 22
```

**Lab / no upstream pinning:** `--no-verify-upstream` — `known_hosts` is not read or updated.

**Rotate the downstream (client-visible) host key** — delete `id_ed25519`, then connect again (your SSH client will warn about a changed key):

```bash
rm ~/.middling-panda/id_ed25519
```

**Fix a stale upstream pin** (e.g. after an older build stored `ssh-dss` incorrectly):

```bash
ssh-keygen -R 'legacy-device.example' -f ~/.middling-panda/known_hosts
ssh-keygen -R '[legacy-device.example]:2222' -f ~/.middling-panda/known_hosts   # non-default port
middling-panda probe -v legacy-device.example 22
```

## How it works

```text
[OpenSSH client]  --modern SSH-->  [MiddlingPanda on stdio]
                                        |
                                   libssh2 + legacy KEX/ciphers
                                        |
                                   [Legacy SSH device]
```

OpenSSH runs `middling-panda proxy <host> <port>` and pipes the session over stdin/stdout.

### Authentication

| Method | Behavior |
|--------|----------|
| **Password** | The password you type for the client is reused on the legacy host (unless `--upstream-identity` succeeds first). |
| **Public key** | After the client proves key ownership to MiddlingPanda, the same key is used upstream via **`SSH_AUTH_SOCK`** (if set) or a matching file under **`~/.ssh/`**. |

Public-key passthrough does **not** replay signatures (each SSH leg has its own `session_id`). The ProxyCommand runs on your machine, so it can use your normal agent and key files.

```bash
# Agent (recommended for passphrase-protected keys)
ssh -A -o ProxyCommand="middling-panda proxy %h %p" admin@legacy-device.example

# On-disk key
ssh -i ~/.ssh/id_ed25519 -o ProxyCommand="middling-panda proxy %h %p" admin@legacy-device.example
```

The legacy host must have your **public** key in `authorized_keys` (same as a direct SSH login).

### DSA-only servers (`PubkeyAcceptedAlgorithms ssh-dss`)

OpenSSH 9+ clients **cannot load** `id_dsa` (`Load key: unknown or unsupported key type`). Use MiddlingPanda to read the DSA key for the **upstream** leg while you authenticate to the panda with password or a modern key.

1. On the server account, install the **user** public key (not the host key under `/etc/ssh/`):

   ```bash
   cat ~/.ssh/id_dsa.pub >> ~/.ssh/authorized_keys
   ```

2. On the client (do **not** use `-i` with the DSA key — the client cannot load it):

   ```bash
   ssh -o ProxyCommand="middling-panda --upstream-identity ~/.ssh/id_dsa proxy %h %p" \
     admin@legacy-device.example
   ```

   With `--upstream-identity`, MiddlingPanda tries that key on the legacy host **before** using your typed password.

   Optional: skip the password prompt when the client allows `none` first:

   ```bash
   ssh -o PreferredAuthentications=none,password \
     -o ProxyCommand="middling-panda --upstream-identity ~/.ssh/id_dsa proxy %h %p" \
     admin@legacy-device.example
   ```

   Or set `MPANDA_UPSTREAM_IDENTITY=~/.ssh/id_dsa`.

   Use an **absolute path** or `~/…` for `--upstream-identity`. OpenSSH runs `ProxyCommand` with cwd `$HOME`, so `./id_dsa` only works if the key lives in your home directory. A broken `id_dsa.pub` (e.g. from `ssh-keygen -y` when the client cannot load DSA) is ignored; libssh2 reads the private key instead.

**Alternative on the server:** keep `HostkeyAlgorithms ssh-dss` but allow modern user keys:

```text
PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss
```

Then use Ed25519 in `authorized_keys` and normal `-i ~/.ssh/id_ed25519` through the proxy.

### Host keys (two layers)

1. **Your client** checks the hostname you typed, but the key on the wire is **MiddlingPanda’s** Ed25519 key (first connect pins it in your normal `known_hosts` for that name).
2. **MiddlingPanda** verifies the **real** device key in `~/.middling-panda/known_hosts` (auto-pinned on first successful connect unless verification is disabled).

## SSH ControlMaster (`-M`)

Full OpenSSH multiplexing is **not** implemented (the mux control leg is handled locally only). For a background master socket:

```bash
ssh -N -M -S ~/.ssh/mux-legacy.sock \
  -o ProxyCommand="middling-panda proxy %h %p" \
  admin@legacy-device.example
```

Attach with:

```bash
ssh -S ~/.ssh/mux-legacy.sock admin@legacy-device.example
```

For a normal login, omit `-M`/`-S`.

## OpenSSL 3 and `ssh-dss`

**First:** confirm `middling-panda probe -v` lists `ssh-dss` under `libssh2 supported algorithms` → `hostkey`. If `ssh-dss` is missing, fix the **libssh2 build** (see above), not OpenSSL alone.

Many Linux distros use **OpenSSL 3**, which disables **DSA** at runtime unless the **legacy** provider is loaded. A server that only offers `ssh-dss` can make `probe` / upstream fail with:

```text
Unable to exchange encryption keys
```

Use the sample config in this repo:

```bash
export OPENSSL_CONF="$PWD/config/openssl-legacy.cnf"
middling-panda probe -v legacy-device.example 22
```

On Fedora you may also need:

```bash
export OPENSSL_MODULES=/usr/lib64/ossl-modules
```

## WSL2

Use the same build and `ProxyCommand` flow as on Linux (install deps from **Fedora** or **Debian** sections above).

### Reaching `sshd` on the Windows host

In WSL2, `127.0.0.1` is the Linux VM’s loopback, not the Windows host where `sshd` may listen. If direct SSH from Windows works but MiddlingPanda in WSL does not, use the Windows host IP:

```bash
WIN_HOST=$(grep -m1 nameserver /etc/resolv.conf | awk '{print $2}')
middling-panda probe "$WIN_HOST" 22
ssh -o ProxyCommand="middling-panda proxy %h %p" admin@"$WIN_HOST"
```

`%h` and `%p` must match the host and port the legacy service exposes.

## Feature status

| Status | Feature |
|--------|---------|
| **MVP** | `proxy` subcommand (ProxyCommand / stdio) |
| **MVP** | Password + public-key passthrough |
| **MVP** | `--upstream-identity` for DSA-only upstream |
| **MVP** | Interactive shell + exec |
| **MVP** | Legacy algorithm set (incl. `ssh-dss` upstream) |
| **MVP** | `probe` subcommand |
| **MVP** | Upstream `known_hosts` + data-dir host key |
| **Deferred** | Native Windows/macOS builds (use WSL2 on Windows) |
| **Deferred** | Encrypted `~/.ssh` keys without agent (use `ssh-add` / `ssh -A`) |
| **Deferred** | SFTP / `direct-tcpip` port forwarding |
| **Deferred** | `listen` mode (TCP accept without per-connection `%h` `%p`) |

## Security

Legacy crypto is weak by design. Run MiddlingPanda only on a management network; do not expose legacy algorithms on an internet-facing `sshd`.

## License

MiddlingPanda is licensed under the [Apache License, Version 2.0](LICENSE). See [LICENSE](LICENSE) for the full text.
