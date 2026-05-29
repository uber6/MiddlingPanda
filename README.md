# MiddlingPanda

SSH crypto bridge written in Rust. Connect with a **modern** OpenSSH client; MiddlingPanda negotiates **legacy** algorithms (including `ssh-dss`) to the real device via libssh2.

No server-side config file. The target host and port come from your SSH command (`%h` / `%p`).

## Build

```bash
cargo build --release
```

The binary is `target/release/middling-panda` (or `target\release\middling-panda.exe` on Windows).

On Windows, libssh2 is built with **WinCNG** (no Perl/OpenSSL required). On Linux/macOS, libssh2 is compiled with OpenSSL from your environment.

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
ssh -o ProxyCommand="middling-panda proxy %h %p" root@192.168.1.10
```

`middling-panda` must be on your `PATH`. All logging goes to **stderr** so stdout stays clean for SSH.

### Optional `~/.ssh/config`

```ssh-config
Host 192.168.* 10.*
  ProxyCommand middling-panda proxy %h %p
```

Then:

```bash
ssh root@192.168.1.10
```

### Probe upstream algorithms

```bash
middling-panda probe 192.168.1.10 22
middling-panda probe -v 192.168.1.10 22
```

Test upstream **login** with a fixed identity (e.g. DSA-only `sshd`):

```bash
middling-panda --upstream-identity /tmp/id_dsa probe -u deciel -v 127.0.0.1 2222
```

Useful before first login to see what the device offers and what was negotiated.

### Data directory

Defaults to `~/.middling-panda/`:

| File | Purpose |
|------|---------|
| `id_ed25519` | MiddlingPanda host key (modern leg — what your SSH client sees) |
| `known_hosts` | Legacy device host keys (panda → device trust) |

Override with `--data-dir /path/to/dir`.

Lab only: `--no-verify-upstream` skips pinning/checking legacy host keys.

If `probe` reports **host key mismatch** after upgrading MiddlingPanda, remove the stale pin (often from an older build that stored `ssh-dss` incorrectly):

```bash
ssh-keygen -R '[127.0.0.1]:2222' -f ~/.middling-panda/known_hosts
./target/release/middling-panda probe -v 127.0.0.1 2222
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

**Authentication passthrough**

| Method | Behavior |
|--------|----------|
| **Password** | The password you type for the client is reused on the legacy host. |
| **Public key** | After the client proves key ownership to MiddlingPanda, the same key is used upstream via **`SSH_AUTH_SOCK`** (if set) or a matching file under **`~/.ssh/`** (`id_ed25519`, `id_rsa`, `id_ecdsa`, `id_dsa`, …). |

Public-key passthrough does **not** replay signatures (each SSH leg has its own `session_id`). The ProxyCommand runs on your machine, so it can use your normal agent and key files.

```bash
# Agent (recommended for passphrase-protected keys)
ssh -A -o ProxyCommand="middling-panda proxy %h %p" user@legacy-host

# On-disk key (default paths)
ssh -i ~/.ssh/id_ed25519 -o ProxyCommand="middling-panda proxy %h %p" user@legacy-host
```

The legacy host must have your **public** key in `authorized_keys` (same as a direct SSH login).

### DSA-only servers (`PubkeyAcceptedAlgorithms ssh-dss`)

OpenSSH 9+ clients **cannot load** `id_dsa` (`Load key: unknown or unsupported key type`). Use MiddlingPanda to read the DSA key file for the **upstream** leg while you log in to the panda with **password** (or Ed25519 to the panda).

1. On the server account, install the **user** public key (not `/etc/ssh/ssh_host_dsa_key`):

   ```bash
   # must be ssh-dss in authorized_keys, e.g.:
   cat ~/.ssh/id_dsa.pub >> ~/.ssh/authorized_keys
   ```

2. On the client:

   ```bash
   ssh -o ProxyCommand="./target/release/middling-panda \
     --upstream-identity /tmp/id_dsa proxy %h %p" \
     -p 2222 deciel@127.0.0.1
   ```

   Do **not** use `-i /tmp/id_dsa` (the client cannot load it).

   With `--upstream-identity`, MiddlingPanda tries that key on the legacy host **before** using your typed password. If upstream pubkey auth succeeds, the password prompt is only for the panda leg (any non-empty password is enough when the client insists on `password` auth).

   Skip the password prompt when the client allows `none` first:

   ```bash
   ssh -o PreferredAuthentications=none,password \
     -o ProxyCommand="./target/release/middling-panda --upstream-identity /tmp/id_dsa proxy %h %p" \
     -p 2222 deciel@127.0.0.1
   ```

   Or: `export MPANDA_UPSTREAM_IDENTITY=/tmp/id_dsa`

**Easier server fix:** keep `HostkeyAlgorithms ssh-dss` but widen user keys:

```text
PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss
```

Then use Ed25519 in `authorized_keys` and normal `-i id_ed25519` through the proxy.

### Host keys (two layers)

1. **Your client** checks the hostname you typed (e.g. `192.168.1.10`) but the key on the wire is **MiddlingPanda’s** Ed25519 key (first connect pins it).
2. **MiddlingPanda** verifies the **real** device key in `~/.middling-panda/known_hosts` (auto-pinned on first successful connect unless you disabled verification).

## SSH ControlMaster (`-M`)

Full OpenSSH multiplexing is **not** implemented (the mux control leg is accepted locally only). For a background master socket, use:

```bash
ssh -N -M -S /tmp/test.ssh -o ProxyCommand="middling-panda proxy %h %p" -p 2222 deciel@127.0.0.1
```

Then attach with `ssh -S /tmp/test.ssh -p 2222 deciel@127.0.0.1`.

For a normal login (no mux), omit `-M`/`-S` or use `-t` for an interactive shell.

## MVP vs deferred

| Status | Feature |
|--------|---------|
| **MVP** | `proxy` subcommand (ProxyCommand / stdio) |
| **MVP** | Password + public-key passthrough |
| **MVP** | Interactive shell + exec |
| **MVP** | Auto legacy algorithm set (incl. `ssh-dss` upstream) |
| **MVP** | `probe` subcommand |
| **MVP** | Upstream `known_hosts` + data-dir host key |
| **Deferred** | Encrypted `~/.ssh` keys without agent (use `ssh-add` / `ssh -A`) |
| **Deferred** | SFTP / `direct-tcpip` port forwarding |
| **Deferred** | `listen` mode (TCP accept without per-connection `%h` `%p`) |

## OpenSSL 3 and `ssh-dss`

**First:** confirm `middling-panda probe -v` lists `ssh-dss` in `libssh2 supported algorithms` → `hostkey`. If `ssh-dss` is missing, fix the **libssh2 build** (previous section), not OpenSSL alone.

Many Linux distros (Fedora, Ubuntu 22.04+) use **OpenSSL 3**, which disables **DSA** at runtime unless the **legacy** provider is loaded. A server that only offers `ssh-dss` can make `probe` / upstream fail with:

```text
Unable to exchange encryption keys
```

OpenSSH fails differently (`no matching host key type found`) because the **client** also disabled `ssh-dss` — MiddlingPanda’s upstream still needs OpenSSL to verify/use DSA for that host key.

**Workaround:** run MiddlingPanda with a config that activates the legacy provider, e.g. `/tmp/openssl-legacy.cnf`:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
```

```bash
export OPENSSL_CONF=/tmp/openssl-legacy.cnf
./target/release/middling-panda probe 127.0.0.1 2222
ssh -p 2222 -o ProxyCommand="./target/release/middling-panda proxy %h %p" deciel@127.0.0.1
```

On Fedora you may also need `OPENSSL_MODULES` pointing at `ossl-modules` (often `/usr/lib64/ossl-modules`).

## WSL → SSH on Windows host

In WSL2, `127.0.0.1` is **WSL’s** loopback, not always the Windows host where your legacy `sshd` listens. If the device works from Windows as `ssh -p 2222 deciel@127.0.0.1` but MiddlingPanda fails in WSL, use the Windows host IP:

```bash
HOST=$(grep -m1 nameserver /etc/resolv.conf | awk '{print $2}')
./target/release/middling-panda probe "$HOST" 2222
ssh -p 2222 -o ProxyCommand="./target/release/middling-panda proxy %h %p" deciel@"$HOST"
```

`%h` and `%p` must reach the same legacy SSH port the Windows host exposes (here port `2222`).

## Security

Legacy crypto is weak by design. Run MiddlingPanda only on a management network; do not expose legacy algorithms on an internet-facing `sshd`.
