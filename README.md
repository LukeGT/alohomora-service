# Pass Secret Service

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/grimsteel/pass-secret-service/release.yml?style=for-the-badge&logo=github)

Implementation of [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service-spec/latest/) using [`pass`](https://www.passwordstore.org/)

Secrets are stored in GPG files under `~/.password-store/secret-service`. Attributes are not encrypted.

## Installation

[![AUR Badge](https://img.shields.io/aur/version/pass-secret-service-bin?style=for-the-badge&logo=archlinux&label=AUR:%20BIN)](https://aur.archlinux.org/packages/pass-secret-service-bin)

[![AUR Badge](https://img.shields.io/aur/version/pass-secret-service-git?style=for-the-badge&logo=archlinux&label=AUR:%20GIT)](https://aur.archlinux.org/packages/pass-secret-service-git)

There are prebuilt binaries for `x86_64-unknown-linux-gnu` on the Releases page.

### Building from source

Does not require any additional dependencies to build (uses a pure-rust D-Bus implementation)

```sh
cargo build --release
```

Systemd service templates, D-Bus session configuration, and setup guides are located in the [`systemd`](systemd/) directory. See [`systemd/README.md`](systemd/README.md) for root service configuration and desktop session bus integration.

## Usage

```
Usage: pass-secret-service [-d <path>] [-f] [-n] [-V] [--log-level <log-level>] [<command>] [<args>]

Background daemon for pass-secret-service: An implementation of org.freedesktop.secrets using pass

Options:
  -d, --path        location of the password store. Will fall back to
                    $PASSWORD_STORE_DIR, or $HOME/.password-store if not set.
  -f, --forget-password-on-lock
                    make gpg-agent forget the cached key password when any
                    collection is locked
  -n, --notify-on-access
                    send a desktop notification via org.freedesktop.Notifications
                    whenever a secret is accessed
  -V, --version     print the current version
  --log-level       log level (overridden by $RUST_LOG environment variable)
                    uses env_logger syntax
  --help, help      display usage information

Commands:
  run-service       Run the secret-service provider
  last-accessor     Retrieve the last application to access the specified secret
```

The subcommand is optional; ommitting it defaults to `run-service`.

### Authorization timeout

Set `ALOHOMORA_AUTH_TIMEOUT_SECS` (integer seconds, 1-3600, default 60) to control how long the service waits for a mobile approval before failing the request. Invalid values abort startup with a configuration error.

### Unlocking and prompts

Reading a secret needs a phone approval, which can take far longer than the 25 second timeout libsecret (GDBus) applies to a single D-Bus method call. Items and collections are therefore reported as locked and approval goes through the standard Secret Service prompt flow:

1. `SearchItems` lists matching items as locked.
2. `Unlock(objects)` returns a prompt object (`/org/freedesktop/secrets/prompt/<id>`) without waiting.
3. `Prompt.Prompt(window_id)` replies immediately; the approval request is sent once that reply is on the wire. Only the D-Bus connection that called `Unlock` may use the prompt, and each prompt can only be started once (one push per prompt). A prompt that is never started is removed after 60 seconds, and a client may have at most 8 outstanding prompts.
4. `Prompt.Completed(dismissed, ao)` is emitted when the request is approved (`dismissed = false`) or when it fails (`dismissed = true`, empty result): it times out after `ALOHOMORA_AUTH_TIMEOUT_SECS`, or immediately if no device could be notified. There is no explicit deny: declining on the phone just lets the request time out. `Prompt.Dismiss` cancels the pending request, and so does the client disconnecting (for example, pressing Enter in the sudo hook to use a password instead).
5. An approval becomes a **single-use grant** for that connection's unique name and the approved objects. A collection grant covers its items, so `Unlock(item)` after `Unlock(collection)` returns without another prompt. The first `GetSecrets`, `Item.GetSecret`, `CreateItem` or `SetSecret` covered by the grant consumes it; the next read needs a new approval. A grant that nobody claims is discarded after 10 seconds. Grants are also dropped when their client disconnects, and any `Lock` call (from any client) on an overlapping item or collection revokes them.

`Item.Locked` and `Collection.Locked` are now `true` by default. They are `false` only while some connection holds an unclaimed grant for the object, because property getters cannot tell who is asking. `SearchItems` reports items as unlocked only for the caller holding the grant.

What this means for clients:

- libsecret (`secret-tool lookup`/`store`, Chrome) unlocks automatically and works as before, now with no 25 second limit on approval.
- `secret-tool search` without `--unlock` lists only the attributes of locked items and no longer prints secrets.
- Clients that check `Locked` themselves must call `Unlock` first. Python `secretstorage`, for example, raises `LockedException` from `Item.get_secret()` and `Collection.create_item()` unless the item or collection was unlocked (as the `keyring` package does) just before.
- Clients that skip `Unlock` and call `GetSecrets`/`GetSecret`/`CreateItem`/`SetSecret` directly still work: the call blocks until the phone approval arrives, so it is limited by the client's method-call timeout (25 seconds for libsecret). The pending request is cancelled if the client disconnects.

### Access notifications (`--notify-on-access`)

Pass `-n` / `--notify-on-access` to send a desktop notification via `org.freedesktop.Notifications` every time a secret value is read. Each notification includes the secret label, the accessing application name, its PID, and UID.

```sh
pass-secret-service -n
pass-secret-service run-service --notify-on-access
```

With systemd D-Bus activation, this can be configured with a drop in:
```sh
systemctl --user edit pass-secret-service.service
```

```toml
[Service]
ExecStart=
ExecStart=/usr/bin/pass-secret-service -n
```

### Getting the last secret accessor (#20)

The service stores information about the last accessor for each secret in memory.

Whenever a process requests a secret (not attributes/other metadata), the PID, UID, and program name are stored.

These can be retrieved with the `last-accessor` subcommand with the secret ID:

```
Usage: pass-secret-service last-accessor <id> [-C <collection>] [-A <alias>]

Retrieve the last application to access the specified secret

Positional Arguments:
  id                the secret ID. use `secret-tool search` to find

Options:
  -C, --collection  the collection of the secret. Takes precedence over --alias
  -A, --alias       the collection alias of the secret. `default` if neither
                    this nor --collection is given.
  --help, help      display usage information
```

**Example output**:
```
[INFO  pass_secret_service] The last access of collection/default/abcd123 was 15m 41s ago:
[INFO  pass_secret_service]   User: 1000
[INFO  pass_secret_service]   Program: gh (PID 123456)
[INFO  pass_secret_service]   Timestamp: Sun, 1 Jan 2026 01:23:45
```

## Local (virtual) device for emergency unlock

If your phone is unavailable you can register a password-protected *local device*. It uses exactly the same protocol as the Android app (RSA-2048 key, `ALHM1` challenge, `ALHR1` response) but the challenge is delivered over loopback HTTP instead of a push notification.

### Registering

Registration reuses Safe Pairing, so it needs approval from an existing device first (or is the very first device):

1. Run `alohomora-setup`; once any existing device approved, it prints the QR code and a ready-to-paste `alohomora-local-device register ...` command (terminal only, never logged; it contains the short-lived pairing token) and waits for a registration.
2. In another terminal on the same host (with access to the key directory), paste that command, i.e.:

   ```sh
   alohomora-local-device register --setup '<setup URL or token>' --server http://127.0.0.1:19969   # --setup can also be piped on stdin
   ```

   You are prompted twice for an unlock password (min. 12 characters). A key pair is generated, the public key is registered with the name "Local Terminal Unlock" via the normal `POST /alohomora/register` route on the internal port (`ALOHOMORA_INTERNAL_PORT`, default 19969), and the encrypted private key is stored.

   If the running service already holds the internal port (relay mode), the setup server cannot bind it; stop the service for the duration of registration or pass `--server` to a reachable setup server.

### Unlocking

When a secret access is pending (the service waits up to 60 seconds), run:

```sh
alohomora-unlock
```

Enter the password; the private key is decrypted in memory only, used to answer the pending challenge, then zeroized. Options: `--device-uuid`, `--server`, `--wait <seconds>` (default 30, how long to wait for a request to appear).

### Storage layout

Under the key directory (`ALOHOMORA_KEY_DIR`, default `/var/lib/alohomora-service`):

```
device-keys/local/<device uuid>/enc_device_registration.json   # daemon side, like Android devices
device-keys/local/<device uuid>/enc_secret_key.bin             # daemon side, like Android devices
device-keys/local/<device uuid>/private_key.enc.json           # CLI side, mode 0600
```

`private_key.enc.json` is versioned JSON holding the Argon2id parameters (m=64 MiB, t=3, p=1 by default), a random 16-byte salt and the AES-256-GCM encrypted PKCS#8 private key. Parameters read back from the file are bounds-checked.

### Security notes

- Local unlocks are logged at `info` (device uuid/name, request uuid, requesting uid/user/pid/process); no secrets are logged and no notification is sent.
- Pending local challenges are kept in memory only and removed on completion or timeout. `GET /alohomora/local/challenges` is served only when the TCP peer is loopback **and** no `X-Forwarded-For`, `Forwarded`, `X-Real-IP` or `Via` header is present. Challenges are encrypted to the device key, so reading them without the password is useless.
- There is no unauthenticated registration route; registration needs the one-time pairing token.
- Anyone who can read the key directory and knows the password can unlock secrets, so treat the password like a root credential. A weak password makes an offline attack on `private_key.enc.json` feasible (Argon2id only slows it down).
