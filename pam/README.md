# Alohomora Sudo Authentication

Configure `sudo` to require mobile biometric push authorization through Alohomora, with fallback to Linux account password authentication upon pressing `Enter`.

## Overview

When you run `sudo <command>`:
1. PAM invokes `/usr/local/lib/alohomora/sudo-alohomora-auth` via `pam_exec.so`, which asks the daemon over a root-only socket (`/run/alohomora/sudo-auth.sock`).
2. Alohomora dispatches a push notification via Firebase Cloud Messaging (FCM) to your paired Android device.
3. The terminal displays:
   ```text
   Alohomora push sent. Press Enter for password: 
   ```
4. **Push approval**: Tap **Approve** on your phone (using fingerprint/face biometric). Alohomora releases the token, and `sudo` executes immediately without asking for a password.
5. **Password fallback**: Hit **Enter** at the terminal prompt (or if phone/service times out or fails, in which case an explanatory message is printed first), and sudo falls back to standard Linux password prompt:
   ```text
   [sudo] password for ubuntu: 
   ```
   Without a tty there is no password fallback: sudo prints the explanation (to the stderr of the process that ran it) followed by `sudo: PAM error: System error`, and does not retry. The script avoids `pam_exec`'s `stdout` option because sudo-rs aborts with a misleading "A terminal is required" if any PAM message arrives without a tty.

## Prerequisites

1. Mobile device paired and registered with `alohomora-service`.
2. `alohomora-service` systemd service running.
3. Ensure your Linux user account has a password set (e.g. `sudo passwd ubuntu`).

## Installation and updates

Build, then run the install script as root:

```bash
cargo build --release
sudo ./pam/install.sh
```

This installs **root-owned copies, never symlinks**:
- `/usr/local/lib/alohomora/`: the helper and all service binaries (0755 root:root).
- `/etc/pam.d/sudo` (0644, original backed up to `.orig`) and `/etc/sudoers.d/90-cloud-init-users` (0440).
- `/etc/systemd/system/alohomora-service.service` (0644), running the installed binary.

It restarts `alohomora-service` if the binary or unit changed, then runs `check.sh`.

**To deploy any change** to these files, re-run `sudo ./pam/install.sh` after merging (one phone tap). Editing the checkout changes nothing on the host. `sudo ./pam/install.sh --service-only` deploys just the binaries and unit (and is how a new host gets the service before PAM is switched on).

## Security model

Root runs these files, so a user-writable copy would be root without a tap. Hence:

- `./pam/check.sh` (no root needed) fails if any file, or any directory above one, is a symlink, not root-owned, or group/world-writable. Run it after any host change.
- The approval never crosses the session bus. The user owns that bus's daemon and socket and could answer `org.freedesktop.secrets` themselves, so the helper talks to `/run/alohomora/sudo-auth.sock`, in a 0700 root directory.
- The service's `GNUPGHOME` and `HOME` are under `/var/lib/alohomora-service`: root's `gpg` obeys `gpg.conf`, which can name a program to run.
- The helper fixes `PATH`, ignores `BASH_ENV`, and drops to the user before writing to a caller-chosen stderr.

## Password fallback

Unchanged: pressing Enter, a denial, a timeout or a stopped service all fall back to the password on a terminal. While `alohomora-service` restarts (a few seconds), terminal `sudo` asks for the password and non-tty `sudo` fails.

## Uninstallation

To restore standard sudo behavior:

```bash
sudo ./pam/uninstall.sh
```

The service, its binaries and its unit stay installed; only PAM, sudoers and the helper are restored.
