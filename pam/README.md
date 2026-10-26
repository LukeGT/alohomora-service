# Alohomora Sudo Authentication

Configure `sudo` to require mobile biometric push authorization through Alohomora, with fallback to Linux account password authentication upon pressing `Enter`.

## Overview

When you run `sudo <command>`:
1. PAM invokes `sudo-alohomora-auth` via `pam_exec.so`.
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
3. Canary authorization token stored in Alohomora:
   ```bash
   printf "sudo-authorized" | secret-tool store --label="Sudo" service sudo
   ```
4. Ensure your Linux user account has a password set (e.g. `sudo passwd ubuntu`).

## Installation

Run the install script as root:

```bash
sudo ./pam/install.sh
```

This will:
- Link `/usr/local/bin/sudo-auth` to `/usr/bin/secret-tool`.
- Link `/usr/local/bin/sudo-alohomora-auth` to `pam/sudo-alohomora-auth`.
- Back up `/etc/pam.d/sudo` to `.orig` and link it to `pam/pam-sudo`.
- Back up `/etc/sudoers.d/90-cloud-init-users` to `.orig` and configure it to require authentication.
- Validate configuration with `visudo -c`.

## Uninstallation

To restore standard sudo behavior:

```bash
sudo ./pam/uninstall.sh
```
