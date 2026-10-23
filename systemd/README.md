# Systemd Service and D-Bus Configuration

Alohomora requires root privileges to access `/var/lib/alohomora-service` and decrypt `local_key.bin` using `systemd-creds`, while serving D-Bus requests on the logged-in desktop user's session bus.

## Files

1. **`alohomora-service.service`**:
   - System-wide systemd unit (`/etc/systemd/system/alohomora-service.service`).
   - Runs as `User=root`.
   - Points `DBUS_SESSION_BUS_ADDRESS` to the user session bus socket (`unix:path=/run/user/1000/bus`).
   - Points `PASSWORD_STORE_DIR`, `GNUPGHOME`, and `HOME` to the target user's directories (`/home/ubuntu/.password-store`, `/home/ubuntu/.gnupg`).
   - Configures `ALOHOMORA_DOMAIN`, ports, `ALOHOMORA_NOTIFICATION_URL`, and `ALOHOMORA_AUTH_TIMEOUT_SECS` (how long to wait for a phone approval, in seconds; default 60, valid 1-3600; the unit sets 3600).

2. **`dbus-session-local.conf`**:
   - D-Bus session configuration drop-in (`/etc/dbus-1/session-local.conf`).
   - By default, user session buses reject connections from UID 0 (`root`).
   - This file allows root to authenticate to the user session bus so `pass-secret-service` can acquire `org.freedesktop.secrets`.

## Setup Instructions

1. Install the D-Bus session override:
   ```sh
   sudo cp systemd/dbus-session-local.conf /etc/dbus-1/session-local.conf
   systemctl --user reload dbus
   ```

2. Install and enable the systemd service:
   ```sh
   sudo cp systemd/alohomora-service.service /etc/systemd/system/alohomora-service.service
   sudo systemctl daemon-reload
   sudo systemctl enable alohomora-service
   ```

3. Pair with your mobile device first using `alohomora-setup` before starting the service:
   ```sh
   sudo env ALOHOMORA_DOMAIN=agent.lukegt.com \
            ALOHOMORA_EXTERNAL_PORT=443 \
            ALOHOMORA_INTERNAL_PORT=19969 \
            /path/to/target/release/alohomora-setup
   ```

4. Start `alohomora-service`:
   ```sh
   sudo systemctl start alohomora-service
   ```
