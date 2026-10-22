#!/usr/bin/env bash
set -euo pipefail

# Must be run with root / sudo
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: install.sh must be run as root (e.g. sudo ./install.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Alohomora sudo authentication..."

# 1. Symlink /usr/local/bin/sudo-auth -> /usr/bin/secret-tool
if [ ! -e "/usr/local/bin/sudo-auth" ]; then
    echo "Creating /usr/local/bin/sudo-auth symlink..."
    ln -sf /usr/bin/secret-tool /usr/local/bin/sudo-auth
fi

# 2. Symlink /usr/local/bin/sudo-alohomora-auth
echo "Linking /usr/local/bin/sudo-alohomora-auth -> ${SCRIPT_DIR}/sudo-alohomora-auth..."
chmod +x "${SCRIPT_DIR}/sudo-alohomora-auth"
ln -sf "${SCRIPT_DIR}/sudo-alohomora-auth" /usr/local/bin/sudo-alohomora-auth

# 3. Configure /etc/pam.d/sudo
if [ ! -L /etc/pam.d/sudo ] && [ -f /etc/pam.d/sudo ] && [ ! -f /etc/pam.d/sudo.orig ]; then
    echo "Backing up original /etc/pam.d/sudo to /etc/pam.d/sudo.orig..."
    cp -p /etc/pam.d/sudo /etc/pam.d/sudo.orig
fi
echo "Linking /etc/pam.d/sudo -> ${SCRIPT_DIR}/pam-sudo..."
ln -sf "${SCRIPT_DIR}/pam-sudo" /etc/pam.d/sudo

# 4. Configure /etc/sudoers.d/90-cloud-init-users (must be regular file owned by root:root 0440)
if [ -f /etc/sudoers.d/90-cloud-init-users ] && [ ! -L /etc/sudoers.d/90-cloud-init-users ] && [ ! -f /etc/sudoers.d/90-cloud-init-users.orig ]; then
    echo "Backing up /etc/sudoers.d/90-cloud-init-users to .orig..."
    cp -p /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/90-cloud-init-users.orig
fi

echo "Updating /etc/sudoers.d/90-cloud-init-users..."
rm -f /etc/sudoers.d/90-cloud-init-users
cp "${SCRIPT_DIR}/90-cloud-init-users" /etc/sudoers.d/90-cloud-init-users
chmod 0440 /etc/sudoers.d/90-cloud-init-users
chown root:root /etc/sudoers.d/90-cloud-init-users

# 5. Validate sudoers syntax
if ! visudo -c; then
    echo "Error: visudo check failed! Reverting sudoers change..." >&2
    if [ -f /etc/sudoers.d/90-cloud-init-users.orig ]; then
        cp -p /etc/sudoers.d/90-cloud-init-users.orig /etc/sudoers.d/90-cloud-init-users
    fi
    exit 1
fi

echo "Alohomora sudo authentication installed successfully!"
