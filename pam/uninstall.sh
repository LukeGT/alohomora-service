#!/usr/bin/env bash
set -euo pipefail

# Must be run with root / sudo
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: uninstall.sh must be run as root (e.g. sudo ./uninstall.sh)" >&2
    exit 1
fi

echo "Uninstalling Alohomora sudo authentication..."

# 1. Restore /etc/pam.d/sudo
if [ -L /etc/pam.d/sudo ]; then
    echo "Removing symlink /etc/pam.d/sudo..."
    rm -f /etc/pam.d/sudo
    if [ -f /etc/pam.d/sudo.orig ]; then
        echo "Restoring /etc/pam.d/sudo from backup..."
        cp -p /etc/pam.d/sudo.orig /etc/pam.d/sudo
        rm -f /etc/pam.d/sudo.orig
    elif [ -f /etc/pam.d/sudo.bak ]; then
        echo "Restoring /etc/pam.d/sudo from .bak..."
        cp -p /etc/pam.d/sudo.bak /etc/pam.d/sudo
    fi
fi

# 2. Restore /etc/sudoers.d/90-cloud-init-users
if [ -f /etc/sudoers.d/90-cloud-init-users.orig ]; then
    echo "Restoring /etc/sudoers.d/90-cloud-init-users from backup..."
    cp -p /etc/sudoers.d/90-cloud-init-users.orig /etc/sudoers.d/90-cloud-init-users
    chmod 0440 /etc/sudoers.d/90-cloud-init-users
    chown root:root /etc/sudoers.d/90-cloud-init-users
    rm -f /etc/sudoers.d/90-cloud-init-users.orig
elif [ -f /etc/sudoers.d/90-cloud-init-users.bak ]; then
    echo "Restoring /etc/sudoers.d/90-cloud-init-users from .bak..."
    cp -p /etc/sudoers.d/90-cloud-init-users.bak /etc/sudoers.d/90-cloud-init-users
    chmod 0440 /etc/sudoers.d/90-cloud-init-users
    chown root:root /etc/sudoers.d/90-cloud-init-users
fi

# 3. Validate sudoers syntax
if ! visudo -c; then
    echo "Warning: visudo check reported issues!" >&2
fi

# 4. Remove /usr/local/bin/sudo-alohomora-auth symlink
if [ -L /usr/local/bin/sudo-alohomora-auth ]; then
    echo "Removing /usr/local/bin/sudo-alohomora-auth symlink..."
    rm -f /usr/local/bin/sudo-alohomora-auth
fi

# 5. Optionally remove /usr/local/bin/sudo-auth symlink if it points to secret-tool
if [ -L /usr/local/bin/sudo-auth ]; then
    TARGET=$(readlink -f /usr/local/bin/sudo-auth 2>/dev/null || true)
    if [ "$TARGET" = "/usr/bin/secret-tool" ]; then
        echo "Removing /usr/local/bin/sudo-auth symlink..."
        rm -f /usr/local/bin/sudo-auth
    fi
fi

echo "Alohomora sudo authentication uninstalled successfully!"
