#!/usr/bin/env bash
set -euo pipefail

# Restores standard sudo and removes the PAM helper. The service (its binaries and unit) stays
# installed: other secret-service clients depend on it, and this may run as a dead-man rollback.
# Usage (as root): uninstall.sh [--prefix DIR]   (--prefix: under DIR, without root or visudo; tests)

umask 022

PREFIX=""
if [[ "${1:-}" == "--prefix" ]]; then PREFIX="${2:?}"; fi
if [[ -z "${PREFIX}" && "$(id -u)" -ne 0 ]]; then
    echo "Error: uninstall.sh must be run as root (e.g. sudo ./uninstall.sh)" >&2
    exit 1
fi

echo "Uninstalling Alohomora sudo authentication..."

# 1. Restore /etc/pam.d/sudo. Only replace ours (a link from an older install, or our copy).
PAM="${PREFIX}/etc/pam.d/sudo"
if [[ -L "${PAM}" ]] || grep -q sudo-alohomora-auth "${PAM}" 2>/dev/null; then
    if [[ -f "${PAM}.orig" ]]; then
        echo "Restoring /etc/pam.d/sudo from backup..."
        cp -p "${PAM}.orig" "${PAM}.new"
    elif [[ -f "${PAM}.bak" ]]; then
        echo "Restoring /etc/pam.d/sudo from .bak..."
        cp -p "${PAM}.bak" "${PAM}.new"
    else
        # Never leave sudo without a PAM file: it would deny everyone.
        echo "No backup; writing the stock password-only /etc/pam.d/sudo..."
        cat >"${PAM}.new" <<'STOCK'
#%PAM-1.0
session    required   pam_limits.so
session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
STOCK
        chmod 0644 "${PAM}.new"
    fi
    mv -Tf "${PAM}.new" "${PAM}"
    rm -f "${PAM}.orig"
fi

# 2. Restore /etc/sudoers.d/90-cloud-init-users
SUDOERS="${PREFIX}/etc/sudoers.d/90-cloud-init-users"
for backup in "${SUDOERS}.orig" "${SUDOERS}.bak"; do
    if [[ -f "${backup}" ]]; then
        echo "Restoring /etc/sudoers.d/90-cloud-init-users from ${backup##*.}..."
        cp -p "${backup}" "${SUDOERS}.new"
        chmod 0440 "${SUDOERS}.new"
        [[ -n "${PREFIX}" ]] || chown root:root "${SUDOERS}.new"
        mv -Tf "${SUDOERS}.new" "${SUDOERS}"
        [[ "${backup}" != *.orig ]] || rm -f "${backup}"
        break
    fi
done

# 3. Validate sudoers syntax
if [[ -z "${PREFIX}" ]] && ! visudo -c >/dev/null; then
    echo "Warning: visudo check reported issues!" >&2
fi

# 4. Remove the helper, its client, and anything an older install left behind
rm -f "${PREFIX}/usr/local/lib/alohomora/sudo-alohomora-auth" \
      "${PREFIX}/usr/local/bin/sudo-alohomora-auth"
if [[ -L "${PREFIX}/usr/local/bin/sudo-auth" ]]; then
    rm -f "${PREFIX}/usr/local/bin/sudo-auth"
fi

echo "Alohomora sudo authentication uninstalled successfully!"
