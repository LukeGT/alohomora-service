#!/usr/bin/env bash
set -euo pipefail

# Installs Alohomora's sudo authentication and service as ROOT-OWNED COPIES, never symlinks: root
# executes these files, so anything the user can edit is a route to root without a phone tap.
# Re-run after every `cargo build --release` to deploy (needs one sudo tap, which is the point).
#
# Usage (as root): install.sh [--service-only] [--bin-dir DIR] [--prefix DIR]
#   --service-only  install the binaries and unit and restart the service; leave PAM and sudoers alone
#   --bin-dir DIR   where the built binaries are (default: <repo>/target/release)
#   --prefix DIR    install under DIR, without root, service control or visudo (tests)

umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"
BIN_DIR="${REPO_DIR}/target/release"
PREFIX="" SERVICE_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-only) SERVICE_ONLY=1; shift ;;
        --bin-dir) BIN_DIR="${2:?}"; shift 2 ;;
        --prefix) PREFIX="${2:?}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ -z "${PREFIX}" && "$(id -u)" -ne 0 ]]; then
    echo "Error: install.sh must be run as root (e.g. sudo ./install.sh)" >&2
    exit 1
fi
owner=(-o root -g root)
[[ -z "${PREFIX}" ]] || owner=()

LIB_DIR="${PREFIX}/usr/local/lib/alohomora"
BINARIES=(pass-secret-service alohomora-sudo-approve alohomora-setup alohomora-local-device alohomora-unlock)
for binary in "${BINARIES[@]}"; do
    [[ -x "${BIN_DIR}/${binary}" ]] || { echo "Error: ${BIN_DIR}/${binary} missing; run cargo build --release" >&2; exit 1; }
done

# Write beside the target, then rename, so a symlink is replaced rather than followed and readers
# never see a partial file.
put() {
    local mode="$1" source="$2" target="$3"
    mkdir -p "$(dirname "${target}")"
    install -m "${mode}" "${owner[@]}" "${source}" "${target}.new"
    mv -Tf "${target}.new" "${target}"
}

sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

echo "Installing Alohomora service binaries and unit..."
install -d -m 0755 "${owner[@]}" "${LIB_DIR}"
service_changed=0
[[ "$(sha "${LIB_DIR}/pass-secret-service")" == "$(sha "${BIN_DIR}/pass-secret-service")" ]] || service_changed=1
UNIT="${PREFIX}/etc/systemd/system/alohomora-service.service"
if [[ -L "${UNIT}" ]] || ! cmp -s "${REPO_DIR}/systemd/alohomora-service.service" "${UNIT}"; then service_changed=1; fi
for binary in "${BINARIES[@]}"; do put 0755 "${BIN_DIR}/${binary}" "${LIB_DIR}/${binary}"; done
put 0644 "${REPO_DIR}/systemd/alohomora-service.service" "${UNIT}"
install -d -m 0700 "${owner[@]}" "${PREFIX}/var/lib/alohomora-service"
install -d -m 0700 "${owner[@]}" "${PREFIX}/var/lib/alohomora-service/gnupg"

# Restart before PAM changes: the new helper needs the daemon's socket. During the restart sudo
# falls back to the password on a terminal and fails without one.
if [[ -z "${PREFIX}" ]]; then
    systemctl daemon-reload
    # An enablement link from an older install still points into the checkout.
    if systemctl is-enabled --quiet alohomora-service; then systemctl reenable --quiet alohomora-service; fi
    if [[ "${service_changed}" -eq 1 ]] && systemctl is-active --quiet alohomora-service; then
        echo "Restarting alohomora-service..."
        systemctl restart alohomora-service
    fi
fi

if [[ "${SERVICE_ONLY}" -eq 0 ]]; then
    echo "Installing Alohomora sudo authentication..."
    put 0755 "${SCRIPT_DIR}/sudo-alohomora-auth" "${LIB_DIR}/sudo-alohomora-auth"

    PAM="${PREFIX}/etc/pam.d/sudo"
    if [[ -f "${PAM}" && ! -L "${PAM}" && ! -e "${PAM}.orig" ]] && ! grep -q sudo-alohomora-auth "${PAM}"; then
        echo "Backing up original /etc/pam.d/sudo to /etc/pam.d/sudo.orig..."
        cp -p "${PAM}" "${PAM}.orig"
    fi
    put 0644 "${SCRIPT_DIR}/pam-sudo" "${PAM}"

    # Replaced by this version; both pointed into the user-writable checkout or are now unused.
    rm -f "${PREFIX}/usr/local/bin/sudo-alohomora-auth" "${PREFIX}/usr/local/bin/sudo-auth"

    SUDOERS="${PREFIX}/etc/sudoers.d/90-cloud-init-users"
    if [[ -f "${SUDOERS}" && ! -L "${SUDOERS}" && ! -e "${SUDOERS}.orig" ]]; then
        echo "Backing up /etc/sudoers.d/90-cloud-init-users to .orig..."
        cp -p "${SUDOERS}" "${SUDOERS}.orig"
    fi
    put 0440 "${SCRIPT_DIR}/90-cloud-init-users" "${SUDOERS}"

    if [[ -z "${PREFIX}" ]] && ! visudo -c >/dev/null; then
        echo "Error: visudo check failed! Reverting sudoers change..." >&2
        [[ ! -f "${SUDOERS}.orig" ]] || cp -p "${SUDOERS}.orig" "${SUDOERS}"
        exit 1
    fi
fi

if [[ -z "${PREFIX}" ]]; then
    check_args=(); [[ "${SERVICE_ONLY}" -eq 0 ]] || check_args=(--service-only)
    "${SCRIPT_DIR}/check.sh" "${check_args[@]+"${check_args[@]}"}"
fi
echo "Alohomora installed successfully!"
