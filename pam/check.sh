#!/usr/bin/env bash
set -euo pipefail

# Fails if anything root executes or trusts for sudo authentication could be changed by a non-root
# user: each file and every directory above it must be root-owned, not a symlink, and not group- or
# world-writable. Needs no root. Prints one line per problem and exits 1 if there is any.
#
# Usage: check.sh [--service-only] [--prefix DIR] [--owner-uid N]
#   --service-only  skip the PAM and sudoers files
#   --prefix DIR    check a tree under DIR, stopping at DIR (tests)
#   --owner-uid N   the uid that must own the files instead of root (tests)

PREFIX="" OWNER_UID=0 SERVICE_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-only) SERVICE_ONLY=1; shift ;;
        --prefix) PREFIX="${2:?}"; shift 2 ;;
        --owner-uid) OWNER_UID="${2:?}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

LIB=/usr/local/lib/alohomora
FILES=(
    "${LIB}/pass-secret-service" "${LIB}/alohomora-sudo-approve" "${LIB}/alohomora-setup"
    "${LIB}/alohomora-local-device" "${LIB}/alohomora-unlock"
    /etc/systemd/system/alohomora-service.service
)
# Only tested for ownership when readable: this directory is deliberately 0700 root.
DIRS=(/var/lib/alohomora-service)
if [[ "${SERVICE_ONLY}" -eq 0 ]]; then
    FILES+=("${LIB}/sudo-alohomora-auth" /etc/pam.d/sudo /etc/sudoers.d/90-cloud-init-users)
fi

bad=0
problem() { echo "FAIL  $1"; bad=1; }

# Sticky is no exception: no path here should sit in a shared directory.
check_entry() {
    local path="$1" uid mode
    if [[ -L "${path}" ]]; then problem "${path} is a symlink -> $(readlink "${path}")"; return; fi
    if ! read -r uid mode < <(stat -c '%u %a' -- "${path}" 2>/dev/null); then
        # A file under an unreadable root-only directory cannot be stat'ed without root.
        if [[ ! -x "$(dirname "${path}")" ]]; then return; fi
        problem "${path} is missing"; return
    fi
    [[ "${uid}" == "${OWNER_UID}" ]] || problem "${path} is owned by uid ${uid}"
    if (( 8#${mode} & 8#022 )); then problem "${path} is group/world-writable (${mode})"; fi
}

check_path() {
    local path="$1"
    check_entry "${PREFIX}${path}"
    path="$(dirname "${path}")"
    while [[ "${path}" != / ]]; do
        check_entry "${PREFIX}${path}"
        path="$(dirname "${path}")"
    done
    [[ -n "${PREFIX}" ]] || check_entry /
}

for path in "${FILES[@]}" "${DIRS[@]}"; do check_path "${path}"; done

# The unit must run the installed copy and keep gpg's config out of the user's reach.
UNIT="${PREFIX}/etc/systemd/system/alohomora-service.service"
if [[ -r "${UNIT}" ]]; then
    grep -q "^ExecStart=${LIB}/pass-secret-service\$" "${UNIT}" || problem "${UNIT} does not run ${LIB}/pass-secret-service"
    if grep -Eq '^[^#]*(GNUPGHOME|HOME)=/home/' "${UNIT}"; then problem "${UNIT} points gpg at a user-writable home"; fi
fi
WANTS="${PREFIX}/etc/systemd/system/multi-user.target.wants/alohomora-service.service"
if [[ -L "${WANTS}" && "$(readlink "${WANTS}")" == /home/* ]]; then problem "${WANTS} points into a home directory"; fi
# The PAM file must only ever call the installed helper.
PAM="${PREFIX}/etc/pam.d/sudo"
if [[ "${SERVICE_ONLY}" -eq 0 && -r "${PAM}" ]]; then
    grep -q "pam_exec.so quiet ${LIB}/sudo-alohomora-auth\$" "${PAM}" || problem "${PAM} does not call ${LIB}/sudo-alohomora-auth"
fi

if [[ "${bad}" -eq 0 ]]; then echo "OK    Alohomora root-owned files"; fi
exit "${bad}"
