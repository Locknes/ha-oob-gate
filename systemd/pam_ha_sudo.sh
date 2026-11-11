#!/bin/bash -p
# ==============================================================================
# pam_ha_sudo.sh - Linux PAM Helper for Home Assistant Out-of-Band Sudo Gate
# Executed by: pam_exec.so inside /etc/pam.d/sudo
# ==============================================================================
set -euo pipefail

# When executed as root via PAM (EUID == 0), strictly enforce immutable system paths.
# Non-root override hooks are allowed ONLY for unprivileged unit tests.
if [[ "${EUID:-0}" -eq 0 ]]; then
    GATE_BIN="/usr/local/libexec/ha-sudo/ha_sudo_gate.py"
    PYTHON_BIN="/usr/bin/python3"
    GROUP_FILE="/etc/group"
    PASSWD_FILE="/etc/passwd"
    TEST_CONFIG_ENV=()
else
    GATE_BIN="${HA_SUDO_TEST_GATE_BIN:-/usr/local/libexec/ha-sudo/ha_sudo_gate.py}"
    PYTHON_BIN="${HA_SUDO_TEST_PYTHON_BIN:-/usr/bin/python3}"
    GROUP_FILE="${HA_SUDO_TEST_GROUP_FILE:-/etc/group}"
    PASSWD_FILE="${HA_SUDO_TEST_PASSWD_FILE:-/etc/passwd}"
    if [[ -n "${HA_SUDO_TEST_CONFIG:-}" ]]; then
        TEST_CONFIG_ENV=("HA_SUDO_CONFIG=${HA_SUDO_TEST_CONFIG}")
    else
        TEST_CONFIG_ENV=()
    fi
fi

BREAKGLASS_GROUP="ha-breakglass"
EXIT_HA_UNREACHABLE=75

# Strictly resolve requesting user from PAM_RUSER (never fallback to caller-mutable env vars)
REQUESTING_USER="${PAM_RUSER:-}"
if [[ -z "$REQUESTING_USER" ]]; then
    echo "[ha-sudo] Fatal: PAM_RUSER is unset; refusing authentication." >&2
    exit 1
fi

# Root running commands directly does not trigger out-of-band check
if [[ "$REQUESTING_USER" == "root" ]]; then
    exit 0
fi

is_breakglass_member() {
    local target_user="$1"
    [[ -r "$GROUP_FILE" ]] || return 1
    local grp_line
    grp_line="$(grep -E "^${BREAKGLASS_GROUP}:" "$GROUP_FILE" 2>/dev/null | head -n1 || true)"
    [[ -n "$grp_line" ]] || return 1
    local grp_gid grp_members
    grp_gid="$(printf '%s' "$grp_line" | cut -d: -f3)"
    grp_members="$(printf '%s' "$grp_line" | cut -d: -f4)"

    # 1. Check supplementary group membership in /etc/group (exact comma-separated token match)
    local IFS=','
    local m
    for m in $grp_members; do
        if [[ "$m" == "$target_user" ]]; then
            return 0
        fi
    done

    # 2. Check primary GID in /etc/passwd if present
    if [[ -n "$grp_gid" && -r "$PASSWD_FILE" ]]; then
        local pw_gid
        pw_gid="$(awk -F: -v u="$target_user" '$1 == u { print $4; exit }' "$PASSWD_FILE" 2>/dev/null || true)"
        if [[ -n "$pw_gid" && "$pw_gid" == "$grp_gid" ]]; then
            return 0
        fi
    fi
    return 1
}

is_physical_console_tty() {
    local tty_val="${PAM_TTY:-}"
    [[ "$tty_val" =~ ^(/dev/)?(tty[1-6]|ttyS[0-3])$ ]]
}

# Always inspect kernel /proc/$PPID/cmdline directly rather than trusting SUDO_COMMAND
COMMAND=""
if [[ -f "/proc/$PPID/cmdline" ]]; then
    COMMAND="$(tr '\0' ' ' < "/proc/$PPID/cmdline" 2>/dev/null || true)"
fi
if [[ -z "${COMMAND// /}" ]]; then
    echo "[ha-sudo] Fatal: Could not inspect /proc/$PPID/cmdline." >&2
    exit 1
fi

if [[ ! -x "$PYTHON_BIN" || ! -f "$GATE_BIN" ]]; then
    echo "[ha-sudo] Warning: Gate runtime missing ($PYTHON_BIN / $GATE_BIN)." >&2
    GATE_RC="$EXIT_HA_UNREACHABLE"
else
    set +e
    if [[ "${EUID:-0}" -eq 0 ]]; then
        /usr/bin/env -i \
            PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            PAM_RUSER="$REQUESTING_USER" \
            PAM_TTY="${PAM_TTY:-}" \
            "$PYTHON_BIN" -I "$GATE_BIN" --pam --user "$REQUESTING_USER" "$COMMAND"
    else
        /usr/bin/env -i \
            PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            PAM_RUSER="$REQUESTING_USER" \
            PAM_TTY="${PAM_TTY:-}" \
            "${TEST_CONFIG_ENV[@]}" \
            "$PYTHON_BIN" "$GATE_BIN" --pam --user "$REQUESTING_USER" "$COMMAND"
    fi
    GATE_RC=$?
    set -e
fi

if [[ "$GATE_RC" -eq 0 ]]; then
    exit 0
fi

# Emergency Break-Glass: ONLY when daemon/Home Assistant is unreachable (exit 75), AND caller is in
# root-managed `/etc/group` `ha-breakglass`, AND authenticated on a local physical/serial console
# (`tty[1-6]` or `ttyS[0-3]`).
if [[ "$GATE_RC" -eq "$EXIT_HA_UNREACHABLE" ]]; then
    if is_physical_console_tty && is_breakglass_member "$REQUESTING_USER"; then
        logger -p authpriv.crit -t ha-sudo-breakglass \
            "EMERGENCY BREAK-GLASS: OOB gate unreachable; permitting '$REQUESTING_USER' on physical console '${PAM_TTY:-}'." 2>/dev/null || true
        echo "[ha-sudo] ⚠️  EMERGENCY BREAK-GLASS: OOB gate unreachable; permitting '$REQUESTING_USER' on local console '${PAM_TTY:-}'." >&2
        exit 0
    fi
fi

exit 1
