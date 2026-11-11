"""
command_policy.py - Structural binary canonicalization and command-prefix allowlist enforcement.

Replaces brittle exact-basename denylists and file-extension blocks in `ssh_gate` and
`command_pinned` `pam_sudo` with:
1. Canonical resolution (`shutil.which` + `os.path.realpath`) inside root-owned system
   binary directories (`st_uid == 0`, non-group/world-writable).
2. Versioned interpreter & interactive-shell regex guard (`python3.12`, `perl5.38`, `ruby3.2`,
   `lua5.4`, `php8.3`, `node20`, `tclsh8.6`, shells, pagers, editors, and privilege wrappers).
3. Explicit, configurable command-prefix allowlists (`allowed_command_prefixes`).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from typing import List, Sequence, Tuple

SAFE_SYSTEM_BIN_DIRS: Tuple[str, ...] = (
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
)
SAFE_SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Matches versioned language interpreters, interactive shells, pagers/editors, and shell-escape wrappers
INTERPRETER_OR_ESCAPE_RE = re.compile(
    r"^(?:"
    r"python|pypy|perl|ruby|irb|erb|lua|luajit|php|node|nodejs|deno|bun|tclsh|expect|"
    r"sh|bash|zsh|dash|ksh|fish|csh|tcsh|ash|busybox|"
    r"su|sudo|doas|pkexec|login|env|nohup|setsid|disown|tmux|screen|"
    r"chroot|nsenter|unshare|systemd-run|xargs|find|"
    r"vim|vi|nvim|view|nano|emacs|ed|less|more|most|man|"
    r"awk|gawk|mawk|nawk|sed|tar|git|gdb|lldb|strace|ltrace"
    r")(?:[0-9._+-]*)$"
)

DEFAULT_SSH_ALLOWED_PREFIXES: Tuple[str, ...] = (
    "systemctl status",
    "systemctl is-active",
    "systemctl is-enabled",
    "systemctl is-failed",
    "systemctl list-units",
    "systemctl list-timers",
    "systemctl show",
    "systemctl cat",
    "journalctl",
    "df",
    "free",
    "uptime",
    "uname",
    "hostname",
    "id",
    "whoami",
    "ps",
    "ss",
    "ip addr",
    "ip link",
    "ip route",
    "ls",
    "stat",
    "docker ps",
    "docker logs",
    "docker inspect",
    "podman ps",
    "podman logs",
    "podman inspect",
)

DEFAULT_PAM_PINNED_ALLOWED_PREFIXES: Tuple[str, ...] = (
    "systemctl status",
    "systemctl start",
    "systemctl stop",
    "systemctl restart",
    "systemctl reload",
    "systemctl enable",
    "systemctl disable",
    "systemctl daemon-reload",
    "systemctl is-active",
    "systemctl is-enabled",
    "systemctl list-units",
    "systemctl list-timers",
    "systemctl show",
    "systemctl cat",
    "journalctl",
    "nginx",
    "apachectl",
    "apache2ctl",
    "caddy",
    "haproxy",
    "ufw",
    "firewall-cmd",
    "nft",
    "ip",
    "ss",
    "df",
    "free",
    "uptime",
    "uname",
    "hostname",
    "id",
    "whoami",
    "ps",
    "ls",
    "stat",
    "docker ps",
    "docker logs",
    "docker inspect",
    "docker restart",
    "podman ps",
    "podman logs",
    "podman inspect",
    "podman restart",
    "kubectl",
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "zypper",
    "pacman",
    "visudo -cf",
)


def _is_within_safe_bin_dirs(real_path: str) -> bool:
    for safe_dir in SAFE_SYSTEM_BIN_DIRS:
        real_safe = os.path.realpath(safe_dir)
        for prefix in (safe_dir, real_safe):
            if os.path.dirname(real_path) == prefix:
                return True
    return False


def resolve_canonical_binary(cmd_token: str) -> Tuple[bool, str, str]:
    """
    Resolve `cmd_token` to a canonical root-owned executable in `SAFE_SYSTEM_BIN_DIRS`.
    Returns `(ok, real_path_or_error_message, canonical_basename)`.
    """
    if not cmd_token or cmd_token.startswith(("./", "../", "~")):
        return False, f"Relative or home binary path '{cmd_token}' is forbidden", ""
    if "/" in cmd_token and not cmd_token.startswith("/"):
        return False, f"Relative binary path '{cmd_token}' is forbidden", ""

    invoked_base = os.path.basename(cmd_token)
    if INTERPRETER_OR_ESCAPE_RE.match(invoked_base):
        return (
            False,
            f"Shell, versioned interpreter, or interactive wrapper '{invoked_base}' is forbidden",
            "",
        )

    resolved = cmd_token if cmd_token.startswith("/") else shutil.which(cmd_token, path=SAFE_SYSTEM_PATH)
    if not resolved:
        return False, f"Binary '{cmd_token}' was not found in system PATH", ""

    real_bin = os.path.realpath(resolved)
    canonical_base = os.path.basename(real_bin)

    if INTERPRETER_OR_ESCAPE_RE.match(canonical_base):
        return (
            False,
            f"Binary '{cmd_token}' resolves to forbidden shell/interpreter '{canonical_base}'",
            "",
        )

    if not _is_within_safe_bin_dirs(real_bin):
        return (
            False,
            f"Binary '{cmd_token}' resolves outside root system directories ({real_bin})",
            "",
        )

    try:
        st = os.stat(real_bin)
    except OSError:
        return False, f"Binary '{real_bin}' could not be stat'd", ""

    if st.st_uid != 0 or (st.st_mode & 0o022) != 0:
        return (
            False,
            f"Binary '{real_bin}' must be owned by root (uid=0) and non-group/world-writable",
            "",
        )

    return True, real_bin, canonical_base


def _matches_prefix(cmd_tokens: Sequence[str], prefix_str: str) -> bool:
    try:
        p_tokens = shlex.split(prefix_str)
    except ValueError:
        p_tokens = prefix_str.strip().split()
    if not p_tokens or len(cmd_tokens) < len(p_tokens):
        return False
    if os.path.basename(p_tokens[0]) != cmd_tokens[0]:
        return False
    return list(cmd_tokens[1 : len(p_tokens)]) == p_tokens[1:]


def validate_allowed_command(
    tokens: List[str],
    allowed_prefixes: Sequence[str],
) -> Tuple[bool, str]:
    """
    Validate a tokenized single command (`tokens`) against canonical binary rules,
    versioned-interpreter guards, and `allowed_prefixes`.
    """
    if not tokens:
        return False, "Empty command"

    ok_bin, bin_or_err, canonical_base = resolve_canonical_binary(tokens[0])
    if not ok_bin:
        return False, bin_or_err

    invoked_base = os.path.basename(tokens[0])
    # Prevent symlink masquerading (e.g. `/usr/local/bin/uptime -> /usr/bin/rm`):
    # evaluate prefix rules strictly against the canonical target binary basename!
    effective_tokens = [canonical_base] + list(tokens[1:])

    # Block interactive editor/shell subcommands on systemctl even if someone configures bare "systemctl"
    if canonical_base == "systemctl":
        for arg in tokens[1:]:
            if arg in ("edit", "shell"):
                return False, f"'systemctl {arg}' spawns an interactive editor/shell and is forbidden"

    if not any(_matches_prefix(effective_tokens, pref) for pref in allowed_prefixes):
        disp = invoked_base if invoked_base == canonical_base else f"{invoked_base} -> {canonical_base}"
        return (
            False,
            f"Command '{disp}' (tokens: {' '.join(effective_tokens[:2])}) is not in allowed_command_prefixes",
        )

    return True, bin_or_err
