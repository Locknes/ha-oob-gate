"""
ssh_gate.py - OpenSSH ForceCommand Gate with Command-Prefix Allowlist & Process-Group Cleanup.

Configured in `/etc/ssh/sshd_config.d/ha-oob-gate.conf`:
    Match Group oob-agents
        ForceCommand /usr/local/bin/ha-oob-gate --ssh-enforce
        AllowTcpForwarding no
        X11Forwarding no
        PermitTunnel no

Security Properties:
1. Captures `SSH_ORIGINAL_COMMAND` before spawning any shell.
2. Canonicalizes `tokens[0]` via `shutil.which()` + `os.path.realpath()`, requiring a root-owned
   executable inside system binary directories, blocking versioned interpreters/shells, and
   enforcing `allowed_command_prefixes`.
3. Wraps approved execution inside a named `systemd-run --user --scope` unit (or process-group
   isolated `timeout`) backed by `/proc`-scanned process-group & session termination (`SIGTERM` ->
   `SIGKILL`) in `revoke()`, even when the original process-group leader has exited.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import time
from typing import Any, Dict, List, Sequence, Set, Tuple

from ..command_policy import DEFAULT_SSH_ALLOWED_PREFIXES, validate_allowed_command
from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec

MAX_SSH_CMD_LEN = 500
FORBIDDEN_SSH_METACHARS = frozenset(";&|`$()<>\n\r*?[]{}~\\")
PROC_ROOT = "/proc"


def _pid_uids(pid: int, proc_root: str = PROC_ROOT) -> Set[int]:
    """Return `{real_uid, effective_uid, saved_uid}` for `pid` from `/proc/<pid>/status`, or empty set."""
    if pid <= 1:
        return set()
    try:
        with open(os.path.join(proc_root, str(pid), "status"), "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 4:
                        return {int(parts[1]), int(parts[2]), int(parts[3])}
    except Exception:
        pass
    return set()


def _pid_owned_by_uid(pid: int, expected_uid: int, proc_root: str = PROC_ROOT) -> bool:
    """Return True if `pid` exists and its real, effective, and saved UIDs all equal `expected_uid` (> 0)."""
    if pid <= 1 or expected_uid <= 0:
        return False
    uids = _pid_uids(pid, proc_root=proc_root)
    return uids == {expected_uid}


def _scan_verified_group_targets(
    target_groups: Sequence[int],
    expected_uid: int,
    proc_root: str = PROC_ROOT,
) -> Tuple[List[int], List[int]]:
    """
    Scan `/proc/[0-9]*/stat` + `status` to find live processes belonging to any PGID or SID in
    `target_groups`, even if the original process-group leader (`timeout`) has already exited.

    Returns `(verified_pgids, verified_member_pids)` where a PGID is included ONLY if at least
    one live process currently resides in it AND every live process in that PGID belongs strictly
    to `expected_uid`.
    """
    valid_groups = {g for g in target_groups if g > 1}
    if not valid_groups or expected_uid <= 0 or not os.path.isdir(proc_root):
        return [], []

    pgrp_members: Dict[int, List[int]] = {}
    pgrp_tainted: Set[int] = set()
    verified_pids: List[int] = []

    try:
        entries = os.listdir(proc_root)
    except OSError:
        return [], []

    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid <= 1:
            continue
        stat_path = os.path.join(proc_root, entry, "stat")
        try:
            with open(stat_path, "r", encoding="utf-8", errors="replace") as sf:
                stat_raw = sf.read()
            # `/proc/<pid>/stat` wraps `comm` in `(...)`; `rpartition(")")` safely skips any `)` inside `comm`
            _, sep, after_comm = stat_raw.rpartition(")")
            if not sep:
                continue
            fields = after_comm.split()
            # fields[0]=state, fields[1]=ppid, fields[2]=pgrp, fields[3]=session
            if len(fields) < 4:
                continue
            pgrp = int(fields[2])
            sid = int(fields[3])
        except Exception:
            continue

        if pgrp not in valid_groups and sid not in valid_groups:
            continue

        uids = _pid_uids(pid, proc_root=proc_root)
        if not uids:
            continue

        owned = uids == {expected_uid}
        if pgrp in valid_groups:
            if owned:
                pgrp_members.setdefault(pgrp, []).append(pid)
            else:
                pgrp_tainted.add(pgrp)

        if owned:
            verified_pids.append(pid)

    verified_pgids = [
        grp for grp, members in pgrp_members.items() if members and grp not in pgrp_tainted
    ]
    return verified_pgids, verified_pids


class SshGateModule(BaseGateModule):
    name = "ssh_gate"
    description = "OpenSSH ForceCommand gate with command-prefix allowlist and process-group cleanup"
    default_ttl_seconds = 300
    requires_root_caller = False

    def _allowed_prefixes(self, config: Dict[str, Any]) -> Sequence[str]:
        mod_cfg = config.get("module_config", {}).get("ssh_gate", {})
        custom = mod_cfg.get("allowed_command_prefixes") or config.get("ssh_allowed_prefixes")
        if isinstance(custom, (list, tuple)) and custom:
            return [str(x) for x in custom if str(x).strip()]
        return DEFAULT_SSH_ALLOWED_PREFIXES

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        cmd = str(params.get("command", "")).strip()
        if not cmd:
            return (
                False,
                "Interactive SSH shell allocation (empty SSH_ORIGINAL_COMMAND) is forbidden. "
                "Specify an explicit non-interactive command.",
            )
        if len(cmd) > MAX_SSH_CMD_LEN:
            return (
                False,
                f"SSH command exceeds maximum displayable length ({MAX_SSH_CMD_LEN} chars) to prevent truncation.",
            )

        bad_chars = [ch for ch in cmd if ch in FORBIDDEN_SSH_METACHARS]
        if bad_chars:
            return (
                False,
                "SSH command contains shell metacharacters, wildcards, or chaining operators; "
                "run one single command per SSH request.",
            )

        try:
            tokens = shlex.split(cmd)
        except ValueError:
            return False, "Malformed quoting in SSH command"

        if not tokens:
            return False, "Empty SSH command"

        ok_cmd, bin_or_err = validate_allowed_command(tokens, self._allowed_prefixes(config))
        if not ok_cmd:
            return False, f"SSH policy rejected command: {bin_or_err}"

        params["_resolved_bin"] = bin_or_err
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        cmd = sanitize_text(params.get("command", ""), max_len=MAX_SSH_CMD_LEN)
        ssh_client = sanitize_text(params.get("ssh_client", "unknown"), max_len=128)
        ttl = max(60, min(int(params.get("ttl_seconds") or self.default_ttl_seconds), self.default_ttl_seconds))

        title = f"🌐 SSH Command [{hostname}] [{verify_code}]"
        message = (
            f"Target Host: {hostname}\n"
            f"SSH User: {caller.username} (UID {caller.uid})\n"
            f"Origin IP: {ssh_client}\n"
            f"Max Runtime: {ttl}s\n\n"
            f"SSH Command:\n{cmd}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Allow SSH [{verify_code}]",
            deny_title="Block SSH",
            approved_title=f"✅ SSH Approved: {hostname}",
            approved_message=f"Permitted SSH command ({ttl}s cap) for {caller.username}: {cmd}",
            denied_title=f"❌ SSH Blocked: {hostname}",
            denied_message=f"Blocked SSH command from {ssh_client}: {cmd}",
            timeout_title=f"⏱️ SSH Timed Out: {hostname}",
            timeout_message=f"Expired without approval: {cmd}",
            command_summary=cmd,
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        max_runtime = max(30, min(int(ttl_seconds), 600))
        unit_name = f"ha-oob-ssh-{req_id.replace('-', '')[:12]}"
        verified_pid = 0
        pgid = 0
        sid = 0
        if caller.pid > 1 and _pid_owned_by_uid(caller.pid, caller.uid):
            verified_pid = caller.pid
            try:
                pgid = os.getpgid(caller.pid)
            except OSError:
                pgid = caller.pid
            try:
                sid = os.getsid(caller.pid)
            except OSError:
                sid = pgid
        return {
            "status": "approved",
            "max_runtime_seconds": max_runtime,
            "unit_name": unit_name,
            "lease_metadata": {
                "pid": verified_pid,
                "pgid": pgid,
                "sid": sid,
                "uid": caller.uid,
                "unit_name": f"{unit_name}.scope",
            },
        }

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        """
        Terminate any live processes in the SSH session's process group / session ID
        (even if the initial PGID leader has already exited) after verifying UID ownership.
        """
        lease_metadata = grant_metadata.get("lease_metadata", grant_metadata)
        expected_uid = int(lease_metadata.get("uid") or 0)
        if expected_uid <= 0:
            return False
        pgid = int(lease_metadata.get("pgid") or 0)
        sid = int(lease_metadata.get("sid") or 0)
        pid = int(lease_metadata.get("pid") or 0)
        unit_scope = str(lease_metadata.get("unit_name") or "").strip()

        killed = False

        # 1. Best-effort user scope termination if running under systemd user manager
        if unit_scope and os.geteuid() == 0 and shutil.which("systemctl"):
            proc = subprocess.run(
                [
                    "systemctl",
                    "--user",
                    f"--machine={expected_uid}@",
                    "kill",
                    "--signal=SIGKILL",
                    unit_scope,
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if proc.returncode == 0:
                killed = True

        # 2. Scan `/proc` for all live members in `(pgid, sid, pid)` verified against `expected_uid`
        verified_pgrps, verified_pids = _scan_verified_group_targets((pgid, sid, pid), expected_uid)
        if pid > 1 and pid not in verified_pids and _pid_owned_by_uid(pid, expected_uid):
            verified_pids.append(pid)

        signaled_term = False
        for grp_id in verified_pgrps:
            try:
                os.killpg(grp_id, signal.SIGTERM)
                signaled_term = True
            except OSError:
                pass
        for member_pid in verified_pids:
            try:
                os.kill(member_pid, signal.SIGTERM)
                signaled_term = True
            except OSError:
                pass

        if signaled_term:
            killed = True
            deadline = time.monotonic() + 0.1
            while time.monotonic() < deadline:
                rem_pgrps, rem_pids = _scan_verified_group_targets((pgid, sid, pid), expected_uid)
                if not rem_pgrps and not rem_pids:
                    return True
                time.sleep(0.01)

        rem_pgrps, rem_pids = _scan_verified_group_targets((pgid, sid, pid), expected_uid)
        for grp_id in set(verified_pgrps) | set(rem_pgrps):
            try:
                os.killpg(grp_id, signal.SIGKILL)
                killed = True
            except OSError:
                pass
        for member_pid in set(verified_pids) | set(rem_pids):
            if _pid_owned_by_uid(member_pid, expected_uid):
                try:
                    os.kill(member_pid, signal.SIGKILL)
                    killed = True
                except OSError:
                    pass

        return killed
