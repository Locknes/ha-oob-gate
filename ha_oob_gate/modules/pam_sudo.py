"""
pam_sudo.py - Linux PAM Sudo & Staged Root Batch Gate Modules.

Security Model & Trust Boundaries:
1. Kernel `SO_PEERCRED` Enforcement (`PamSudoModule`):
   `pam_sudo` requests over `/run/ha-sudo/daemon.sock` MUST originate from `uid == 0`
   (the root `pam_exec.so` helper spawned by `/usr/bin/sudo`), and `prepare_ipc_params()`
   reads `/proc/<sudo_pid>/cmdline` and `/proc/<sudo_pid>/cwd` directly from kernel memory.
2. Single-Use Command Pinning (`command_pinned` mode):
   Commands are validated against canonical root-owned system binaries, versioned
   interpreter guards, and `allowed_command_prefixes`. Tickets are HMAC-SHA256 signed
   and consumed atomically under an exclusive `flock`.
3. Human-Approved Root Batch Execution (`SudoBatchModule`):
   Snapshots a multi-line bash script into `/run/ha-sudo/staged/batch_<id>.sh` (`0500 root:root`),
   pins `cwd` + script content via SHA-256, displays the snapshot on the operator's phone,
   and upon approval executes it as `root` (`UID 0`) inside a transient `systemd-run` unit
   with mount-namespace and capability guardrails (`ProtectHome=yes`, `PrivateTmp=yes`,
   inaccessible `/etc/ha-sudo`, `/run/ha-sudo/tickets`, `/dev/shm`, `/run/user`, and
   read-only `/etc/pam.d`, `/etc/sudoers`, `/etc/systemd`, `/etc/ssh`) to prevent
   post-staging TOCTOU and accidental or opportunistic gate self-tampering.
   NOTE: `sudo_batch` executes operator-approved commands as `root` on the host; it is
   not a containment sandbox for untrusted or intentionally malicious `root` code.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..command_policy import DEFAULT_PAM_PINNED_ALLOWED_PREFIXES, validate_allowed_command
from ..sanitize import sanitize_text, sha256_hex
from . import BaseGateModule, CallerInfo, NotificationSpec

MAX_DISPLAY_CMD_LEN = 500
MAX_DISPLAY_SCRIPT_LEN = 600
ALLOWED_BATCH_SHEBANG_RE = re.compile(r"^#!\s*(?:/bin/bash|/usr/bin/bash|/usr/bin/env\s+bash)\s*$")

FORBIDDEN_PINNED_SUDO_FLAGS = frozenset(
    {
        "-i",
        "--login",
        "-s",
        "--shell",
        "-e",
        "--edit",
        "-R",
        "--chroot",
        "-D",
        "--chdir",
        "-E",
        "-l",
        "--list",
        "-v",
        "--validate",
        "-k",
        "-K",
    }
)


def inspect_proc_command(pid: int) -> Tuple[str, str]:
    """Read `/proc/<pid>/cmdline` and `/proc/<pid>/cwd` directly from kernel procfs."""
    cmd_str = ""
    cwd_str = ""
    if pid <= 1:
        return cmd_str, cwd_str
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read(8192)
        parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]
        if parts:
            cmd_str = shlex.join(parts)
    except Exception:
        pass
    try:
        cwd_str = os.readlink(f"/proc/{pid}/cwd")
    except Exception:
        pass
    return cmd_str, cwd_str


def compute_ticket_signature(
    key: bytes,
    username: str,
    scope_mode: str,
    cmd_sha256: str,
    issued_at: float,
    expires_at: float,
    req_id: str,
) -> str:
    """Compute HMAC-SHA256 signature over all security-critical ticket fields."""
    msg = f"{username}:{scope_mode}:{cmd_sha256}:{issued_at}:{expires_at}:{req_id}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def get_user_ticket_path(ticket_dir: str, username: str, cmd_sha256: str = "") -> str:
    safe_user = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", username)
    base_dir = ticket_dir.rstrip("/")
    tickets_subdir = base_dir if os.path.basename(base_dir) == "tickets" else os.path.join(ticket_dir, "tickets")
    if cmd_sha256 and cmd_sha256 != "WINDOW_ANY":
        return os.path.join(tickets_subdir, f"{safe_user}.{cmd_sha256[:16]}.ticket")
    return os.path.join(tickets_subdir, f"{safe_user}.window.ticket")


def _split_cmd_tokens(cmd: str) -> List[str]:
    if not cmd:
        return []
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.strip().split()


def normalize_sudo_command(cmd: str) -> str:
    """
    Normalize command tokens using `shlex` (preserving argument boundaries) and strip
    only the leading `sudo` binary token (and an immediately following `--` separator
    if present). All sudo flags (`-i`, `-s`, `-u`, `-D`, `-R`, `-E`, `-l`, etc.) are
    preserved so flag-only commands and user-switching flags remain cryptographically distinct.
    """
    tokens = _split_cmd_tokens(cmd)
    if not tokens:
        return ""
    if tokens[0] in ("sudo", "/usr/bin/sudo", "/bin/sudo"):
        tokens = tokens[1:]
        if tokens and tokens[0] == "--":
            tokens = tokens[1:]
    return shlex.join(tokens)


def extract_sudo_target_argv(norm_cmd: str) -> Tuple[bool, List[str], str]:
    """
    Parse leading `sudo` options from `norm_cmd` for `command_pinned` validation.
    Rejects interactive/shell/edit/chroot/chdir/env-preserve flags while permitting
    `-n`/`--non-interactive`, `-u <user>`/`--user=<user>`, `-g <group>`/`--group=<group>`,
    and `--`, returning `(ok, target_argv, error_message)`.
    """
    tokens = _split_cmd_tokens(norm_cmd)
    if not tokens:
        return False, [], "Empty sudo command"

    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--":
            idx += 1
            break
        if not tok.startswith("-") or tok == "-":
            break

        if tok in FORBIDDEN_PINNED_SUDO_FLAGS or tok.startswith("--preserve-env"):
            return (
                False,
                [],
                f"Sudo option '{tok}' is forbidden for command_pinned accounts. "
                "Use 'oob-auth sudo-batch' for multi-step root operations.",
            )

        if tok in ("-n", "--non-interactive"):
            idx += 1
            continue

        if tok in ("-u", "--user", "-g", "--group"):
            if idx + 1 >= len(tokens):
                return False, [], f"Missing argument for sudo option '{tok}'"
            idx += 2
            continue

        if tok.startswith(("--user=", "--group=")):
            val = tok.split("=", 1)[1].strip()
            if not val:
                return False, [], f"Missing value for sudo option '{tok}'"
            idx += 1
            continue

        # Combined short flags (e.g. `-ni`, `-nu`, `-Ei`)
        if not tok.startswith("--"):
            short_flags = tok[1:]
            for forbidden_ch in ("i", "s", "e", "R", "D", "E", "l", "v", "k", "K"):
                if forbidden_ch in short_flags:
                    return (
                        False,
                        [],
                        f"Sudo flag '-{forbidden_ch}' in '{tok}' is forbidden for command_pinned accounts.",
                    )
            if short_flags == "n":
                idx += 1
                continue

        return (
            False,
            [],
            f"Unrecognized or disallowed sudo option '{tok}' for command_pinned mode.",
        )

    target_argv = tokens[idx:]
    if not target_argv:
        return False, [], "Missing target command after sudo options"
    return True, target_argv, "ok"


def get_user_scope_mode(username: str, config: Dict[str, Any]) -> str:
    """
    Determine whether `username` uses `deny_pam_sudo` (forces `sudo_batch` only),
    `command_pinned` (single-use exact command match), or `window` (15m window for human admins).
    """
    policies = config.get("user_policies", {})
    mode = policies.get(username, config.get("default_sudo_scope", "command_pinned"))
    if mode not in ("command_pinned", "window", "deny_pam_sudo", "batch_only"):
        return "command_pinned"
    return mode


def verify_and_consume_ticket(
    ticket_dir: str,
    username: str,
    command: str,
    hmac_key: Optional[bytes],
) -> bool:
    """
    Verify an existing HMAC-signed sudo ticket for `username` and `command`.
    Uses an exclusive flock on `<tickets_subdir>/.ticket.lock` so concurrent callers
    cannot race and consume a single-use `command_pinned` ticket more than once.
    """
    if not hmac_key:
        return False

    norm_cmd = normalize_sudo_command(command)
    actual_cmd_sha = sha256_hex(norm_cmd)
    candidates = [
        get_user_ticket_path(ticket_dir, username, actual_cmd_sha),
        get_user_ticket_path(ticket_dir, username, "WINDOW_ANY"),
    ]
    tickets_subdir = os.path.dirname(candidates[0])
    if not os.path.isdir(tickets_subdir):
        return False

    lock_path = os.path.join(tickets_subdir, ".ticket.lock")
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        return False

    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        for ticket_path in candidates:
            if not os.path.exists(ticket_path):
                continue
            try:
                with open(ticket_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                issued_at = float(data.get("issued_at", 0))
                expires_at = float(data.get("expires_at", 0))
                req_id = str(data.get("request_id", ""))
                sig = str(data.get("signature", ""))
                ticket_user = str(data.get("user", ""))
                scope_mode = str(data.get("scope_mode", "command_pinned"))
                expected_cmd_sha = str(data.get("cmd_sha256", ""))

                if ticket_user != username:
                    continue

                now = time.time()
                if now > expires_at or now < issued_at:
                    try:
                        os.remove(ticket_path)
                    except OSError:
                        pass
                    continue

                expected_sig = compute_ticket_signature(
                    hmac_key, username, scope_mode, expected_cmd_sha, issued_at, expires_at, req_id
                )
                if not hmac.compare_digest(sig, expected_sig):
                    try:
                        os.remove(ticket_path)
                    except OSError:
                        pass
                    continue

                if scope_mode == "command_pinned":
                    if not hmac.compare_digest(actual_cmd_sha, expected_cmd_sha):
                        continue
                    try:
                        os.remove(ticket_path)
                    except OSError:
                        return False
                    return True

                return True
            except Exception:
                continue
        return False
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(lock_fd)
        except OSError:
            pass


def create_signed_ticket(
    ticket_dir: str,
    username: str,
    req_id: str,
    command: str,
    scope_mode: str,
    timeout_seconds: int,
    hmac_key: bytes,
) -> str:
    """Create an HMAC-SHA256 signed ticket inside `/run/ha-sudo/tickets` (`0700 root:root`)."""
    now = time.time()
    expires_at = now + timeout_seconds
    norm_cmd = normalize_sudo_command(command)
    cmd_sha256 = sha256_hex(norm_cmd) if scope_mode == "command_pinned" else "WINDOW_ANY"
    ticket_path = get_user_ticket_path(ticket_dir, username, cmd_sha256)
    tickets_subdir = os.path.dirname(ticket_path)
    os.makedirs(tickets_subdir, mode=0o700, exist_ok=True)
    try:
        os.chmod(tickets_subdir, 0o700)
    except OSError:
        pass

    sig = compute_ticket_signature(hmac_key, username, scope_mode, cmd_sha256, now, expires_at, req_id)
    payload = {
        "user": username,
        "scope_mode": scope_mode,
        "cmd_sha256": cmd_sha256,
        "command_norm": norm_cmd[:256],
        "issued_at": now,
        "expires_at": expires_at,
        "request_id": req_id,
        "signature": sig,
    }

    tmp_path = f"{ticket_path}.tmp.{os.getpid()}.{uuid.uuid4().hex[:6]}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    tfd = os.open(tmp_path, flags, 0o600)
    try:
        os.fchmod(tfd, 0o600)
    except OSError:
        pass
    with os.fdopen(tfd, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp_path, ticket_path)
    return ticket_path


class PamSudoModule(BaseGateModule):
    name = "pam_sudo"
    description = "Linux PAM sudo 2FA gate (single-use command-pinned allowlist or human window)"
    default_ttl_seconds = 900
    requires_root_caller = True
    ipc_elevation_alias = "request_elevation"

    def _allowed_prefixes(self, config: Dict[str, Any]) -> Sequence[str]:
        mod_cfg = config.get("module_config", {}).get("pam_sudo", {})
        custom = mod_cfg.get("allowed_command_prefixes") or config.get("pam_allowed_prefixes")
        if isinstance(custom, (list, tuple)) and custom:
            return [str(x) for x in custom if str(x).strip()]
        return DEFAULT_PAM_PINNED_ALLOWED_PREFIXES

    def prepare_ipc_params(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        enriched = dict(params)
        if caller.is_root:
            sudo_pid = int(enriched.get("pid") or caller.pid)
            proc_cmd, proc_cwd = inspect_proc_command(sudo_pid)
            if proc_cmd:
                enriched["command"] = proc_cmd
            if proc_cwd:
                enriched["cwd"] = proc_cwd
        return enriched

    def handle_ipc_action(
        self,
        action: str,
        req: Dict[str, Any],
        caller: CallerInfo,
        config: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if action != "check_ticket":
            return None
        if not caller.is_root:
            return {
                "valid": False,
                "error": f"Security violation: check_ticket requires root PAM helper (got UID {caller.uid})",
            }
        target_user = str(req.get("user") or caller.username)
        cmd = str(req.get("command") or "")
        valid = verify_and_consume_ticket(
            ticket_dir=str(config.get("ticket_dir", "/run/ha-sudo")),
            username=target_user,
            command=cmd,
            hmac_key=config.get("_hmac_key"),
        )
        return {"valid": valid}

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not caller.is_root:
            return (
                False,
                f"Security violation: pam_sudo can only be invoked by root pam_exec helper (caller uid={caller.uid})",
            )
        user = str(params.get("user", "")).strip()
        cmd = str(params.get("command", "")).strip()
        if not user:
            return False, "Missing target user for pam_sudo"
        if not cmd:
            return False, "Missing command for pam_sudo"
        if len(cmd) > MAX_DISPLAY_CMD_LEN:
            return (
                False,
                f"Command exceeds maximum displayable length ({MAX_DISPLAY_CMD_LEN} chars) to prevent blind-tail truncation.",
            )

        norm_cmd = normalize_sudo_command(cmd)
        if not norm_cmd:
            return False, "Missing normalized command for pam_sudo"

        scope_mode = get_user_scope_mode(user, config)
        if scope_mode in ("deny_pam_sudo", "batch_only"):
            return (
                False,
                f"Direct sudo (pam_sudo) is disabled for account '{user}'. "
                "Use 'oob-auth sudo-batch --reason ... --script ...' instead.",
            )

        if scope_mode == "command_pinned":
            ok_argv, target_argv, argv_err = extract_sudo_target_argv(norm_cmd)
            if not ok_argv:
                return False, argv_err
            ok_cmd, cmd_err = validate_allowed_command(target_argv, self._allowed_prefixes(config))
            if not ok_cmd:
                return (
                    False,
                    f"{cmd_err}. Use 'oob-auth sudo-batch' for multi-step root operations.",
                )

        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        user = sanitize_text(params.get("user", "user"), max_len=64)
        cmd = sanitize_text(params.get("command", "unspecified command"), max_len=MAX_DISPLAY_CMD_LEN)
        cwd = sanitize_text(params.get("cwd", "unknown"), max_len=256)
        proc = sanitize_text(params.get("parent_process", "sudo"), max_len=64)
        pid = params.get("pid", "")
        scope_mode = get_user_scope_mode(user, config)
        scope_badge = "Single-Use Exact Command" if scope_mode == "command_pinned" else "15m Window"

        title = f"🚨 Sudo Requested: {hostname} [{verify_code}]"
        message = (
            f"Host: {hostname}\n"
            f"User: {user} ({scope_badge})\n"
            f"Process: {proc}" + (f" (PID: {pid})\n" if pid else "\n") +
            f"Directory: {cwd}\n\n"
            f"Command:\n{cmd}"
        )
        approve_label = f"Approve [{verify_code}]" if scope_mode == "command_pinned" else f"Approve 15m [{verify_code}]"
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=approve_label,
            deny_title="Deny",
            approved_title=f"✅ Sudo Approved: {hostname}",
            approved_message=f"Authorized ({scope_badge}) for {user}: {cmd}",
            denied_title=f"❌ Sudo Denied: {hostname}",
            denied_message=f"Rejected command for {user}: {cmd}",
            timeout_title=f"⏱️ Sudo Timed Out: {hostname}",
            timeout_message=f"Expired with no response: {cmd}",
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
        user = str(params["user"])
        cmd = str(params["command"])
        scope_mode = get_user_scope_mode(user, config)
        ticket_dir = config.get("ticket_dir", "/run/ha-sudo")
        hmac_key = config["_hmac_key"]
        effective_ttl = 60 if scope_mode == "command_pinned" else ttl_seconds

        if scope_mode == "command_pinned" and params.get("synchronous_pam"):
            return {
                "status": "approved",
                "scope_mode": scope_mode,
                "ticket_path": None,
                "ttl_seconds": effective_ttl,
            }

        ticket_path = create_signed_ticket(
            ticket_dir=ticket_dir,
            username=user,
            req_id=req_id,
            command=cmd,
            scope_mode=scope_mode,
            timeout_seconds=effective_ttl,
            hmac_key=hmac_key,
        )
        return {
            "status": "approved",
            "scope_mode": scope_mode,
            "ticket_path": ticket_path,
            "ttl_seconds": effective_ttl,
        }

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        ticket_path = grant_metadata.get("ticket_path")
        if ticket_path and os.path.exists(ticket_path):
            try:
                os.remove(ticket_path)
            except OSError:
                pass
        return True


class SudoBatchModule(BaseGateModule):
    """
    Human-Approved Staged Root Batch Execution (`sudo_batch`).

    Snapshots the submitted bash script into a root-owned `0500` file, pins `cwd` and
    script contents via SHA-256, displays the snapshot on the phone, and executes it as
    `root` inside a transient `systemd-run` unit with mount-namespace guardrails
    (`ProtectHome=yes`, `PrivateTmp=yes`, inaccessible `/etc/ha-sudo`, `/run/ha-sudo/tickets`,
    `/dev/shm`, `/run/user`, and read-only `/etc/pam.d`, `/etc/sudoers`, `/etc/systemd`, `/etc/ssh`).
    """

    name = "sudo_batch"
    description = "Human-approved SHA-256 staged root batch execution with gate self-tamper protection"
    default_ttl_seconds = 300
    requires_root_caller = False
    run_grant_async = True

    def cleanup_pending_request(self, params: Dict[str, Any]) -> None:
        staged = params.get("_staged_path")
        if staged and os.path.exists(staged):
            try:
                os.remove(staged)
            except OSError:
                pass

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        script_content = str(params.get("script_content", "")).strip()
        reason = str(params.get("reason", "")).strip()
        if not script_content:
            return False, "Missing script_content for sudo_batch"
        if len(script_content) > MAX_DISPLAY_SCRIPT_LEN:
            return (
                False,
                f"script_content exceeds maximum displayable size ({MAX_DISPLAY_SCRIPT_LEN} chars) to prevent blind-tail notification truncation; split into smaller verifiable batches",
            )
        if not reason:
            return False, "A human-readable --reason is required for sudo_batch"
        if len(reason) > 200:
            return False, "reason exceeds maximum displayable length (200 chars)"

        # Validate custom shebangs explicitly rather than ignoring `#!` lines under `bash`
        body_content = script_content
        if script_content.startswith("#!"):
            first_line, _, remainder = script_content.partition("\n")
            if not ALLOWED_BATCH_SHEBANG_RE.match(first_line):
                return (
                    False,
                    "Unsupported shebang in sudo_batch script; omit the shebang or use '#!/bin/bash' or '#!/usr/bin/env bash'",
                )
            body_content = remainder.strip()
            if not body_content:
                return False, "sudo_batch script contains only a shebang with no commands"

        raw_cwd = str(params.get("cwd") or "/").strip()
        resolved_cwd = os.path.realpath(raw_cwd) if raw_cwd else "/"
        used_raw_cwd = bool(raw_cwd)
        if not os.path.isdir(resolved_cwd):
            resolved_cwd = "/"
            used_raw_cwd = False
        elif os.geteuid() == 0:
            # Never execute root batches inside a directory owned or writable by an unprivileged user
            try:
                st = os.stat(resolved_cwd)
                if st.st_uid != 0 or (st.st_mode & 0o022) != 0:
                    resolved_cwd = "/"
                    used_raw_cwd = False
            except OSError:
                resolved_cwd = "/"
                used_raw_cwd = False
        # Under root execution (ProtectHome=yes + private tmpfs on /tmp and /var/tmp), fall back cleanly to /
        if resolved_cwd == "/root" or resolved_cwd.startswith(("/root/", "/home/", "/run/user/")):
            resolved_cwd = "/"
            used_raw_cwd = False
        elif os.geteuid() == 0 and resolved_cwd.startswith(("/tmp/", "/var/tmp/")):
            resolved_cwd = "/"
            used_raw_cwd = False
        cwd = resolved_cwd
        params["cwd"] = cwd

        ticket_dir = config.get("ticket_dir", "/run/ha-sudo")
        staged_dir = os.path.join(ticket_dir, "staged")
        os.makedirs(staged_dir, exist_ok=True)
        os.chmod(staged_dir, 0o700)

        stage_id = uuid.uuid4().hex
        staged_path = os.path.join(staged_dir, f"batch_{stage_id}.sh")
        full_script = "#!/bin/bash\nset -euo pipefail\n" + body_content + "\n"

        sflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(staged_path, sflags, 0o500)
        try:
            os.fchmod(fd, 0o500)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(full_script)

        params["_staged_path"] = staged_path
        params["_staged_cwd"] = cwd
        params["_staged_raw_cwd"] = raw_cwd if used_raw_cwd else cwd
        params["_staged_sha256"] = sha256_hex(f"{cwd}\n{full_script}".encode("utf-8"))
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        reason = sanitize_text(params.get("reason", "Batch maintenance"), max_len=200, allow_newlines=False)
        cwd = sanitize_text(params.get("_staged_cwd", params.get("cwd", "/")), max_len=256, allow_newlines=False)
        script_preview = sanitize_text(
            params.get("script_content", ""), max_len=MAX_DISPLAY_SCRIPT_LEN, allow_newlines=True
        )
        sha_short = str(params.get("_staged_sha256", ""))[:12]

        title = f"📜 Root Batch [{hostname}] [{verify_code}]"
        message = (
            f"Host: {hostname}\n"
            f"Caller: {caller.username} (UID {caller.uid})\n"
            f"Directory: {cwd}\n"
            f"Reason: {reason}\n"
            f"Staged SHA-256: {sha_short}...\n\n"
            f"Script to Execute (as root):\n{script_preview}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Run Batch [{verify_code}]",
            deny_title="Deny",
            approved_title=f"✅ Root Batch Approved: {hostname}",
            approved_message=f"Executed staged batch ({sha_short}) for {caller.username}: {reason}",
            denied_title=f"❌ Root Batch Denied: {hostname}",
            denied_message=f"Rejected batch for {caller.username}: {reason}",
            timeout_title=f"⏱️ Root Batch Timed Out: {hostname}",
            timeout_message=f"Expired without approval: {reason}",
            command_summary=reason,
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        staged_path = params.get("_staged_path", "")
        expected_sha = params.get("_staged_sha256", "")
        expected_cwd = params.get("_staged_cwd") or "/"
        raw_cwd = params.get("_staged_raw_cwd") or expected_cwd
        unit_name = f"ha-sudo-batch-{req_id.replace('-', '')[:12]}"

        try:
            if not staged_path or not os.path.exists(staged_path):
                return {"status": "error", "message": "Staged script missing"}

            if not os.path.isdir(raw_cwd):
                return {"status": "error", "message": "Security alert: Staged working directory no longer exists"}

            real_cwd = os.path.realpath(raw_cwd)
            if real_cwd != expected_cwd:
                return {"status": "error", "message": "Security alert: Working directory symlink TOCTOU detected"}

            with open(staged_path, "rb") as f:
                current_bytes = f.read()
            combined_bytes = real_cwd.encode("utf-8") + b"\n" + current_bytes
            if not hmac.compare_digest(sha256_hex(combined_bytes), expected_sha):
                return {"status": "error", "message": "Security alert: Staged script or CWD SHA-256 mismatch"}

            cwd = real_cwd
            max_runtime = max(10, min(int(ttl_seconds), 300))
            clean_env = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/tmp",
                "USER": "root",
                "LOGNAME": "root",
                "LANG": "C.UTF-8",
            }

            if os.geteuid() == 0:
                capsh_bin = shutil.which("capsh", path=clean_env["PATH"])
                unshare_bin = shutil.which("unshare", path=clean_env["PATH"])
                systemd_run_bin = shutil.which("systemd-run", path=clean_env["PATH"])
                if not systemd_run_bin or not os.path.isdir("/run/systemd/system") or not unshare_bin or not capsh_bin:
                    return {
                        "status": "error",
                        "message": "Security error: systemd-run, unshare, and capsh are required for root cgroup, PID, mount, and capability isolation",
                    }
                # Kernel mount-namespace & capability guardrails (fail-closed, zero `|| true` fallbacks):
                # - Inaccessible mode-000 tmpfs masks on gate secrets/tickets and mutable user/IPC dirs
                # - Isolated private tmpfs on /tmp and /var/tmp
                # - Read-only bind mounts on PAM, sudoers, systemd, SSH, and gate code
                ns_guard = (
                    "set -euo pipefail; "
                    "for d in /etc/ha-sudo /run/ha-sudo/tickets /home /dev/shm /run/user; do "
                    "  if [ -d \"$d\" ]; then mount -t tmpfs -o ro,nosuid,nodev,noexec,size=4k,mode=000 tmpfs \"$d\"; fi; "
                    "done; "
                    "for priv_tmp in /tmp /var/tmp; do "
                    "  if [ -d \"$priv_tmp\" ]; then mount -t tmpfs -o nosuid,nodev,size=64m,mode=1777 tmpfs \"$priv_tmp\"; fi; "
                    "done; "
                    "for ro in /usr/local/libexec/ha-sudo /etc/pam.d /etc/sudoers /etc/sudoers.d /etc/systemd /etc/ssh /run/ha-sudo/staged; do "
                    "  if [ -e \"$ro\" ]; then mount --bind \"$ro\" \"$ro\" && mount -o remount,ro,bind \"$ro\"; fi; "
                    "done; "
                    "mount -t proc proc /proc; "
                    f"[ -x {shlex.quote(capsh_bin)} ] || exit 1; "
                    f"exec {shlex.quote(capsh_bin)} "
                    "--drop=cap_sys_admin,cap_sys_ptrace,cap_sys_module,cap_sys_rawio,cap_sys_boot,cap_mac_admin,cap_mac_override,cap_dac_read_search "
                    "-- -c 'exec /bin/bash \"$1\"' _ \"$1\""
                )
                exec_cmd = [
                    systemd_run_bin,
                    "--wait",
                    "--pipe",
                    "--collect",
                    f"--unit={unit_name}",
                    "--quiet",
                    f"--property=RuntimeMaxSec={max_runtime}",
                    "--property=PrivateTmp=yes",
                    "--property=ProtectHome=yes",
                    "--property=ProtectControlGroups=yes",
                    "--property=ProtectKernelModules=yes",
                    "--property=ProtectKernelTunables=yes",
                    "--property=InaccessiblePaths=/etc/ha-sudo /run/ha-sudo/tickets /dev/shm /run/user",
                    "--property=ReadOnlyPaths=/usr/local/libexec/ha-sudo /etc/pam.d /etc/sudoers /etc/sudoers.d /etc/systemd /etc/ssh /run/ha-sudo/staged",
                    "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_BOOT CAP_MAC_ADMIN CAP_MAC_OVERRIDE CAP_DAC_READ_SEARCH",
                    unshare_bin,
                    "--mount",
                    "--propagation",
                    "private",
                    "--pid",
                    "--fork",
                    "/bin/bash",
                    "-c",
                    ns_guard,
                    "ha-sudo-ns-guard",
                    staged_path,
                ]
            else:
                exec_cmd = ["/bin/bash", staged_path]

            try:
                proc = subprocess.run(
                    exec_cmd,
                    cwd=cwd,
                    env=clean_env,
                    capture_output=True,
                    text=True,
                    timeout=max_runtime,
                    start_new_session=True,
                    close_fds=True,
                )
            except subprocess.TimeoutExpired:
                if os.geteuid() == 0 and shutil.which("systemctl"):
                    for suffix in (".service", ".scope"):
                        subprocess.run(
                            ["systemctl", "kill", "--signal=SIGKILL", f"{unit_name}{suffix}"],
                            check=False,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                return {"status": "error", "message": f"Batch execution timed out after {max_runtime}s"}

            return {
                "status": "approved",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[-16384:],
                "stderr": proc.stderr[-16384:],
                "staged_sha256": expected_sha,
            }
        finally:
            if os.geteuid() == 0 and shutil.which("systemctl"):
                for suffix in (".service", ".scope"):
                    subprocess.run(
                        ["systemctl", "kill", "--signal=SIGKILL", f"{unit_name}{suffix}"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
            self.cleanup_pending_request(params)

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        return True
