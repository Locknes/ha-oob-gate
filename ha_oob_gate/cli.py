#!/usr/bin/env python3
"""
cli.py - Unified Client, PAM Helper, OpenSSH ForceCommand Helper, and Daemon Entrypoint
for `ha_oob_gate`.

Supports:
1. Daemon & PAM Modes (backwards-compatible with `ha_sudo_gate.py`):
   - `ha_sudo_gate.py --daemon`
   - `ha_sudo_gate.py --pam --user <user> <cmd...>`
   - `ha_sudo_gate.py --ssh-enforce`
   - `ha_sudo_gate.py --test`
2. Modular CLI Subcommands (`oob-auth` / `request-jit.py`):
   - `oob-auth sudo-batch --reason "..." --script "systemctl restart nginx && systemctl status nginx"`
   - `oob-auth k8s-token --role jit-workload-operator --namespaces default --reason "..."`
   - `oob-auth github-token --repo owner/repo --permission write --reason "..."`
   - `oob-auth ha-api --lease --scope read --path /api/states --reason "..."`
   - `oob-auth secret-checkout --key external_api_key --reason "..."`
   - `oob-auth confirm --summary "Delete legacy Helm release" --reason "..."`
   - `oob-auth revoke`
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .daemon import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_TLS_CERT_PATH,
    get_or_create_hmac_key,
    load_config,
    run_daemon,
    trigger_ha_webhook,
)
from .ipc import FrameTooLargeError, recv_json_frame, send_json_frame
from .modules import discover_modules
from .modules.pam_sudo import inspect_proc_command, verify_and_consume_ticket

EXIT_HA_UNREACHABLE = 75
DEFAULT_K8S_BROKER_URL = os.environ.get("JIT_BROKER_URL", "https://oob-gate.example.com:8443")


def _get_user_runtime_dir(create: bool = False) -> str:
    """
    Resolve a user-private (`0700`) runtime directory (never world-writable `/dev/shm` or `/tmp`).
    When `create=False`, returns the best candidate path without touching the filesystem so
    importing `ha_oob_gate.cli` has zero side effects.
    """
    uid = os.getuid()
    candidates = []
    if uid == 0:
        candidates.append("/run/ha-sudo/staged")
        candidates.append("/run/ha-sudo")
    candidates.extend(
        [
            os.environ.get("XDG_RUNTIME_DIR", ""),
            f"/run/user/{uid}",
            os.path.expanduser("~/.cache/ha-sudo"),
        ]
    )

    if not create:
        for path in candidates:
            if not path:
                continue
            try:
                if os.path.isdir(path) and os.lstat(path).st_uid == uid:
                    return path
            except OSError:
                continue
        return os.path.expanduser("~/.cache/ha-sudo")

    for path in candidates:
        if not path:
            continue
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
            st = os.lstat(path)
            if st.st_uid == uid:
                if path != "/run/ha-sudo":
                    try:
                        os.chmod(path, 0o700)
                    except OSError:
                        pass
                return path
        except OSError:
            continue
    return f"/run/user/{uid}"


def _runtime_file_path(filename: str, create_dir: bool = False) -> str:
    return os.path.join(_get_user_runtime_dir(create=create_dir), filename)


def _build_broker_ssl_context(cacert_path: Optional[str] = None) -> Optional[ssl.SSLContext]:
    """Build a TLSv1.2+ SSLContext pinned to `/etc/ha-sudo/tls.crt` (when present) for HTTPS broker calls."""
    ca = cacert_path or os.environ.get("HA_SUDO_CACERT", DEFAULT_TLS_CERT_PATH)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    if ca and os.path.isfile(ca) and os.access(ca, os.R_OK):
        ctx.load_verify_locations(cafile=ca)
    else:
        ctx.load_default_certs()
    return ctx


def send_unix_socket_request(socket_path: str, payload: Dict[str, Any], timeout: float = 930.0) -> Dict[str, Any]:
    """
    Send a newline-delimited JSON request frame over `/run/ha-sudo/daemon.sock` and read one response frame.
    Keeps the client write half open (does NOT call `shutdown(SHUT_WR)`) so the daemon can detect true
    client disconnects (`Ctrl+C` / EOF) via `MSG_PEEK | MSG_DONTWAIT`.
    """
    if not os.path.exists(socket_path):
        raise FileNotFoundError(
            f"ha-oob-gate daemon socket not found at {socket_path}. "
            "Ensure ha-sudo-gate.service is running."
        )
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(socket_path)
        send_json_frame(s, payload)
        resp = recv_json_frame(s, max_bytes=1024 * 1024)
        if resp is None:
            return {"status": "error", "code": 502, "message": "Empty response from daemon"}
        return resp
    except FrameTooLargeError as e:
        return {"status": "error", "code": 502, "message": str(e)}
    finally:
        s.close()


def run_pam_gate(config: Dict[str, Any], username: str, command: str) -> None:
    """
    Invoked by `pam_exec.so` during `sudo` execution (`euid == 0`).
    Inspects `/proc/<sudo_pid>/cmdline` directly from kernel memory, checks for an
    existing command-pinned or window ticket, and otherwise requests phone approval
    via `/run/ha-sudo/daemon.sock`.

    Never starts an in-process HTTP server inside PAM: if the daemon socket or
    Home Assistant webhook is unreachable, exits with `EXIT_HA_UNREACHABLE` (`75`)
    so `pam_ha_sudo.sh` can offer physical-console break-glass recovery (`ha-breakglass`).
    """
    hmac_key = get_or_create_hmac_key(config.get("hmac_key_path", "/etc/ha-sudo/hmac.key"))
    ticket_dir = config.get("ticket_dir", "/run/ha-sudo")
    socket_path = config.get("socket_path", "/run/ha-sudo/daemon.sock")

    ppid = os.getppid()
    proc_cmd, proc_cwd = inspect_proc_command(ppid)
    if proc_cmd:
        command = proc_cmd
    cwd = proc_cwd or os.getcwd()

    # Fast path 1: Verify and (if command_pinned) consume local HMAC ticket directly as root
    if verify_and_consume_ticket(ticket_dir, username, command, hmac_key):
        sys.exit(0)

    # Fast path 2: Ask the running root daemon over Unix socket
    parent_comm = "sudo"
    try:
        with open(f"/proc/{ppid}/comm", "r", encoding="utf-8") as f:
            parent_comm = f.read().strip()
    except Exception:
        pass

    req_payload = {
        "action": "request_elevation",
        "module": "pam_sudo",
        "user": username,
        "command": command,
        "cwd": cwd,
        "pid": ppid,
        "parent_process": parent_comm,
        "synchronous_pam": True,
    }

    hostname = socket.gethostname()
    sys.stderr.write(f"\n[ha-oob-gate] Sudo elevation requested on '{hostname}'\n")
    sys.stderr.write(f"[ha-oob-gate] User          : {username}\n")
    sys.stderr.write(f"[ha-oob-gate] Command       : {command}\n")
    sys.stderr.write("[ha-oob-gate] 📱 Actionable notification sent to phone. Waiting for approval...\n")
    sys.stderr.flush()

    try:
        resp = send_unix_socket_request(socket_path, req_payload, timeout=float(config["timeout_seconds"]) + 15)
    except KeyboardInterrupt:
        sys.stderr.write("\n[ha-oob-gate] Elevation request cancelled by user.\n")
        sys.exit(1)
    except (
        FileNotFoundError,
        ConnectionRefusedError,
        TimeoutError,
        socket.timeout,
        OSError,
        RuntimeError,
        ValueError,
    ) as sock_err:
        sys.stderr.write(f"[ha-oob-gate] ⚠️ Daemon socket unavailable ({sock_err}).\n")
        sys.exit(EXIT_HA_UNREACHABLE)

    if not isinstance(resp, dict) or not resp.get("status"):
        sys.stderr.write("[ha-oob-gate] ⚠️ Malformed response from daemon.\n")
        sys.exit(EXIT_HA_UNREACHABLE)

    status = resp.get("status")
    if status == "approved":
        if resp.get("ticket_path"):
            verify_and_consume_ticket(ticket_dir, username, command, hmac_key)
        sys.stderr.write("[ha-oob-gate] ✅ Approved via phone!\n\n")
        sys.exit(0)
    if status == "denied":
        sys.stderr.write("[ha-oob-gate] ❌ Sudo elevation explicitly denied via phone.\n\n")
        sys.exit(1)
    if status == "timeout":
        sys.stderr.write("[ha-oob-gate] ❌ Sudo elevation timed out without phone approval.\n\n")
        sys.exit(1)

    msg = str(resp.get("message", "Unknown error"))
    sys.stderr.write(f"[ha-oob-gate] ❌ Error during elevation: {msg}\n\n")
    if resp.get("code") in (502, 503, 504) or "Failed to reach Home Assistant webhook" in msg:
        sys.exit(EXIT_HA_UNREACHABLE)
    sys.exit(1)


def _can_run_systemd_user_scope() -> bool:
    """Return True if `systemd-run --user --scope` is functional for the current session."""
    if not shutil.which("systemd-run"):
        return False
    uid = os.getuid()
    xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS") and not os.path.exists(os.path.join(xdg, "bus")):
        return False
    try:
        probe = subprocess.run(
            ["systemd-run", "--user", "--scope", "--quiet", "--", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return probe.returncode == 0
    except Exception:
        return False


def run_ssh_enforce(config: Dict[str, Any]) -> None:
    """
    OpenSSH `ForceCommand` handler (`--ssh-enforce`).
    Captures `SSH_ORIGINAL_COMMAND`, prompts Home Assistant via `ssh_gate`,
    disables interactive pagers (`PAGER=cat`, `SYSTEMD_PAGER=cat`, `GIT_PAGER=cat`),
    and enforces hard runtime expiration via `systemd-run --user --scope --unit=<unit_name>`
    (or `timeout --signal=TERM --kill-after=5s` in its own process group) backed by
    root-enforced `/proc` group/session scanning in `SshGateModule.revoke()`.
    """
    ssh_cmd = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
    if not ssh_cmd:
        sys.stderr.write(
            "[ha-oob-gate] ❌ Security error: interactive SSH shells without an explicit "
            "SSH_ORIGINAL_COMMAND are forbidden.\n"
        )
        sys.exit(1)
    ssh_client = os.environ.get("SSH_CLIENT", os.environ.get("SSH_CONNECTION", "unknown")).split()[0]
    socket_path = config.get("socket_path", "/run/ha-sudo/daemon.sock")

    sys.stderr.write(f"[ha-oob-gate] 🔑 SSH command approval requested: {ssh_cmd}\n")
    sys.stderr.write("[ha-oob-gate] 📱 Waiting for mobile approval...\n")
    sys.stderr.flush()

    resp = send_unix_socket_request(
        socket_path,
        {
            "action": "module_request",
            "module": "ssh_gate",
            "params": {"command": ssh_cmd, "client_ip": ssh_client, "pid": os.getpid()},
        },
        timeout=float(config["timeout_seconds"]) + 15,
    )
    if resp.get("status") != "approved":
        sys.stderr.write(f"[ha-oob-gate] ❌ SSH access {resp.get('status', 'denied')}: {resp.get('message', '')}\n")
        sys.exit(1)

    max_runtime = int(resp.get("max_runtime_seconds", config.get("timeout_seconds", 900)))
    unit_name = str(resp.get("unit_name") or f"ha-oob-ssh-{os.getpid()}")
    sys.stderr.write(f"[ha-oob-gate] ✅ Approved! Executing (max runtime {max_runtime}s)...\n")
    sys.stderr.flush()

    try:
        cmd_argv = shlex.split(ssh_cmd)
    except ValueError:
        sys.stderr.write("[ha-oob-gate] ❌ Malformed SSH command.\n")
        sys.exit(1)
    if not cmd_argv:
        sys.exit(1)

    os.environ["PAGER"] = "cat"
    os.environ["SYSTEMD_PAGER"] = "cat"
    os.environ["GIT_PAGER"] = "cat"

    if os.geteuid() != 0 and _can_run_systemd_user_scope():
        os.execvp(
            "systemd-run",
            [
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                f"--unit={unit_name}",
                f"--property=RuntimeMaxSec={max_runtime}",
                "--",
                *cmd_argv,
            ],
        )
    elif os.geteuid() == 0 and shutil.which("systemd-run"):
        os.execvp(
            "systemd-run",
            [
                "systemd-run",
                "--scope",
                "--quiet",
                f"--unit={unit_name}",
                f"--property=RuntimeMaxSec={max_runtime}",
                "--",
                *cmd_argv,
            ],
        )
    elif shutil.which("timeout"):
        os.execvp(
            "timeout",
            [
                "timeout",
                "--signal=TERM",
                "--kill-after=5s",
                f"{max_runtime}s",
                "--",
                *cmd_argv,
            ],
        )
    else:
        sys.stderr.write("[ha-oob-gate] ❌ Security error: timeout/systemd-run unavailable for runtime enforcement.\n")
        sys.exit(1)


def run_test(config: Dict[str, Any]) -> None:
    """Validate system configuration, discovered modules, and Home Assistant connectivity."""
    mods = discover_modules(config.get("enabled_modules"))
    print("=== ha-oob-gate Security & Module Diagnostic ===")
    print(f"UID                : {os.geteuid()}")
    print(f"Config Path        : {DEFAULT_CONFIG_PATH}")
    print(f"HA URL             : {config.get('ha_url')}")
    print(f"HA Trusted IP      : {config.get('ha_trusted_ip')}")
    wh_id = str(config.get("webhook_id", ""))
    print(f"Webhook ID         : {(wh_id[:8] + '...[redacted]') if wh_id else '(not set)'}")
    print(f"Callback Host:Port : {config.get('callback_host')}:{config.get('callback_port')}")
    print(f"Socket Path        : {config.get('socket_path')} (Exists: {os.path.exists(config.get('socket_path', ''))})")
    print(f"Discovered Modules : {', '.join(sorted(mods.keys()))}")
    print("\nTesting connectivity to Home Assistant webhook endpoint...")
    ok = trigger_ha_webhook(
        config,
        {
            "test": True,
            "hostname": socket.gethostname(),
        },
    )
    print(f"HA Reachability    : {'OK (Responded 200/201)' if ok else 'FAILED'}")
    print("================================================")


def extract_kubeconfig_token() -> str:
    """Extract current Kubernetes bearer token via `kubectl config view --raw --minify`."""
    raw = subprocess.check_output(
        ["kubectl", "config", "view", "--raw", "--minify", "-o", "jsonpath={.users[0].user.token}"],
        text=True,
    ).strip()
    if not raw:
        raise RuntimeError("Could not find Bearer token in current kubeconfig.")
    return raw


def cmd_sudo_batch(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            script_content = f.read()
    else:
        script_content = args.script or ""

    if not script_content.strip():
        sys.stderr.write("Error: Provide either --script or --file with non-empty script commands.\n")
        sys.exit(1)

    sys.stderr.write("[oob-auth] Staging immutable script snapshot and dispatching mobile notification...\n")
    sys.stderr.flush()
    resp = send_unix_socket_request(
        config["socket_path"],
        {
            "action": "module_request",
            "module": "sudo_batch",
            "params": {
                "script_content": script_content,
                "reason": args.reason,
                "cwd": os.getcwd(),
            },
        },
        timeout=float(config["timeout_seconds"]) + 30,
    )
    if resp.get("status") != "approved":
        sys.stderr.write(f"[oob-auth] ❌ Batch request {resp.get('status')}: {resp.get('message', '')}\n")
        sys.exit(1)

    if resp.get("stdout"):
        sys.stdout.write(resp["stdout"])
    if resp.get("stderr"):
        sys.stderr.write(resp["stderr"])
    sys.exit(int(resp.get("exit_code", 0)))


def _save_k8s_lease(
    req_id: str,
    caller_nonce: str,
    pdata: Dict[str, Any],
    broker_url: str = "",
    transport: str = "unix",
    cacert: str = "",
    raw_token: bool = False,
) -> None:
    token_out_path = _runtime_file_path(".jit-k8s-token", create_dir=True)
    lease_out_path = _runtime_file_path(".jit-k8s-lease.json", create_dir=True)
    oflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(token_out_path, oflags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        pass
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(pdata["token"])

    lfd = os.open(lease_out_path, oflags, 0o600)
    try:
        os.fchmod(lfd, 0o600)
    except OSError:
        pass
    with os.fdopen(lfd, "w", encoding="utf-8") as f:
        json.dump(
            {
                "request_id": req_id,
                "caller_nonce": caller_nonce,
                "broker_url": broker_url,
                "cacert": cacert,
                "transport": transport,
                "expires_at": pdata.get("expires_at"),
                "service_account": pdata.get("service_account"),
            },
            f,
        )
    sys.stderr.write(f"[oob-auth] ✅ Approved! Temporary JWT saved to {token_out_path} (0600)\n")
    sys.stderr.write(f"[oob-auth]    ServiceAcct: {pdata.get('service_account')}\n")
    sys.stderr.write(f"[oob-auth]    Expires at : {pdata.get('expires_at')}\n")
    sys.stderr.write(f"[oob-auth]    Usage      : kubectl --token=\"$(cat {token_out_path})\" ...\n")
    sys.stderr.write("[oob-auth]    Revoke     : oob-auth revoke\n")
    sys.stderr.flush()

    if raw_token:
        sys.stdout.write(f"{pdata['token']}\n")
    else:
        sys.stdout.write(f"export K8S_JIT_TOKEN={shlex.quote(pdata['token'])}\n")
    sys.stdout.flush()


def cmd_k8s_token(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    if not args.broker_url and os.path.exists(config["socket_path"]):
        sys.stderr.write(f"[oob-auth] 📱 Requesting mobile approval for K8s role '{args.role}' in {args.namespaces}...\n")
        sys.stderr.flush()
        resp = send_unix_socket_request(
            config["socket_path"],
            {
                "action": "module_request",
                "module": "k8s_token",
                "params": {
                    "role": args.role,
                    "namespaces": args.namespaces,
                    "reason": args.reason,
                },
            },
            timeout=float(args.timeout or config.get("timeout_seconds", 900)) + 15,
        )
        if resp.get("status") == "approved" and resp.get("token"):
            _save_k8s_lease(
                req_id=resp.get("request_id", ""),
                caller_nonce=resp.get("caller_nonce", ""),
                pdata=resp,
                transport="unix",
                raw_token=bool(getattr(args, "raw", False)),
            )
            return
        sys.stderr.write(f"[oob-auth] ❌ Request {resp.get('status', 'denied')}: {resp.get('message', '')}\n")
        sys.exit(1)

    sa_token = extract_kubeconfig_token()
    broker_url = (args.broker_url or DEFAULT_K8S_BROKER_URL).rstrip("/")
    cacert_path = getattr(args, "cacert", "") or config.get("tls_cert_path", DEFAULT_TLS_CERT_PATH)
    ssl_ctx = _build_broker_ssl_context(cacert_path) if broker_url.startswith("https://") else None

    req_body = json.dumps(
        {
            "module": "k8s_token",
            "params": {
                "role": args.role,
                "namespaces": args.namespaces,
                "reason": args.reason,
            },
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{broker_url}/v1/request",
        data=req_body,
        headers={
            "Authorization": f"Bearer {sa_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=ssl_ctx) as resp:
            init_data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"[oob-auth] Broker error ({e.code}): {e.read().decode('utf-8', errors='replace')}\n")
        sys.exit(1)

    req_id = init_data["request_id"]
    caller_nonce = init_data["caller_nonce"]
    verify_code = init_data["verify_code"]
    sys.stderr.write(f"[oob-auth] 📱 Approval requested! Verification Code: [{verify_code}] (Request ID: {req_id})\n")
    sys.stderr.write(f"[oob-auth]    Role: {args.role} | Namespaces: {', '.join(args.namespaces)}\n")
    sys.stderr.write("[oob-auth]    Waiting for mobile approval via Home Assistant...\n")
    sys.stderr.flush()

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        poll_url = f"{broker_url}/v1/requests/{req_id}?caller_nonce={caller_nonce}&wait=20"
        poll_req = urllib.request.Request(poll_url, method="GET")
        with urllib.request.urlopen(poll_req, timeout=25, context=ssl_ctx) as presp:
            pdata = json.loads(presp.read().decode("utf-8"))

        status = pdata.get("status")
        if status in ("pending", "processing"):
            continue
        if status == "approved":
            _save_k8s_lease(
                req_id,
                caller_nonce,
                pdata,
                broker_url=broker_url,
                transport="http",
                cacert=cacert_path,
                raw_token=bool(getattr(args, "raw", False)),
            )
            return
        sys.stderr.write(f"[oob-auth] ❌ Request {status}: {pdata.get('message', '')}\n")
        sys.exit(1)

    sys.stderr.write("[oob-auth] ❌ Timed out waiting for approval.\n")
    sys.exit(1)


def cmd_confirm(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    sys.stderr.write(f"[oob-auth] 📱 Requesting mobile confirmation for: {args.summary}\n")
    sys.stderr.flush()
    resp = send_unix_socket_request(
        config["socket_path"],
        {
            "action": "module_request",
            "module": "generic_confirm",
            "params": {"summary": args.summary, "reason": args.reason},
        },
        timeout=float(config["timeout_seconds"]) + 15,
    )
    if resp.get("status") == "approved":
        sig = str(resp.get("receipt_signature", ""))
        sys.stderr.write(f"[oob-auth] ✅ Confirmed! Receipt signature: {sig}\n")
        sys.stdout.write(f"{sig}\n")
        sys.exit(0)
    sys.stderr.write(f"[oob-auth] ❌ Confirmation {resp.get('status', 'denied')}.\n")
    sys.exit(1)


def cmd_secret_checkout(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    sys.stderr.write(f"[oob-auth] 📱 Requesting secret checkout for key: {args.key}\n")
    sys.stderr.flush()
    resp = send_unix_socket_request(
        config["socket_path"],
        {
            "action": "module_request",
            "module": "secret_checkout",
            "params": {"key": args.key, "reason": args.reason},
        },
        timeout=float(config["timeout_seconds"]) + 15,
    )
    if resp.get("status") == "approved":
        if getattr(args, "stdout", False):
            sys.stdout.write(f"{resp['value']}\n")
        else:
            safe_key = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in args.key)
            secret_path = _runtime_file_path(f".jit-secret-{safe_key}", create_dir=True)
            sflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            sfd = os.open(secret_path, sflags, 0o600)
            try:
                os.fchmod(sfd, 0o600)
            except OSError:
                pass
            with os.fdopen(sfd, "w", encoding="utf-8") as f:
                f.write(resp["value"])
            sys.stderr.write(f"[oob-auth] ✅ Secret checked out to {secret_path} (mode 0600)\n")
            sys.stdout.write(f"{secret_path}\n")
        sys.exit(0)
    sys.stderr.write(f"[oob-auth] ❌ Secret checkout {resp.get('status', 'denied')}: {resp.get('message', '')}\n")
    sys.exit(1)


def cmd_github_token(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    sys.stderr.write(f"[oob-auth] 🐙 Requesting GitHub {args.permission.upper()} token for {args.repo}...\n")
    sys.stderr.flush()
    resp = send_unix_socket_request(
        config["socket_path"],
        {
            "action": "module_request",
            "module": "github_token",
            "params": {
                "repo": args.repo,
                "permission": args.permission,
                "reason": args.reason,
            },
        },
        timeout=float(config["timeout_seconds"]) + 15,
    )
    if resp.get("status") == "approved" and resp.get("token"):
        mode_note = "auto-approved via repo tag" if resp.get("auto_approved") else "approved via Home Assistant"
        sys.stderr.write(f"[oob-auth] ✅ GitHub {args.permission} token granted ({mode_note}).\n")
        sys.stdout.write(f"{resp['token']}\n")
        sys.exit(0)
    sys.stderr.write(f"[oob-auth] ❌ GitHub token request {resp.get('status', 'denied')}: {resp.get('message', '')}\n")
    sys.exit(1)


def _save_ha_lease(req_id: str, caller_nonce: str, resp: Dict[str, Any]) -> None:
    ha_lease_out_path = _runtime_file_path(".jit-ha-lease.json", create_dir=True)
    oflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    lfd = os.open(ha_lease_out_path, oflags, 0o600)
    try:
        os.fchmod(lfd, 0o600)
    except OSError:
        pass
    ttl_sec = int(resp.get("ttl_seconds", 900))
    exp_ts = time.time() + ttl_sec
    with os.fdopen(lfd, "w", encoding="utf-8") as f:
        json.dump(
            {
                "request_id": req_id,
                "caller_nonce": caller_nonce,
                "scope": resp.get("scope", "read"),
                "domains": resp.get("domains", []),
                "expires_at": exp_ts,
                "transport": "unix",
            },
            f,
        )
    sys.stderr.write(
        f"[oob-auth] ✅ HA API '{resp.get('scope', 'read')}' proxy lease active for {ttl_sec // 60}m "
        f"(saved to {ha_lease_out_path})\n"
    )


def _print_ha_proxy_result(proxy_res: Dict[str, Any]) -> None:
    status = proxy_res.get("status")
    if status in ("ok", "http_error"):
        data = proxy_res.get("data")
        if isinstance(data, (dict, list)):
            print(json.dumps(data, indent=2))
        elif data is not None:
            print(str(data))
        if status == "http_error":
            sys.stderr.write(f"[oob-auth] ❌ Home Assistant HTTP {proxy_res.get('http_status')}\n")
            sys.exit(1)
        sys.exit(0)
    sys.stderr.write(f"[oob-auth] ❌ HA proxy error: {proxy_res.get('message', proxy_res)}\n")
    sys.exit(1)


def cmd_ha_api(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    body_obj = None
    if args.data:
        try:
            body_obj = json.loads(args.data)
        except Exception as e:
            sys.stderr.write(f"[oob-auth] ❌ --data must be valid JSON: {e}\n")
            sys.exit(1)

    ha_lease_out_path = _runtime_file_path(".jit-ha-lease.json", create_dir=False)
    if not args.lease and not args.single and args.path and os.path.exists(ha_lease_out_path):
        try:
            with open(ha_lease_out_path, "r", encoding="utf-8") as f:
                lease = json.load(f)
            if time.time() < float(lease.get("expires_at", 0)):
                proxy_res = send_unix_socket_request(
                    config["socket_path"],
                    {
                        "action": "ha_proxy_call",
                        "request_id": lease["request_id"],
                        "caller_nonce": lease["caller_nonce"],
                        "method": args.method,
                        "path": args.path,
                        "body": body_obj,
                    },
                    timeout=30.0,
                )
                _print_ha_proxy_result(proxy_res)
        except SystemExit:
            raise
        except Exception:
            pass

    if not args.reason:
        sys.stderr.write(
            "[oob-auth] ❌ No active HA API lease found (or lease expired). Provide --reason \"...\" to request mobile approval.\n"
        )
        sys.exit(1)

    mode = "single" if args.single else "lease"
    if mode == "single" and not args.path:
        sys.stderr.write("[oob-auth] ❌ --single requires --path /api/...\n")
        sys.exit(1)

    sys.stderr.write(
        f"[oob-auth] 🏠 Requesting mobile approval for Home Assistant API ({mode}, scope={args.scope})...\n"
    )
    resp = send_unix_socket_request(
        config["socket_path"],
        {
            "action": "module_request",
            "module": "ha_api",
            "params": {
                "mode": mode,
                "scope": args.scope,
                "domains": args.domains or [],
                "method": args.method,
                "path": args.path or "",
                "body": body_obj,
                "reason": args.reason,
            },
        },
        timeout=float(config.get("timeout_seconds", 900)) + 15,
    )
    if resp.get("status") != "approved":
        sys.stderr.write(f"[oob-auth] ❌ HA API request {resp.get('status', 'denied')}: {resp.get('message', '')}\n")
        sys.exit(1)

    if mode == "single":
        _print_ha_proxy_result(resp.get("proxy_response", {}))

    _save_ha_lease(resp.get("request_id", ""), resp.get("caller_nonce", ""), resp)
    if args.path:
        proxy_res = send_unix_socket_request(
            config["socket_path"],
            {
                "action": "ha_proxy_call",
                "request_id": resp["request_id"],
                "caller_nonce": resp["caller_nonce"],
                "method": args.method,
                "path": args.path,
                "body": body_obj,
            },
            timeout=30.0,
        )
        _print_ha_proxy_result(proxy_res)


def _revoke_single_lease_file(lease_path: str, config: Dict[str, Any], label: str) -> bool:
    if not os.path.exists(lease_path):
        return False
    with open(lease_path, "r", encoding="utf-8") as f:
        lease = json.load(f)
    try:
        if lease.get("transport") == "unix" or os.path.exists(config["socket_path"]):
            resp = send_unix_socket_request(
                config["socket_path"],
                {
                    "action": "revoke",
                    "request_id": lease["request_id"],
                    "caller_nonce": lease.get("caller_nonce", ""),
                },
                timeout=15.0,
            )
            sys.stderr.write(f"[oob-auth] 🗑️ {label} lease {lease['request_id']} revoked ({resp.get('status')}).\n")
        else:
            sa_token = extract_kubeconfig_token()
            broker_url = lease.get("broker_url", DEFAULT_K8S_BROKER_URL).rstrip("/")
            cacert_path = lease.get("cacert") or config.get("tls_cert_path", DEFAULT_TLS_CERT_PATH)
            ssl_ctx = _build_broker_ssl_context(cacert_path) if broker_url.startswith("https://") else None
            req = urllib.request.Request(
                f"{broker_url}/v1/revoke",
                data=json.dumps(
                    {
                        "request_id": lease["request_id"],
                        "caller_nonce": lease["caller_nonce"],
                    }
                ).encode("utf-8"),
                headers={"Authorization": f"Bearer {sa_token}", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10, context=ssl_ctx) as resp:
                sys.stderr.write(f"[oob-auth] 🗑️ {label} lease {lease['request_id']} revoked on cluster ({resp.status}).\n")
    except Exception as e:
        sys.stderr.write(f"[oob-auth] Warning: {label} revoke returned: {e}\n")
    finally:
        if os.path.exists(lease_path):
            os.remove(lease_path)
    return True


def cmd_revoke(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    lease_out_path = _runtime_file_path(".jit-k8s-lease.json", create_dir=False)
    token_out_path = _runtime_file_path(".jit-k8s-token", create_dir=False)
    ha_lease_out_path = _runtime_file_path(".jit-ha-lease.json", create_dir=False)

    revoked_any = False
    if os.path.exists(lease_out_path):
        revoked_any = _revoke_single_lease_file(lease_out_path, config, "K8s") or revoked_any
        if os.path.exists(token_out_path):
            os.remove(token_out_path)
    if os.path.exists(ha_lease_out_path):
        revoked_any = _revoke_single_lease_file(ha_lease_out_path, config, "HA API") or revoked_any
    if not revoked_any:
        sys.stderr.write("[oob-auth] No active K8s or HA API lease metadata found.\n")


def main(argv: Optional[list[str]] = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    config = load_config()

    if argv and argv[0] in ("--mcp-stdio", "mcp-stdio"):
        from .mcp_server import run_mcp_stdio_server

        run_mcp_stdio_server(config)
        return

    subcommands = {"sudo-batch", "k8s-token", "github-token", "ha-api", "confirm", "secret-checkout", "revoke"}
    if argv and argv[0] in subcommands:
        parser = argparse.ArgumentParser(prog="oob-auth", description="Universal Out-of-Band Auth Client")
        sub = parser.add_subparsers(dest="subcmd", required=True)

        p_batch = sub.add_parser(
            "sudo-batch",
            help="Execute a SHA-256-pinned bash script as root with 1 mobile tap and self-tamper guardrails",
        )
        p_batch.add_argument("--reason", required=True, help="Why this root batch is needed")
        p_batch.add_argument("--script", help="Inline bash script commands")
        p_batch.add_argument("--file", help="Path to bash script file to snapshot and execute")

        p_k8s = sub.add_parser("k8s-token", help="Request a 30-minute scoped Kubernetes JWT")
        p_k8s.add_argument("--broker-url", default="", help="Optional remote broker URL (defaults to local daemon socket)")
        p_k8s.add_argument(
            "--cacert",
            default=DEFAULT_TLS_CERT_PATH,
            help="CA certificate path for HTTPS broker verification (default: /etc/ha-sudo/tls.crt)",
        )
        p_k8s.add_argument(
            "--role",
            default="jit-workload-operator",
            choices=["view", "jit-workload-operator", "jit-storage-operator"],
        )
        p_k8s.add_argument("--namespaces", nargs="+", default=["default"])
        p_k8s.add_argument("--reason", required=True)
        p_k8s.add_argument("--timeout", type=int, default=300)
        p_k8s.add_argument("--raw", action="store_true", help="Print bare JWT on stdout instead of `export K8S_JIT_TOKEN=...`")

        p_gh = sub.add_parser("github-token", help="Request a tag-evaluated GitHub App single-repo token or Vault PAT")
        p_gh.add_argument("--repo", required=True, help="Target repository in 'owner/repo' format")
        p_gh.add_argument("--permission", default="write", choices=["read", "write"], help="Requested permission level")
        p_gh.add_argument("--reason", default="Git repository operation", help="Reason for GitHub access")

        p_ha = sub.add_parser("ha-api", help="Execute filtered Home Assistant REST API calls via root proxy (zero raw token exposure)")
        p_ha.add_argument("--lease", action="store_true", help="Request a 15-minute filtered proxy lease")
        p_ha.add_argument("--single", action="store_true", help="Request mobile approval for a single API call without standing lease")
        p_ha.add_argument("--scope", default="read", choices=["read", "admin"], help="Requested proxy scope (read or admin)")
        p_ha.add_argument("--domains", nargs="*", default=[], help="Optional allowed service domains for admin calls (e.g. light switch)")
        p_ha.add_argument("--method", default="GET", choices=["GET", "POST", "DELETE"], help="HTTP method")
        p_ha.add_argument("--path", default="", help="Home Assistant REST API path (e.g. /api/states or /api/services/light/turn_on)")
        p_ha.add_argument("--data", default="", help="Optional JSON request body for POST/DELETE calls")
        p_ha.add_argument("--reason", default="", help="Reason for Home Assistant API access (required when requesting approval)")

        p_conf = sub.add_parser("confirm", help="Request a generic Yes/No mobile approval receipt")
        p_conf.add_argument("--summary", required=True, help="Action summary to display on phone")
        p_conf.add_argument("--reason", required=True, help="Reason for the action")

        p_sec = sub.add_parser("secret-checkout", help="Request one-time checkout of a named secret")
        p_sec.add_argument("--key", required=True, help="Secret key name")
        p_sec.add_argument("--reason", required=True, help="Reason for secret checkout")
        p_sec.add_argument("--stdout", action="store_true", help="Print secret value to stdout instead of writing 0600 file path")

        sub.add_parser("revoke", help="Immediately revoke active Kubernetes JWT or Home Assistant API lease")

        args = parser.parse_args(argv)
        if args.subcmd == "sudo-batch":
            cmd_sudo_batch(args, config)
        elif args.subcmd == "k8s-token":
            cmd_k8s_token(args, config)
        elif args.subcmd == "github-token":
            cmd_github_token(args, config)
        elif args.subcmd == "ha-api":
            cmd_ha_api(args, config)
        elif args.subcmd == "confirm":
            cmd_confirm(args, config)
        elif args.subcmd == "secret-checkout":
            cmd_secret_checkout(args, config)
        elif args.subcmd == "revoke":
            cmd_revoke(args, config)
        return

    parser = argparse.ArgumentParser(description="Modular Home Assistant Out-of-Band Gate")
    parser.add_argument("--daemon", action="store_true", help="Run as persistent root systemd daemon")
    parser.add_argument("--http-only", action="store_true", help="Run HTTP listener only (for K8s pod mode)")
    parser.add_argument("--pam", action="store_true", help="Run as PAM client helper during sudo")
    parser.add_argument("--ssh-enforce", action="store_true", help="Run as OpenSSH ForceCommand helper")
    parser.add_argument("--mcp-stdio", action="store_true", help="Run as JSON-RPC 2.0 MCP server over stdio")
    parser.add_argument("--test", action="store_true", help="Run self-diagnostic and connectivity check")
    parser.add_argument("--user", type=str, default=None, help="Target username for PAM check")
    parser.add_argument("command", nargs="*", help="Command being executed")

    args = parser.parse_args(argv)

    if args.mcp_stdio:
        from .mcp_server import run_mcp_stdio_server

        run_mcp_stdio_server(config)
    elif args.daemon:
        run_daemon(config, enable_unix_socket=not args.http_only)
    elif args.ssh_enforce:
        run_ssh_enforce(config)
    elif args.test:
        run_test(config)
    else:
        username = (args.user or os.environ.get("PAM_RUSER") or "").strip()
        if not username:
            sys.stderr.write("[ha-oob-gate] ❌ Security error: PAM_RUSER is unset; refusing PAM elevation.\n")
            sys.exit(1)
        cmd = " ".join(args.command) if args.command else "administrative command"
        run_pam_gate(config, username, cmd)


if __name__ == "__main__":
    main()
