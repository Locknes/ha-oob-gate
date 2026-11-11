"""
daemon.py - Core Out-of-Band Authorization Daemon (ha-oob-gate).

Runs either:
1. On a Linux host as `root` (`ha-sudo-gate.service` / `ha-oob-gate.service`),
   listening on Unix socket `/run/ha-sudo/daemon.sock` (with kernel `SO_PEERCRED`
   verification) and HTTPS port `:8443` (for Home Assistant callbacks).
2. Inside an isolated Kubernetes Pod (`jit-system`), authenticating callers via
   Kubernetes `TokenReview` and serving `k8s_token` and `secret_checkout`.
"""

from __future__ import annotations

import datetime
import hmac
import json
import math
import os
import pwd
import secrets
import select
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Tuple

from . import __version__
from .audit import emit_audit_event
from .ipc import FrameTooLargeError, recv_json_frame, send_json_frame
from .k8s_client import k8s_api_request
from .modules import BaseGateModule, CallerInfo, NotificationSpec, discover_modules
from .sanitize import HEX64_REGEX, UUID_REGEX, sanitize_text

ROOT_CONFIG_PATH = "/etc/ha-sudo/config.json"
DEFAULT_CONFIG_PATH = ROOT_CONFIG_PATH if os.geteuid() == 0 else os.environ.get("HA_SUDO_CONFIG", ROOT_CONFIG_PATH)
DEFAULT_HMAC_KEY_PATH = "/etc/ha-sudo/hmac.key"
DEFAULT_TLS_CERT_PATH = "/etc/ha-sudo/tls.crt"
DEFAULT_TLS_KEY_PATH = "/etc/ha-sudo/tls.key"
DEFAULT_TICKET_DIR = "/run/ha-sudo"
DEFAULT_SOCKET_PATH = "/run/ha-sudo/daemon.sock"
DEFAULT_PORT = 8443
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_RESOLVED_RETENTION_SECONDS = 120.0
MAX_PAYLOAD_SIZE = 16384
MAX_ACTIVE_REQUESTS = 64
MAX_ACTIVE_LEASES = 256


def detect_primary_ip() -> str:
    """Auto-detect the host's primary outbound LAN IP address via UDP route lookup (sends zero packets)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def load_config(custom_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from JSON file and/or environment variables.
    When running as root (UID 0), strictly enforces `/etc/ha-sudo/config.json`
    owned by `root:root` with no group/other permissions (`0600`) and ignores
    caller-mutable environment variables (`HA_SUDO_CONFIG`, `ENABLED_MODULES`, etc.).
    """
    is_root = os.geteuid() == 0
    defaults: Dict[str, Any] = {
        "ha_url": "" if is_root else os.environ.get("HA_URL", ""),
        "ha_webhook_url": "" if is_root else os.environ.get("HA_WEBHOOK_URL", ""),
        "ha_trusted_ip": "" if is_root else os.environ.get("HA_TRUSTED_IP", ""),
        "ha_approval_token": "" if is_root else os.environ.get("HA_APPROVAL_TOKEN", ""),
        "webhook_id": "" if is_root else os.environ.get("HA_WEBHOOK_ID", ""),
        "callback_host": "" if is_root else os.environ.get("CALLBACK_HOST", ""),
        "listen_port": DEFAULT_PORT if is_root else int(os.environ.get("LISTEN_PORT", str(DEFAULT_PORT))),
        "callback_port": DEFAULT_PORT if is_root else int(os.environ.get("CALLBACK_PORT", os.environ.get("LISTEN_PORT", str(DEFAULT_PORT)))),
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS if is_root else int(os.environ.get("TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))),
        "resolved_request_retention_seconds": DEFAULT_RESOLVED_RETENTION_SECONDS,
        "hmac_key_path": DEFAULT_HMAC_KEY_PATH,
        "tls_enabled": True if is_root else os.environ.get("TLS_ENABLED", "true").lower() in ("1", "true", "yes"),
        "tls_cert_path": DEFAULT_TLS_CERT_PATH if is_root else os.environ.get("TLS_CERT_PATH", DEFAULT_TLS_CERT_PATH),
        "tls_key_path": DEFAULT_TLS_KEY_PATH if is_root else os.environ.get("TLS_KEY_PATH", DEFAULT_TLS_KEY_PATH),
        "ticket_dir": DEFAULT_TICKET_DIR,
        "socket_path": DEFAULT_SOCKET_PATH,
        "vault_path": "/etc/ha-sudo/vault.json",
        "enabled_modules": None,
        "default_sudo_scope": "command_pinned",
        "user_policies": {},
        "passwordless_pam_users": [],
        "allowed_k8s_callers": [],
        "max_requests_per_10m": 6,
        "max_auto_approvals_per_10m": 60,
    }

    if is_root:
        search_paths = [ROOT_CONFIG_PATH]
    else:
        search_paths = [custom_path] if custom_path else [DEFAULT_CONFIG_PATH]

    for path in search_paths:
        if path and os.path.exists(path):
            try:
                if is_root:
                    st = os.stat(path)
                    if st.st_uid != 0 or (st.st_mode & 0o077) != 0:
                        raise PermissionError(
                            f"Refusing to load root config {path}: must be owned by root (0) with 0600 permissions"
                        )
                with open(path, "r", encoding="utf-8") as f:
                    user_conf = json.load(f)
                    defaults.update(user_conf)
                break
            except Exception as e:
                sys.stderr.write(f"[ha-oob-gate] Warning: Could not read {path}: {e}\n")

    if not defaults.get("callback_host"):
        defaults["callback_host"] = detect_primary_ip()
    if not defaults.get("callback_port"):
        defaults["callback_port"] = defaults["listen_port"]

    if not is_root and os.environ.get("ENABLED_MODULES"):
        defaults["enabled_modules"] = [
            m.strip() for m in os.environ["ENABLED_MODULES"].split(",") if m.strip()
        ]

    return defaults


def get_or_create_hmac_key(key_path: str = DEFAULT_HMAC_KEY_PATH) -> Optional[bytes]:
    """Retrieve the root HMAC secret key or generate a new 256-bit key atomically with 0400 permissions."""
    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        except PermissionError:
            return None
        except Exception as e:
            sys.stderr.write(f"[ha-oob-gate] Error reading HMAC key at {key_path}: {e}\n")
            return None

    if os.geteuid() == 0:
        try:
            os.makedirs(os.path.dirname(key_path), mode=0o700, exist_ok=True)
            key = secrets.token_bytes(32)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(key_path, flags, 0o400)
            try:
                os.fchmod(fd, 0o400)
            except OSError:
                pass
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            return key
        except Exception as e:
            sys.stderr.write(f"[ha-oob-gate] Failed to generate HMAC key at {key_path}: {e}\n")
    # Fallback in-memory key for non-root container mode (e.g. K8s pod)
    return secrets.token_bytes(32)


def get_socket_peer_caller(conn: socket.socket) -> CallerInfo:
    """
    Extract kernel-verified (pid, uid, gid) from a Linux AF_UNIX socket via SO_PEERCRED.
    Cannot be spoofed by user-space processes.
    """
    SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
    creds = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        username = f"uid_{uid}"
    return CallerInfo(
        uid=uid,
        gid=gid,
        pid=pid,
        username=username,
        is_root=(uid == 0),
        source="unix_socket",
    )


def create_tls_context(config: Dict[str, Any]) -> ssl.SSLContext:
    """Create a hardened server-side TLS context (minimum TLSv1.2)."""
    cert_path = config.get("tls_cert_path", DEFAULT_TLS_CERT_PATH)
    key_path = config.get("tls_key_path", DEFAULT_TLS_KEY_PATH)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def wrap_http_server_tls(http_server: ThreadingHTTPServer, config: Dict[str, Any]) -> bool:
    """Wrap `ThreadingHTTPServer.socket` in TLS when `tls_enabled` is True."""
    if not config.get("tls_enabled", True):
        return False
    ctx = create_tls_context(config)
    http_server.socket = ctx.wrap_socket(http_server.socket, server_side=True)
    return True


def verify_ha_callback_origin(
    config: Dict[str, Any], client_ip: str, approval_token_hdr: str = ""
) -> Tuple[bool, str]:
    """
    Defense-in-depth verification for Home Assistant callbacks and bootstrap calls.
    Requires BOTH:
      1. `client_ip in allowed_ips` whenever `ha_trusted_ip` is configured, AND
      2. Constant-time `hmac.compare_digest` on `X-HA-Approval-Token` whenever `ha_approval_token` is configured.
    Fails closed if neither `ha_trusted_ip` nor `ha_approval_token` is configured.
    """
    trusted_ip = str(config.get("ha_trusted_ip", "") or "").strip()
    allowed_ips = {ip.strip() for ip in trusted_ip.split(",") if ip.strip()}
    expected_hdr_tok = str(config.get("ha_approval_token", "") or "").strip()

    if not allowed_ips and not expected_hdr_tok:
        return False, "Forbidden: Neither ha_trusted_ip nor ha_approval_token is configured"

    if allowed_ips and client_ip not in allowed_ips:
        return False, "Forbidden: Untrusted Client IP"

    if expected_hdr_tok:
        if not approval_token_hdr or not hmac.compare_digest(str(approval_token_hdr), expected_hdr_tok):
            return False, "Forbidden: Invalid or missing X-HA-Approval-Token"

    return True, "ok"


def trigger_ha_webhook(config: Dict[str, Any], payload: Dict[str, Any]) -> bool:
    """Dispatch actionable notification webhook to Home Assistant."""
    webhook_url = config.get("ha_webhook_url", "")
    if not webhook_url:
        ha_url = config.get("ha_url", "").rstrip("/")
        webhook_id = config.get("webhook_id", "")
        if not ha_url or not webhook_id:
            sys.stderr.write("[ha-oob-gate] Error: Missing ha_url/webhook_id in configuration.\n")
            return False
        webhook_url = f"{ha_url}/api/webhook/{webhook_id}"

    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": f"ha-oob-gate/{__version__}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201, 202)
    except Exception as e:
        sys.stderr.write(f"[ha-oob-gate] Error reaching Home Assistant webhook: {e}\n")
        return False


class GateEngine:
    """
    Stateful coordination engine managing active pending requests, rate limiting,
    pluggable modules, and active lease expiration / revocation.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.hmac_key = get_or_create_hmac_key(config.get("hmac_key_path", DEFAULT_HMAC_KEY_PATH))
        self.config["_hmac_key"] = self.hmac_key
        self.modules: Dict[str, BaseGateModule] = discover_modules(config.get("enabled_modules"))
        self._ipc_aliases: Dict[str, str] = {
            mod.ipc_elevation_alias: mod_name
            for mod_name, mod in self.modules.items()
            if mod.ipc_elevation_alias
        }
        self.lock = threading.Lock()
        self.active_requests: Dict[str, Dict[str, Any]] = {}
        self.active_leases: Dict[str, Dict[str, Any]] = {}
        self.request_timestamps: list[float] = []
        self.request_timestamps_by_caller: Dict[str, list[float]] = {}
        self.auto_approve_timestamps_by_caller: Dict[str, list[float]] = {}

    def _caller_rate_key(self, caller: Optional[CallerInfo] = None, params: Optional[Dict[str, Any]] = None) -> str:
        if caller is None:
            return "global"
        if caller.is_root and params and params.get("user"):
            return f"pam_user:{params.get('user')}"
        if caller.k8s_identity:
            return f"k8s:{caller.k8s_identity}"
        return f"uid:{caller.uid}"

    def check_rate_limit_locked(
        self,
        caller: Optional[CallerInfo] = None,
        params: Optional[Dict[str, Any]] = None,
        record: bool = True,
    ) -> Tuple[bool, str, float]:
        now = time.time()
        key = self._caller_rate_key(caller, params)
        bucket = self.request_timestamps_by_caller.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < 600]
        self.request_timestamps[:] = [t for t in self.request_timestamps if now - t < 600]
        max_reqs = int(self.config.get("max_requests_per_10m", 6))
        if len(bucket) >= max_reqs:
            return False, f"Rate limit exceeded for caller ({key}: max {max_reqs} requests per 10 minutes)", 0.0
        if record:
            bucket.append(now)
            self.request_timestamps.append(now)
        return True, "ok", now

    def unrecord_rate_limit_locked(
        self,
        caller: Optional[CallerInfo],
        params: Optional[Dict[str, Any]],
        ts: float,
    ) -> None:
        if ts <= 0.0:
            return
        key = self._caller_rate_key(caller, params)
        bucket = self.request_timestamps_by_caller.get(key)
        if bucket and ts in bucket:
            bucket.remove(ts)
            if not bucket:
                self.request_timestamps_by_caller.pop(key, None)
        if ts in self.request_timestamps:
            self.request_timestamps.remove(ts)

    def check_auto_approve_rate_limit_locked(
        self,
        caller: Optional[CallerInfo] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        now = time.time()
        key = self._caller_rate_key(caller, params)
        bucket = self.auto_approve_timestamps_by_caller.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < 600]
        max_auto = int(self.config.get("max_auto_approvals_per_10m", 60))
        if len(bucket) >= max_auto:
            return False, f"Auto-approval rate limit exceeded for caller ({key}: max {max_auto} per 10 minutes)"
        bucket.append(now)
        return True, "ok"

    def _record_lease_locked(self, req_id: str, lease_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        evicted = None
        if len(self.active_leases) >= MAX_ACTIVE_LEASES and req_id not in self.active_leases:
            oldest_id = min(self.active_leases, key=lambda k: self.active_leases[k].get("expires_at", 0.0))
            evicted = self.active_leases.pop(oldest_id, None)
            if evicted is not None:
                evicted = dict(evicted)
                evicted.setdefault("request_id", oldest_id)
        self.active_leases[req_id] = lease_entry
        return evicted

    def _revoke_evicted_lease(self, evicted: Optional[Dict[str, Any]]) -> None:
        if not evicted:
            return
        mod_name = evicted.get("module")
        if not mod_name:
            return
        mod = self.modules.get(mod_name)
        if mod:
            try:
                mod.revoke(
                    str(evicted.get("request_id", "")),
                    evicted.get("grant_metadata") or {},
                    self.config,
                )
            except Exception as e:
                sys.stderr.write(f"[ha-oob-gate] Error revoking evicted lease {evicted.get('request_id')}: {e}\n")

    def _evict_stale_requests_locked(self, now: float) -> list[Tuple[BaseGateModule, Dict[str, Any]]]:
        """
        Evict expired pending requests and uncollected resolved requests from `self.active_requests`.
        Returns a list of `(module, params)` pairs needing `cleanup_pending_request()` outside `self.lock`.
        Never evicts in-flight `"processing"` requests.
        """
        pending_cleanup: list[Tuple[BaseGateModule, Dict[str, Any]]] = []
        max_pending_age = float(self.config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)) + 60.0
        retention_sec = float(
            self.config.get("resolved_request_retention_seconds", DEFAULT_RESOLVED_RETENTION_SECONDS)
        )

        for req_id, req in list(self.active_requests.items()):
            status = req.get("status")
            if status == "processing":
                continue
            if status == "pending":
                if now - float(req.get("created_at", now)) > max_pending_age:
                    self.active_requests.pop(req_id, None)
                    req["status"] = "timeout"
                    req["resolved_at"] = now
                    mod = self.modules.get(str(req.get("module", "")))
                    if mod is not None:
                        pending_cleanup.append((mod, req.get("params") or {}))
                    cond = req.get("condition")
                    if cond is not None:
                        with cond:
                            cond.notify_all()
            else:
                resolved_at = float(req.get("resolved_at", req.get("created_at", now)))
                if now - resolved_at >= retention_sec:
                    self.active_requests.pop(req_id, None)

        return pending_cleanup

    def _clamp_ttl(self, params: Dict[str, Any], mod: BaseGateModule) -> int:
        raw_ttl = params.get("ttl_seconds")
        try:
            req_ttl = int(raw_ttl) if raw_ttl is not None else mod.default_ttl_seconds
        except (ValueError, TypeError):
            req_ttl = mod.default_ttl_seconds
        ttl = max(60, min(req_ttl, mod.default_ttl_seconds))
        params["ttl_seconds"] = ttl
        return ttl

    def submit_and_wait(
        self,
        module_name: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        wait_seconds: Optional[float] = None,
        disconnect_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Validate request against `module_name`, dispatch Home Assistant webhook,
        and either wait synchronously (`wait_seconds=None`) or return `202 pending`
        for async polling.
        """
        mod = self.modules.get(module_name)
        if not mod:
            return {"status": "error", "code": 400, "message": f"Module '{module_name}' is not enabled"}

        if mod.requires_root_caller and not caller.is_root:
            return {
                "status": "error",
                "code": 403,
                "message": f"Module '{module_name}' requires root caller (SO_PEERCRED uid=0, got uid={caller.uid})",
            }

        ttl = self._clamp_ttl(params, mod)

        # Atomically reserve per-caller rate-limit slot and check active_requests capacity BEFORE module
        # validation so concurrent bursts cannot bypass rate limits during outbound API calls or staging.
        pending_cleanup: list[Tuple[BaseGateModule, Dict[str, Any]]] = []
        with self.lock:
            if len(self.active_requests) >= MAX_ACTIVE_REQUESTS:
                pending_cleanup = self._evict_stale_requests_locked(time.time())
            if len(self.active_requests) >= MAX_ACTIVE_REQUESTS:
                rl_ok = False
                rl_msg = "Too many active pending requests"
                rl_ts = 0.0
            else:
                rl_ok, rl_msg, rl_ts = self.check_rate_limit_locked(caller, params, record=True)

        for cleanup_mod, cleanup_params in pending_cleanup:
            cleanup_mod.cleanup_pending_request(cleanup_params)

        if not rl_ok:
            return {"status": "error", "code": 429, "message": rl_msg}

        ok, msg = mod.validate(params, caller, self.config)
        if not ok:
            if not mod.retain_rate_limit_on_validate_error(params):
                with self.lock:
                    self.unrecord_rate_limit_locked(caller, params, rl_ts)
            mod.cleanup_pending_request(params)
            return {"status": "error", "code": 403, "message": msg}

        if mod.can_auto_approve(params, caller, self.config):
            with self.lock:
                self.unrecord_rate_limit_locked(caller, params, rl_ts)
                auto_ok, auto_msg = self.check_auto_approve_rate_limit_locked(caller, params)
                if not auto_ok:
                    mod.cleanup_pending_request(params)
                    return {"status": "error", "code": 429, "message": auto_msg}

            req_id = str(uuid.uuid4())
            caller_nonce = secrets.token_hex(16)
            try:
                grant_res = mod.grant(req_id, params, caller, ttl, self.config)
            except Exception as e:
                mod.cleanup_pending_request(params)
                return {"status": "error", "code": 500, "message": f"Grant failed: {e}"}
            if grant_res.get("status") == "error":
                mod.cleanup_pending_request(params)
                grant_res.setdefault("code", 500)
                return grant_res
            grant_res.setdefault("status", "approved")
            grant_res["request_id"] = req_id
            grant_res["caller_nonce"] = caller_nonce
            grant_res["auto_approved"] = True
            with self.lock:
                evicted = self._record_lease_locked(
                    req_id,
                    {
                        "request_id": req_id,
                        "caller_nonce": caller_nonce,
                        "caller": caller,
                        "module": module_name,
                        "grant_metadata": grant_res,
                        "expires_at": time.time() + ttl,
                    },
                )
            self._revoke_evicted_lease(evicted)
            emit_audit_event(
                "request.auto_approved",
                self.config,
                request_id=req_id,
                module=module_name,
                caller_user=caller.username,
                caller_uid=caller.uid,
                caller_source=caller.source,
                ttl_seconds=ttl,
                params=params,
            )
            return grant_res

        evicted_cleanup: list[Tuple[BaseGateModule, Dict[str, Any]]] = []
        with self.lock:
            if len(self.active_requests) >= MAX_ACTIVE_REQUESTS:
                evicted_cleanup = self._evict_stale_requests_locked(time.time())
            if len(self.active_requests) >= MAX_ACTIVE_REQUESTS:
                self.unrecord_rate_limit_locked(caller, params, rl_ts)
                over_capacity = True
            else:
                over_capacity = False
                req_id = str(uuid.uuid4())
                approve_nonce = secrets.token_hex(32)
                deny_nonce = secrets.token_hex(32)
                caller_nonce = secrets.token_hex(16)
                verify_code = secrets.token_hex(2).upper()
                cond = threading.Condition()

                hostname = sanitize_text(self.config.get("hostname") or socket.gethostname(), max_len=128)
                notif: NotificationSpec = mod.format_notification(params, caller, verify_code, hostname, self.config)

                req_entry = {
                    "request_id": req_id,
                    "nonce": approve_nonce,
                    "approve_nonce": approve_nonce,
                    "deny_nonce": deny_nonce,
                    "caller_nonce": caller_nonce,
                    "verify_code": verify_code,
                    "module": module_name,
                    "params": params,
                    "caller": caller,
                    "ttl_seconds": ttl,
                    "condition": cond,
                    "status": "pending",
                    "created_at": time.time(),
                    "resolved_at": None,
                    "abandoned_by_sync_waiter": False,
                    "grant_result": None,
                }
                self.active_requests[req_id] = req_entry

        for cleanup_mod, cleanup_params in evicted_cleanup:
            cleanup_mod.cleanup_pending_request(cleanup_params)

        if over_capacity:
            mod.cleanup_pending_request(params)
            return {"status": "error", "code": 429, "message": "Too many active pending requests"}

        webhook_payload = {
            "request_id": req_id,
            "nonce": approve_nonce,
            "approve_nonce": approve_nonce,
            "deny_nonce": deny_nonce,
            "verify_code": verify_code,
            "module": module_name,
            "hostname": hostname,
            "user": sanitize_text(params.get("user", caller.username), max_len=64),
            "command": sanitize_text(notif.command_summary or params.get("command", module_name), max_len=512),
            "cwd": sanitize_text(params.get("cwd", "/"), max_len=256),
            "pid": params.get("pid", caller.pid),
            "parent_process": sanitize_text(params.get("parent_process", caller.source), max_len=64),
            "title": notif.title,
            "message": notif.message,
            "approve_title": notif.approve_title,
            "deny_title": notif.deny_title,
            "approved_title": notif.approved_title,
            "approved_message": notif.approved_message,
            "denied_title": notif.denied_title,
            "denied_message": notif.denied_message,
            "timeout_title": notif.timeout_title,
            "timeout_message": notif.timeout_message,
            "tag": f"oob_{req_id}",
            "channel": f"OOB: {hostname}",
            "group": f"oob_{hostname}",
            "icon": notif.icon,
            "color": notif.color,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "callback_scheme": "https" if self.config.get("tls_enabled", True) else "http",
            "callback_host": self.config["callback_host"],
            "callback_port": self.config["callback_port"],
            "timeout": self.config["timeout_seconds"],
        }

        if not trigger_ha_webhook(self.config, webhook_payload):
            with self.lock:
                self.active_requests.pop(req_id, None)
            mod.cleanup_pending_request(params)
            return {"status": "error", "code": 502, "message": "Failed to reach Home Assistant webhook"}

        emit_audit_event(
            "request.submitted",
            self.config,
            request_id=req_id,
            module=module_name,
            caller_user=caller.username,
            caller_uid=caller.uid,
            caller_source=caller.source,
            verify_code=verify_code,
            ttl_seconds=ttl,
            params=params,
        )

        if wait_seconds == 0:
            return {
                "status": "pending",
                "code": 202,
                "request_id": req_id,
                "caller_nonce": caller_nonce,
                "verify_code": verify_code,
                "ttl_seconds": ttl,
            }

        timeout = wait_seconds if wait_seconds is not None else float(self.config["timeout_seconds"])
        return self.wait_for_resolution(
            req_id,
            timeout=timeout,
            cleanup_on_exit=(wait_seconds is None),
            disconnect_check=disconnect_check,
        )

    def wait_for_resolution(
        self,
        req_id: str,
        timeout: float,
        cleanup_on_exit: bool = True,
        disconnect_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        with self.lock:
            req_entry = self.active_requests.get(req_id)
            if not req_entry:
                return {"status": "error", "code": 404, "message": "Unknown request_id"}
            cond: threading.Condition = req_entry["condition"]
            mod = self.modules.get(str(req_entry.get("module", "")))

        deadline = time.time() + timeout
        client_disconnected = False
        with cond:
            while req_entry["status"] in ("pending", "processing"):
                if disconnect_check is not None and req_entry["status"] == "pending":
                    if disconnect_check():
                        client_disconnected = True
                        break
                rem = deadline - time.time()
                if rem <= 0:
                    if cleanup_on_exit and req_entry["status"] == "processing":
                        cond.wait(timeout=15.0)
                    break
                wait_slice = min(rem, 1.0) if disconnect_check is not None else rem
                cond.wait(timeout=wait_slice)

        if client_disconnected:
            clear_hostname = sanitize_text(self.config.get("hostname") or socket.gethostname(), max_len=128)
            cancelled_now = False
            with self.lock:
                if req_entry["status"] == "pending":
                    req_entry["status"] = "cancelled"
                    req_entry["resolved_at"] = time.time()
                    self.active_requests.pop(req_id, None)
                    cancelled_now = True
            if cancelled_now:
                if mod is not None:
                    mod.cleanup_pending_request(req_entry["params"])
                try:
                    trigger_ha_webhook(
                        self.config,
                        {
                            "clear": True,
                            "action": "clear_notification",
                            "request_id": req_id,
                            "tag": f"oob_{req_id}",
                            "hostname": clear_hostname,
                            "message": "clear_notification",
                        },
                    )
                except Exception:
                    pass
                return {"status": "cancelled", "request_id": req_id, "message": "Client disconnected"}

        timed_out_pending = False
        with self.lock:
            status = req_entry["status"]
            if status == "pending" and cleanup_on_exit:
                req_entry["status"] = "timeout"
                req_entry["resolved_at"] = time.time()
                self.active_requests.pop(req_id, None)
                timed_out_pending = True
            elif status == "processing" and cleanup_on_exit:
                # Synchronous waiter timed out while `_grant_worker` is still executing.
                # Mark as abandoned so `_grant_worker` evicts the request and revokes any uncollected lease,
                # and return a deterministic timeout status instead of `"status": "pending"`.
                req_entry["abandoned_by_sync_waiter"] = True
                return {
                    "status": "timeout",
                    "request_id": req_id,
                    "message": "Timed out waiting for grant execution",
                }
            elif cleanup_on_exit and status in ("approved", "denied", "error", "cancelled", "timeout"):
                self.active_requests.pop(req_id, None)

        if timed_out_pending:
            if mod is not None:
                mod.cleanup_pending_request(req_entry["params"])
            return {"status": "timeout", "request_id": req_id}

        if status == "approved":
            return req_entry["grant_result"] or {"status": "approved", "request_id": req_id}
        if status == "denied":
            return {"status": "denied", "request_id": req_id}
        if status == "cancelled":
            return {"status": "cancelled", "request_id": req_id}
        if status == "pending":
            return {
                "status": "pending",
                "request_id": req_id,
                "verify_code": req_entry["verify_code"],
            }
        if status == "processing":
            return {
                "status": "processing",
                "request_id": req_id,
                "verify_code": req_entry["verify_code"],
            }
        if status == "timeout":
            return {"status": "timeout", "request_id": req_id}
        return req_entry.get("grant_result") or {"status": "error", "message": "Grant failed"}

    def handle_ha_callback(
        self, req_id: str, nonce: str, action: str, client_ip: str, approval_token_hdr: str = ""
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Process an incoming approval/denial callback from Home Assistant.
        Strictly enforces BOTH `ha_trusted_ip` (when configured) AND `X-HA-Approval-Token`
        (when configured), UUIDv4 format, and action-specific 256-bit `approve_nonce` / `deny_nonce`.
        Executes `mod.grant()` asynchronously in a background worker thread so long-running
        grants never block Home Assistant's `rest_command`.
        """
        origin_ok, origin_err = verify_ha_callback_origin(self.config, client_ip, approval_token_hdr)
        if not origin_ok:
            sys.stderr.write(f"[ha-oob-gate SECURITY] Rejected callback from {client_ip}: {origin_err}\n")
            return 403, {"error": origin_err}

        if not UUID_REGEX.match(req_id) or not HEX64_REGEX.match(nonce):
            return 400, {"error": "Bad Request: Invalid UUID or 64-hex Nonce format"}

        denied_cleanup = False
        with self.lock:
            req_entry = self.active_requests.get(req_id)
            if not req_entry:
                return 404, {"error": "Not Found: No active request matching request_id"}

            if req_entry["status"] != "pending":
                return 409, {"error": f"Request already resolved ({req_entry['status']})"}

            cond: threading.Condition = req_entry["condition"]
            mod = self.modules[req_entry["module"]]

            if action == "deny":
                valid_deny = hmac.compare_digest(nonce, req_entry["deny_nonce"]) or hmac.compare_digest(
                    nonce, req_entry["approve_nonce"]
                )
                if not valid_deny:
                    sys.stderr.write(f"[ha-oob-gate SECURITY] Deny nonce mismatch on request {req_id}!\n")
                    return 401, {"error": "Unauthorized: Mismatched Nonce"}
                req_entry["status"] = "denied"
                req_entry["resolved_at"] = time.time()
                denied_cleanup = True
            elif action != "approve":
                return 400, {"error": f"Invalid action '{action}'"}
            else:
                if not hmac.compare_digest(nonce, req_entry["approve_nonce"]):
                    sys.stderr.write(f"[ha-oob-gate SECURITY] Approve nonce mismatch on request {req_id}!\n")
                    return 401, {"error": "Unauthorized: Mismatched Approve Nonce"}
                req_entry["status"] = "processing"

        if denied_cleanup:
            mod.cleanup_pending_request(req_entry["params"])
            with cond:
                cond.notify_all()
            emit_audit_event(
                "callback.denied",
                self.config,
                request_id=req_id,
                module=req_entry["module"],
                client_ip=client_ip,
            )
            return 200, {"status": "denied", "request_id": req_id, "message": "Elevation rejected"}

        def _grant_worker():
            evicted_lease = None
            abandoned_lease = None
            try:
                grant_res = mod.grant(
                    req_id=req_id,
                    params=req_entry["params"],
                    caller=req_entry["caller"],
                    ttl_seconds=req_entry["ttl_seconds"],
                    config=self.config,
                )
                now = time.time()
                if grant_res.get("status") == "error":
                    grant_res["request_id"] = req_id
                    with self.lock:
                        req_entry["grant_result"] = grant_res
                        req_entry["status"] = "error"
                        req_entry["resolved_at"] = now
                        if req_entry.get("abandoned_by_sync_waiter"):
                            self.active_requests.pop(req_id, None)
                else:
                    grant_res.setdefault("status", "approved")
                    grant_res["request_id"] = req_id
                    grant_res["caller_nonce"] = req_entry["caller_nonce"]
                    with self.lock:
                        req_entry["grant_result"] = grant_res
                        req_entry["status"] = "approved"
                        req_entry["resolved_at"] = now
                        lease_entry = {
                            "request_id": req_id,
                            "caller_nonce": req_entry["caller_nonce"],
                            "caller": req_entry["caller"],
                            "module": req_entry["module"],
                            "grant_metadata": grant_res,
                            "expires_at": now + req_entry["ttl_seconds"],
                        }
                        if req_entry.get("abandoned_by_sync_waiter"):
                            self.active_requests.pop(req_id, None)
                            abandoned_lease = lease_entry
                        else:
                            evicted_lease = self._record_lease_locked(req_id, lease_entry)
                    self._revoke_evicted_lease(evicted_lease)
                    self._revoke_evicted_lease(abandoned_lease)
                    emit_audit_event(
                        "callback.approved",
                        self.config,
                        request_id=req_id,
                        module=req_entry["module"],
                        client_ip=client_ip,
                        ttl_seconds=req_entry["ttl_seconds"],
                    )
            except Exception as e:
                with self.lock:
                    req_entry["status"] = "error"
                    req_entry["resolved_at"] = time.time()
                    req_entry["grant_result"] = {"status": "error", "message": str(e)}
                    if req_entry.get("abandoned_by_sync_waiter"):
                        self.active_requests.pop(req_id, None)
            finally:
                with cond:
                    cond.notify_all()

        worker = threading.Thread(target=_grant_worker, name=f"oob-grant-{req_id[:8]}", daemon=True)
        worker.start()
        if not mod.run_grant_async:
            worker.join(timeout=0.025)
        return 200, {"status": "approved", "request_id": req_id, "message": "Elevation granted"}

    def revoke_lease(self, req_id: str, caller_nonce: str = "") -> bool:
        with self.lock:
            lease = self.active_leases.get(req_id)
            if not lease:
                return False
            expected_nonce = lease.get("caller_nonce", "")
            if not caller_nonce or not expected_nonce or not hmac.compare_digest(caller_nonce, expected_nonce):
                return False
            self.active_leases.pop(req_id, None)
            self.active_requests.pop(req_id, None)

        mod = self.modules.get(lease["module"])
        if mod:
            return mod.revoke(req_id, lease["grant_metadata"], self.config)
        return True

    def dispatch_lease_rpc(
        self,
        req_id: str,
        caller_nonce: str,
        action: str,
        payload: Dict[str, Any],
        caller: Optional[CallerInfo] = None,
        expected_module: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generic active-lease RPC dispatcher: validates lease existence, module match, TTL,
        constant-time `caller_nonce`, and caller identity, then delegates to
        `BaseGateModule.handle_lease_rpc()`.
        """
        now = time.time()
        with self.lock:
            lease = self.active_leases.get(req_id)
            if not lease or (expected_module and lease.get("module") != expected_module):
                label = f"{expected_module} " if expected_module else ""
                return {"status": "error", "code": 404, "message": f"No active {label}lease found for request_id"}
            if now >= float(lease.get("expires_at", 0)):
                self.active_leases.pop(req_id, None)
                return {"status": "error", "code": 401, "message": "Lease has expired"}
            expected_nonce = lease.get("caller_nonce", "")
            if not caller_nonce or not expected_nonce or not hmac.compare_digest(caller_nonce, expected_nonce):
                return {"status": "error", "code": 403, "message": "Invalid caller_nonce for active lease"}
            lease_caller: Optional[CallerInfo] = lease.get("caller")
            if caller is not None and lease_caller is not None:
                if (
                    caller.source != lease_caller.source
                    or caller.uid != lease_caller.uid
                    or caller.username != lease_caller.username
                    or caller.k8s_identity != lease_caller.k8s_identity
                ):
                    return {"status": "error", "code": 403, "message": "Caller identity mismatch for active lease"}
            lease_snapshot = dict(lease)

        mod = self.modules.get(str(lease_snapshot.get("module", "")))
        if mod is None:
            return {"status": "error", "code": 404, "message": "Lease module is not loaded"}
        return mod.handle_lease_rpc(action, payload, lease_snapshot, caller, self.config)

    def sweep_expired_leases(self) -> None:
        now = time.time()
        expired_leases: list[Tuple[str, Dict[str, Any]]] = []
        pending_cleanup: list[Tuple[BaseGateModule, Dict[str, Any]]] = []
        with self.lock:
            for req_id, lease in list(self.active_leases.items()):
                if now >= lease["expires_at"]:
                    expired_leases.append((req_id, lease))
                    self.active_leases.pop(req_id, None)

            pending_cleanup = self._evict_stale_requests_locked(now)

            self.request_timestamps[:] = [t for t in self.request_timestamps if now - t < 600]
            for k in list(self.request_timestamps_by_caller.keys()):
                b = [t for t in self.request_timestamps_by_caller[k] if now - t < 600]
                if b:
                    self.request_timestamps_by_caller[k] = b
                else:
                    self.request_timestamps_by_caller.pop(k, None)
            for k in list(self.auto_approve_timestamps_by_caller.keys()):
                b = [t for t in self.auto_approve_timestamps_by_caller[k] if now - t < 600]
                if b:
                    self.auto_approve_timestamps_by_caller[k] = b
                else:
                    self.auto_approve_timestamps_by_caller.pop(k, None)

        for cleanup_mod, cleanup_params in pending_cleanup:
            cleanup_mod.cleanup_pending_request(cleanup_params)

        for req_id, lease in expired_leases:
            mod = self.modules.get(lease["module"])
            if mod:
                try:
                    mod.revoke(req_id, lease["grant_metadata"], self.config)
                except Exception as e:
                    sys.stderr.write(f"[ha-oob-gate] Error revoking expired lease {req_id}: {e}\n")


def verify_k8s_bearer_token(auth_header: str, config: Dict[str, Any]) -> Tuple[bool, CallerInfo, str]:
    """Authenticate an HTTP caller via the Kubernetes TokenReview API."""
    if not auth_header.startswith("Bearer "):
        return False, CallerInfo(-1, -1, -1, "anonymous", False), "Missing Bearer token"
    caller_jwt = auth_header[len("Bearer "):].strip()
    try:
        tr = k8s_api_request(
            "POST",
            "/apis/authentication.k8s.io/v1/tokenreviews",
            {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": caller_jwt}},
            config=config,
        )
        status = tr.get("status", {})
        if not status.get("authenticated"):
            return False, CallerInfo(-1, -1, -1, "anonymous", False), "TokenReview: not authenticated"
        username = status.get("user", {}).get("username", "")
        allowed = set(config.get("allowed_k8s_callers", []))
        if allowed and username not in allowed:
            return False, CallerInfo(-1, -1, -1, username, False), f"Caller '{username}' is not in allowed_k8s_callers"
        return (
            True,
            CallerInfo(
                uid=0,
                gid=0,
                pid=0,
                username=username.split(":")[-1],
                is_root=False,
                source="http_k8s_token",
                k8s_identity=username,
            ),
            "ok",
        )
    except Exception as e:
        return False, CallerInfo(-1, -1, -1, "anonymous", False), f"TokenReview error: {e}"


_HTTP_SEMAPHORE = threading.BoundedSemaphore(32)


def make_http_handler(engine: GateEngine):
    class GateHTTPHandler(BaseHTTPRequestHandler):
        timeout = 15

        def handle(self):
            if not _HTTP_SEMAPHORE.acquire(timeout=5.0):
                return
            try:
                super().handle()
            finally:
                _HTTP_SEMAPHORE.release()

        def _send_json(self, code: int, payload: Dict[str, Any]):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            clean_path = parsed.path
            if clean_path == "/healthz":
                self._send_json(200, {"ok": True, "modules": sorted(engine.modules.keys())})
                return

            if clean_path in (
                "/universal_oob_auth_blueprint.yaml",
                "/blueprint.yaml",
                "/blueprint",
            ):
                bp_filename = "universal_oob_auth_blueprint.yaml"
                bp_path = os.path.join("/usr/local/libexec/ha-sudo", bp_filename)
                if os.path.isfile(bp_path):
                    with open(bp_path, "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/yaml; charset=utf-8")
                    self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._send_json(404, {"error": f"blueprint file {bp_filename} not found in /usr/local/libexec/ha-sudo"})
                return

            if clean_path == "/k8s-jit-rbac.yaml":
                rbac_path = "/usr/local/libexec/ha-sudo/k8s-jit-rbac-and-guardrails.yaml"
                if os.path.isfile(rbac_path):
                    with open(rbac_path, "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/yaml; charset=utf-8")
                    self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._send_json(404, {"error": "k8s-jit-rbac-and-guardrails.yaml not found in /usr/local/libexec/ha-sudo"})
                return

            if clean_path.startswith("/v1/requests/"):
                req_id = clean_path.rsplit("/", 1)[-1]
                qparams = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
                caller_nonce = (qparams.get("caller_nonce") or [""])[0]
                try:
                    raw_wait = float((qparams.get("wait") or ["20"])[0])
                    wait_sec = 20.0 if (math.isnan(raw_wait) or math.isinf(raw_wait)) else max(0.0, min(raw_wait, 30.0))
                except (ValueError, TypeError):
                    wait_sec = 20.0

                with engine.lock:
                    req_entry = engine.active_requests.get(req_id)
                    if not req_entry:
                        self._send_json(404, {"error": "unknown request_id"})
                        return
                    if not caller_nonce or not hmac.compare_digest(caller_nonce, req_entry.get("caller_nonce", "")):
                        self._send_json(403, {"error": "invalid caller_nonce"})
                        return

                res = engine.wait_for_resolution(req_id, timeout=wait_sec, cleanup_on_exit=False)
                if res.get("status") in ("approved", "denied", "error", "timeout", "cancelled"):
                    with engine.lock:
                        engine.active_requests.pop(req_id, None)
                self._send_json(200, res)
                return

            self._send_json(404, {"error": "not found"})

        def do_POST(self):
            try:
                content_len = int(self.headers.get("Content-Length", "0"))
            except (ValueError, TypeError):
                content_len = -1
            if content_len <= 0 or content_len > MAX_PAYLOAD_SIZE:
                self._send_json(400, {"error": "Invalid payload size"})
                return

            try:
                data = json.loads(self.rfile.read(content_len).decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "Malformed JSON"})
                return

            clean_path = urllib.parse.urlsplit(self.path).path

            # 0. Out-of-Band K8s Broker Token Bootstrap (/v1/bootstrap-k8s-token)
            if clean_path == "/v1/bootstrap-k8s-token":
                client_ip = self.client_address[0]
                approval_token_hdr = self.headers.get("X-HA-Approval-Token", "")
                origin_ok, origin_err = verify_ha_callback_origin(engine.config, client_ip, approval_token_hdr)
                if not origin_ok:
                    self._send_json(403, {"error": origin_err})
                    return

                tok_path = engine.config.get("k8s_token_path", "/etc/ha-sudo/k8s_broker.token")
                if os.path.isfile(tok_path):
                    self._send_json(403, {"error": "K8s broker token is already bootstrapped and locked."})
                    return
                candidate_tok = str(data.get("token", "")).strip()
                if not candidate_tok:
                    self._send_json(400, {"error": "Missing token"})
                    return
                try:
                    tr = k8s_api_request(
                        "POST",
                        "/apis/authentication.k8s.io/v1/tokenreviews",
                        {
                            "apiVersion": "authentication.k8s.io/v1",
                            "kind": "TokenReview",
                            "spec": {"token": candidate_tok},
                        },
                        config=engine.config,
                        override_token=candidate_tok,
                    )
                    status = tr.get("status", {})
                    username = status.get("user", {}).get("username", "")
                    if not status.get("authenticated") or username != "system:serviceaccount:jit-system:jit-elevation-broker":
                        self._send_json(
                            403,
                            {
                                "error": f"TokenReview rejected identity '{username}' (expected system:serviceaccount:jit-system:jit-elevation-broker)"
                            },
                        )
                        return
                    with engine.lock:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                        fd = os.open(tok_path, flags, 0o600)
                        try:
                            os.fchmod(fd, 0o600)
                        except OSError:
                            pass
                        with os.fdopen(fd, "w", encoding="utf-8") as f:
                            f.write(candidate_tok + "\n")
                        os.chown(tok_path, 0, 0)
                    self._send_json(
                        200,
                        {
                            "status": "ok",
                            "identity": username,
                            "saved_to": tok_path,
                        },
                    )
                except FileExistsError:
                    self._send_json(403, {"error": "K8s broker token is already bootstrapped and locked."})
                except Exception as e:
                    self._send_json(500, {"error": f"TokenReview verification failed: {e}"})
                return

            # 1. Home Assistant Callback Endpoints (/approve, /deny, /callback)
            if clean_path in ("/approve", "/deny", "/callback"):
                req_id = str(data.get("request_id", ""))
                nonce = str(data.get("nonce", ""))
                action = str(data.get("action", "")).lower()

                if clean_path == "/approve" or data.get("approved") is True or action in ("approve", "approved"):
                    action = "approve"
                elif clean_path == "/deny" or data.get("approved") is False or action in ("deny", "denied"):
                    action = "deny"
                elif clean_path == "/callback" and not action:
                    action = "approve"

                code, resp = engine.handle_ha_callback(
                    req_id=req_id,
                    nonce=nonce,
                    action=action,
                    client_ip=self.client_address[0],
                    approval_token_hdr=self.headers.get("X-HA-Approval-Token", ""),
                )
                self._send_json(code, resp)
                return

            # 2. Remote Caller Request Submission (/v1/request)
            if clean_path == "/v1/request":
                ok, caller, err = verify_k8s_bearer_token(self.headers.get("Authorization", ""), engine.config)
                if not ok:
                    self._send_json(401, {"error": err})
                    return
                module_name = str(data.get("module", "k8s_token"))
                params = data.get("params", data)
                res = engine.submit_and_wait(module_name, params, caller, wait_seconds=0)
                code = res.pop("code", 202 if res.get("status") == "pending" else 400)
                self._send_json(code, res)
                return

            # 3. Remote Lease Revocation (/v1/revoke)
            if clean_path == "/v1/revoke":
                ok, _, err = verify_k8s_bearer_token(self.headers.get("Authorization", ""), engine.config)
                if not ok:
                    self._send_json(401, {"error": err})
                    return
                req_id = str(data.get("request_id", ""))
                caller_nonce = str(data.get("caller_nonce", ""))
                if not engine.revoke_lease(req_id, caller_nonce):
                    self._send_json(404, {"error": "lease not found or invalid caller_nonce"})
                    return
                self._send_json(200, {"status": "revoked", "request_id": req_id})
                return

            # 4. Active Lease RPC (/v1/ha-proxy and generic /v1/lease-rpc)
            if clean_path in ("/v1/ha-proxy", "/v1/lease-rpc"):
                ok, caller, err = verify_k8s_bearer_token(self.headers.get("Authorization", ""), engine.config)
                if not ok:
                    self._send_json(401, {"error": err})
                    return
                rpc_action = "ha_proxy_call" if clean_path == "/v1/ha-proxy" else str(data.get("action", ""))
                expected_mod = "ha_api" if clean_path == "/v1/ha-proxy" else data.get("module")
                res = engine.dispatch_lease_rpc(
                    req_id=str(data.get("request_id", "")),
                    caller_nonce=str(data.get("caller_nonce", "")),
                    action=rpc_action,
                    payload=data,
                    caller=caller,
                    expected_module=str(expected_mod) if expected_mod else None,
                )
                code = res.pop("code", 200 if res.get("status") in ("ok", "http_error") else 400)
                self._send_json(code, res)
                return

            self._send_json(404, {"error": "not found"})

        def log_message(self, format, *args):
            return

    return GateHTTPHandler


_ROOT_SOCKET_SEMAPHORE = threading.BoundedSemaphore(16)
_USER_SOCKET_SEMAPHORE = threading.BoundedSemaphore(8)


def _is_socket_disconnected(conn: socket.socket) -> bool:
    """Non-blocking check (`select` + `MSG_PEEK | MSG_DONTWAIT`) for client EOF / `Ctrl+C`."""
    try:
        rlist, _, _ = select.select([conn], [], [], 0)
        if not rlist:
            return False
        data = conn.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        return len(data) == 0
    except BlockingIOError:
        return False
    except OSError:
        return True


def handle_unix_socket_client(conn: socket.socket, engine: GateEngine):
    """
    Handle a local IPC request over `/run/ha-sudo/daemon.sock`.
    Uses kernel `SO_PEERCRED` so caller UID/PID cannot be spoofed, newline-delimited
    JSON framing (`ha_oob_gate.ipc`), and reserves a dedicated semaphore pool for
    root PAM callers so unprivileged users can never starve administrative `sudo` sessions.
    """
    try:
        caller = get_socket_peer_caller(conn)
    except Exception:
        conn.close()
        return

    sem = _ROOT_SOCKET_SEMAPHORE if caller.is_root else _USER_SOCKET_SEMAPHORE
    if not sem.acquire(timeout=5.0):
        try:
            send_json_frame(conn, {"status": "error", "message": "Too many concurrent local IPC requests"})
        except Exception:
            pass
        finally:
            conn.close()
        return

    try:
        conn.settimeout(2.0)
        try:
            req = recv_json_frame(conn, max_bytes=MAX_PAYLOAD_SIZE)
        except FrameTooLargeError as e:
            send_json_frame(conn, {"status": "error", "message": str(e)})
            return
        if req is None:
            return
        conn.settimeout(30.0)
        action = str(req.get("action", ""))

        # 1. Module fast-path IPC actions (e.g. `check_ticket` handled by `PamSudoModule`)
        for mod in engine.modules.values():
            handled = mod.handle_ipc_action(action, req, caller, engine.config)
            if handled is not None:
                send_json_frame(conn, handled)
                return

        # 2. Module elevation request (`module_request` or module-specific alias like `request_elevation`)
        if action == "module_request" or action in engine._ipc_aliases:
            default_mod = engine._ipc_aliases.get(action, "")
            module_name = str(req.get("module") or default_mod)
            params = dict(req.get("params", req))

            mod = engine.modules.get(module_name)
            if mod is not None:
                if mod.requires_root_caller and not caller.is_root:
                    send_json_frame(
                        conn,
                        {
                            "status": "error",
                            "code": 403,
                            "message": f"Security violation: {module_name} requires root caller (got UID {caller.uid})",
                        },
                    )
                    return
                params = mod.prepare_ipc_params(params, caller, engine.config)

            res = engine.submit_and_wait(
                module_name,
                params,
                caller,
                wait_seconds=None,
                disconnect_check=lambda: _is_socket_disconnected(conn),
            )
            if res.get("status") != "cancelled":
                send_json_frame(conn, res)
            return

        # 3. Active Lease RPC (`ha_proxy_call` or generic `lease_rpc`)
        if action in ("ha_proxy_call", "lease_rpc"):
            rpc_action = "ha_proxy_call" if action == "ha_proxy_call" else str(req.get("rpc_action", ""))
            expected_mod = "ha_api" if action == "ha_proxy_call" else req.get("module")
            res = engine.dispatch_lease_rpc(
                req_id=str(req.get("request_id", "")),
                caller_nonce=str(req.get("caller_nonce", "")),
                action=rpc_action,
                payload=req,
                caller=caller,
                expected_module=str(expected_mod) if expected_mod else None,
            )
            send_json_frame(conn, res)
            return

        # 4. Active Lease Revocation (`revoke`)
        if action == "revoke":
            req_id = str(req.get("request_id", ""))
            ok = engine.revoke_lease(req_id, str(req.get("caller_nonce", "")))
            send_json_frame(conn, {"status": "revoked" if ok else "not_found"})
            return

        send_json_frame(conn, {"status": "error", "message": f"Unknown action '{action}'"})
    except Exception as e:
        try:
            send_json_frame(conn, {"status": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        sem.release()
        conn.close()


def run_daemon(config: Dict[str, Any], enable_unix_socket: bool = True):
    """Start the persistent `ha-oob-gate` daemon (HTTP/HTTPS listener + Unix socket + GC loop)."""
    engine = GateEngine(config)
    port = int(config["listen_port"])

    def gc_loop():
        while True:
            time.sleep(15)
            engine.sweep_expired_leases()

    threading.Thread(target=gc_loop, daemon=True).start()

    handler_cls = make_http_handler(engine)
    http_server = ThreadingHTTPServer(("0.0.0.0", port), handler_cls)
    http_server.daemon_threads = True
    tls_active = wrap_http_server_tls(http_server, config)
    proto_label = "HTTPS (TLSv1.2+)" if tls_active else "HTTP"
    sys.stdout.write(
        f"[ha-oob-gate] Started {proto_label} listener on :{port} "
        f"(Modules: {sorted(engine.modules.keys())}, Trusted HA IP: {config.get('ha_trusted_ip')})\n"
    )
    sys.stdout.flush()

    if not enable_unix_socket:
        http_server.serve_forever()
        return

    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    ticket_dir = config["ticket_dir"]
    socket_path = config["socket_path"]
    os.makedirs(ticket_dir, exist_ok=True)
    os.chmod(ticket_dir, 0o755)
    for subdir_name in ("tickets", "staged"):
        sub_path = os.path.join(ticket_dir, subdir_name)
        os.makedirs(sub_path, exist_ok=True)
        os.chmod(sub_path, 0o700)

    if os.path.exists(socket_path):
        try:
            os.remove(socket_path)
        except OSError:
            pass

    ipc_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ipc_sock.bind(socket_path)
    os.chmod(socket_path, 0o666)
    ipc_sock.listen(16)
    sys.stdout.write(f"[ha-oob-gate] Listening on SO_PEERCRED Unix socket at {socket_path}\n")
    sys.stdout.flush()

    try:
        while True:
            conn, _ = ipc_sock.accept()
            t = threading.Thread(target=handle_unix_socket_client, args=(conn, engine), daemon=True)
            t.start()
    except KeyboardInterrupt:
        sys.stdout.write("\n[ha-oob-gate] Shutting down...\n")
    finally:
        if os.path.exists(socket_path):
            try:
                os.remove(socket_path)
            except OSError:
                pass
