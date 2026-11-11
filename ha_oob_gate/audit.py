"""
audit.py - Structured JSON Security Audit Logger for ha_oob_gate.

Emits single-line structured JSON records to stdout/journald (and an optional
root-only `0600` audit log file) for every security-relevant gate event while
unconditionally redacting secrets, tokens, keys, passwords, and capability nonces.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
import threading
from typing import Any, Dict, Optional

REDACTED_AUDIT_KEYS = frozenset(
    {
        "token",
        "value",
        "nonce",
        "approve_nonce",
        "deny_nonce",
        "caller_nonce",
        "hmac_key",
        "_hmac_key",
        "ha_admin_token",
        "ha_approval_token",
        "password",
        "passwd",
        "secret",
        "private_key",
        "private_key_pem",
        "authorization",
        "content_b64",
    }
)

REDACTED_KEY_SUFFIXES = (
    "_token",
    "_secret",
    "_key",
    "_nonce",
    "_password",
    "_passwd",
    "_pem",
)

REDACTED_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "authorization",
    "private_key",
)

_AUDIT_FILE_LOCK = threading.Lock()


def is_sensitive_audit_key(key: str) -> bool:
    """Return True if `key` names a secret, credential, key, password, or nonce."""
    low = key.strip().lower()
    if low in REDACTED_AUDIT_KEYS:
        return True
    if low.endswith(REDACTED_KEY_SUFFIXES):
        return True
    return any(sub in low for sub in REDACTED_KEY_SUBSTRINGS)


def scrub_audit_payload(obj: Any) -> Any:
    """Recursively redact sensitive secret/nonce keys before logging."""
    if isinstance(obj, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in obj.items():
            key_str = str(k)
            if is_sensitive_audit_key(key_str):
                cleaned[key_str] = "[REDACTED]"
            else:
                cleaned[key_str] = scrub_audit_payload(v)
        return cleaned
    if isinstance(obj, (list, tuple)):
        return [scrub_audit_payload(item) for item in obj]
    if isinstance(obj, bytes):
        return f"<bytes:{len(obj)}>"
    return obj


def emit_audit_event(
    event: str,
    config: Optional[Dict[str, Any]] = None,
    sink_buffer: Optional[Any] = None,
    **fields: Any,
) -> Dict[str, Any]:
    """
    Build, scrub, and emit a structured single-line JSON audit record.
    Never raises exceptions to callers on I/O failures.
    """
    cfg = config or {}
    record: Dict[str, Any] = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
    }
    record.update(scrub_audit_payload(fields))

    if sink_buffer is not None:
        try:
            sink_buffer.append(record)
        except Exception:
            pass

    if not cfg.get("audit_log_enabled", True):
        return record

    line = json.dumps(record, separators=(",", ":"), sort_keys=True)

    if cfg.get("audit_stdout", True):
        try:
            sys.stdout.write(f"[ha-oob-gate AUDIT] {line}\n")
            sys.stdout.flush()
        except Exception:
            pass

    audit_path = str(cfg.get("audit_log_path") or "").strip()
    if audit_path:
        try:
            parent = os.path.dirname(audit_path)
            if parent:
                os.makedirs(parent, mode=0o700, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            with _AUDIT_FILE_LOCK:
                fd = os.open(audit_path, flags, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception as e:
            sys.stderr.write(f"[ha-oob-gate] Warning: failed writing audit_log_path {audit_path}: {e}\n")

    return record
