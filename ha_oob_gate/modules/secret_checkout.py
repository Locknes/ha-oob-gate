"""
secret_checkout.py - One-Time Vault Secret Checkout Module.

Allows requesting temporary read access to a named secret key stored in a dedicated
vault JSON file or Kubernetes Secret mount upon mobile approval.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Tuple

from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec

PROTECTED_INTERNAL_KEYS = frozenset(
    {
        "ha_admin_token",
        "ha_approval_token",
        "k8s_broker_token",
        "hmac_key",
        "github_app_pem",
        "github_push_pat",
    }
)


class SecretCheckoutModule(BaseGateModule):
    name = "secret_checkout"
    description = "One-time secret key checkout upon mobile approval"
    default_ttl_seconds = 300
    requires_root_caller = False

    def _load_vault(self, config: Dict[str, Any]) -> Dict[str, str]:
        vault_path = config.get("vault_path", "/etc/ha-sudo/vault.json")
        if not os.path.exists(vault_path):
            return {}
        try:
            with open(vault_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {str(k): str(v) for k, v in data.items()}
        except Exception:
            return {}

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        secret_key = str(params.get("key", "")).strip()
        reason = str(params.get("reason", "")).strip()
        if secret_key.lower() in PROTECTED_INTERNAL_KEYS:
            return (
                False,
                f"Security policy: internal gate credential '{secret_key}' cannot be checked out raw; use the dedicated filtered gate module",
            )
        vault = self._load_vault(config)
        if not secret_key or not reason or secret_key not in vault:
            return False, "Invalid secret checkout request"
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        secret_key = sanitize_text(params.get("key", ""), max_len=128)
        reason = sanitize_text(params.get("reason", ""), max_len=300)
        caller_disp = caller.k8s_identity or caller.username

        title = f"🗝️ Secret Checkout: {secret_key} [{verify_code}]"
        message = (
            f"Host: {hostname}\n"
            f"Caller: {caller_disp}\n"
            f"Secret Key: {secret_key}\n\n"
            f"Reason:\n{reason}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Release Secret [{verify_code}]",
            deny_title="Deny",
            approved_title=f"✅ Secret Released: {secret_key}",
            approved_message=f"Checked out '{secret_key}' to {caller_disp}: {reason}",
            denied_title=f"❌ Secret Checkout Denied: {secret_key}",
            denied_message=f"Rejected checkout of '{secret_key}' for {caller_disp}",
            timeout_title=f"⏱️ Secret Checkout Timed Out: {secret_key}",
            timeout_message=f"Expired without response: '{secret_key}'",
            command_summary=f"secret:{secret_key}",
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        vault = self._load_vault(config)
        key = str(params["key"]).strip()
        if key not in vault:
            return {"status": "error", "message": "Secret not found"}
        return {
            "status": "approved",
            "key": key,
            "value": vault[key],
        }
