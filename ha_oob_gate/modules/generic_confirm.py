"""
generic_confirm.py - Universal Human-in-the-Loop Yes/No Approval Gate Module.

Allows any script, CI/CD job, Terraform/Ansible workflow, or AI agent to pause
and require an explicit [Approve] / [Deny] tap on the user's phone before proceeding.
Returns an HMAC-signed approval receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict, Tuple

from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec


class GenericConfirmModule(BaseGateModule):
    name = "generic_confirm"
    description = "Universal human-in-the-loop Yes/No approval gate for scripts, CI/CD, and agents"
    default_ttl_seconds = 300
    requires_root_caller = False

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        summary = str(params.get("summary", params.get("command", ""))).strip()
        reason = str(params.get("reason", "")).strip()
        if not summary:
            return False, "Missing action --summary"
        if not reason:
            return False, "Missing --reason"
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        summary = sanitize_text(params.get("summary", params.get("command", "")), max_len=400)
        reason = sanitize_text(params.get("reason", ""), max_len=300)
        caller_disp = caller.k8s_identity or caller.username

        title = f"🛡️ Confirm Action [{hostname}] [{verify_code}]"
        message = (
            f"Host: {hostname}\n"
            f"Caller: {caller_disp}\n"
            f"Reason: {reason}\n\n"
            f"Proposed Action:\n{summary}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Confirm [{verify_code}]",
            deny_title="Reject",
            approved_title=f"✅ Action Confirmed [{verify_code}]",
            approved_message=f"Confirmed for {caller_disp}: {summary}",
            denied_title=f"❌ Action Rejected [{verify_code}]",
            denied_message=f"Rejected for {caller_disp}: {summary}",
            timeout_title=f"⏱️ Confirmation Timed Out [{verify_code}]",
            timeout_message=f"Expired without response: {summary}",
            command_summary=summary,
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        ts = int(time.time())
        summary = sanitize_text(params.get("summary", params.get("command", "")), max_len=400)
        hmac_key: bytes = config["_hmac_key"]
        receipt = hmac.new(
            hmac_key,
            f"confirm:{req_id}:{caller.username}:{ts}:{summary}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {
            "status": "approved",
            "approved_at": ts,
            "receipt_hmac": receipt,
        }
