"""
example_module.py - Starter Template for Custom Community Gate Modules.

To create a new Out-of-Band (OOB) gate module:
1. Copy this file to `ha_oob_gate/modules/<your_module>.py`.
2. Set a unique `name` on your `BaseGateModule` subclass.
3. Add the module name to `enabled_modules` in `/etc/ha-sudo/config.json`.
   No changes to Home Assistant or `daemon.py` are required!
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec


class ExampleCustomModule(BaseGateModule):
    name = "example_custom"
    description = "Starter template demonstrating how to add a new OOB gate module"
    default_ttl_seconds = 600
    requires_root_caller = False

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        target = str(params.get("target", "")).strip()
        if not target:
            return False, "Missing 'target' parameter"
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        target = sanitize_text(params.get("target", ""), max_len=200)
        return NotificationSpec(
            title=f"🔌 Custom Gate [{verify_code}]",
            message=f"Caller {caller.username} on {hostname} requested access to: {target}",
            approve_title=f"Approve [{verify_code}]",
            deny_title="Deny",
            command_summary=target,
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {"status": "approved", "target": params["target"], "ttl_seconds": ttl_seconds}
