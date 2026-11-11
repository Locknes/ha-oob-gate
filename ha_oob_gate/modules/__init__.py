"""
Pluggable Gate Module interface (BaseGateModule) and dynamic module loader.
To add a new OOB gate module, drop a Python file into this directory that
subclasses BaseGateModule and sets a unique `name` attribute.
"""

from __future__ import annotations

import importlib
import inspect
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass
class CallerInfo:
    """Kernel- or TokenReview-verified identity of the requesting caller."""

    uid: int
    gid: int
    pid: int
    username: str
    is_root: bool
    source: str = "unix_socket"  # "unix_socket" or "http_k8s_token" or "http_api_key"
    k8s_identity: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationSpec:
    """Standardized Home Assistant actionable notification payload fields."""

    title: str
    message: str
    approve_title: str = "Approve"
    deny_title: str = "Deny"
    approved_title: str = ""
    approved_message: str = ""
    denied_title: str = ""
    denied_message: str = ""
    timeout_title: str = ""
    timeout_message: str = ""
    command_summary: str = ""
    icon: str = ""
    color: str = ""


class BaseGateModule:
    """
    Abstract base class for all Out-of-Band (OOB) Authorization Gate Modules.
    """

    name: str = ""
    description: str = ""
    default_ttl_seconds: int = 900
    requires_root_caller: bool = False
    run_grant_async: bool = False
    ipc_elevation_alias: Optional[str] = None

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Pre-flight validation before dispatching a push notification to Home Assistant.
        Returns `(True, "ok")` or `(False, "error reason")`.
        """
        return True, "ok"

    def can_auto_approve(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> bool:
        """
        Optional hook allowing a module to approve pre-authorized low-risk requests
        without sending a mobile push notification (for example, a GitHub repository
        explicitly tagged `oob-read` or `oob-write` in `github_token`).
        """
        return False

    def retain_rate_limit_on_validate_error(self, params: Dict[str, Any]) -> bool:
        """
        Return True if `validate()` consumed external upstream API quota prior to
        rejection and should retain its caller rate-limit slot.
        """
        return False

    def cleanup_pending_request(self, params: Dict[str, Any]) -> None:
        """Clean up any staged artifacts if a request fails, times out, or is cancelled before `grant()`."""
        return None

    def prepare_ipc_params(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Allow root-only IPC modules (such as `pam_sudo`) to populate/override params from kernel `/proc`."""
        return params

    def handle_ipc_action(
        self,
        action: str,
        req: Dict[str, Any],
        caller: CallerInfo,
        config: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Handle a module-specific fast-path IPC action (such as `check_ticket`), or return `None`."""
        return None

    def handle_lease_rpc(
        self,
        action: str,
        payload: Dict[str, Any],
        lease: Dict[str, Any],
        caller: Optional[CallerInfo],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute an authenticated RPC against an active lease owned by this module."""
        return {
            "status": "error",
            "code": 400,
            "message": f"Module '{self.name}' does not support lease RPC '{action}'",
        }

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        """Build the actionable push notification displayed on the Home Assistant mobile app."""
        raise NotImplementedError

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Executed ONLY after Home Assistant cryptographically verifies user approval.
        Returns a dictionary of grant metadata/credentials sent back to the caller.
        """
        raise NotImplementedError

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        """
        Clean up any ephemeral tickets, ServiceAccounts, or processes when the lease
        expires or when explicit revocation is requested.
        """
        return True


def discover_modules(enabled_names: Optional[list[str]] = None) -> Dict[str, BaseGateModule]:
    """
    Dynamically discover and instantiate all BaseGateModule subclasses in this package.
    """
    registry: Dict[str, BaseGateModule] = {}
    pkg_dir = os.path.dirname(os.path.abspath(__file__))

    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        mod_basename = fname[:-3]
        if mod_basename == "example_module" and (not enabled_names or "example_custom" not in enabled_names):
            continue
        full_mod_name = f"ha_oob_gate.modules.{mod_basename}"
        try:
            mod = importlib.import_module(full_mod_name)
        except Exception:
            mod = importlib.import_module(f".{mod_basename}", package=__package__)

        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, BaseGateModule) and obj is not BaseGateModule and getattr(obj, "name", ""):
                instance: BaseGateModule = obj()
                if enabled_names is None or instance.name in enabled_names:
                    registry[instance.name] = instance

    return registry
