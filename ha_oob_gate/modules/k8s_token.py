"""
k8s_token.py - Kubernetes Ephemeral JIT ServiceAccount & Scoped RBAC Token Module.

When approved via Home Assistant push notification, creates an ephemeral
ServiceAccount (`jit-oob-<id>`), binds the requested role to target namespaces,
mints a short-lived `TokenRequest` JWT, and automatically deletes the
ServiceAccount + RoleBindings upon TTL expiry or `oob-auth revoke`.
"""

from __future__ import annotations

import datetime
import re
import time
from typing import Any, Dict, List, Tuple

from ..k8s_client import k8s_api_request
from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec

DEFAULT_ALLOWED_ROLES = {
    "view",
    "jit-workload-operator",
    "jit-storage-operator",
}

DEFAULT_PROTECTED_NAMESPACES = {
    "jit-system",
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "cert-manager",
}

# DNS-1123 subdomain regex matching valid Kubernetes PersistentVolumeClaim names
PVC_NAME_REGEX = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
MAX_ALLOWED_PVCS = 8
MAX_SA_NAME_LENGTH = 253


def _normalize_allow_pvcs(raw: Any) -> Tuple[bool, List[str], str]:
    """Validate and deduplicate optional `allow_pvcs` PVC claimName allowlist."""
    if raw is None or raw == []:
        return True, [], "ok"
    if not isinstance(raw, list):
        return False, [], "allow_pvcs must be a list of PersistentVolumeClaim names"
    cleaned: List[str] = []
    seen = set()
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            return False, [], "allow_pvcs entries must be non-empty strings"
        name = item.strip()
        if "--" in name:
            return (
                False,
                [],
                f"PVC claimName '{name}' cannot contain '--' (reserved delimiter for CEL guardrail pinning)",
            )
        if not PVC_NAME_REGEX.fullmatch(name) or len(name) > 200:
            return (
                False,
                [],
                f"Invalid PVC claimName '{name}': must be a valid lowercase DNS-1123 name without wildcards",
            )
        if name not in seen:
            seen.add(name)
            cleaned.append(name)
    if len(cleaned) > MAX_ALLOWED_PVCS:
        return False, [], f"At most {MAX_ALLOWED_PVCS} PVCs may be pinned in a single k8s_token grant"
    return True, cleaned, "ok"


def build_jit_sa_name(sa_prefix: str, short_id: str, allow_pvcs: List[str]) -> str:
    """
    Build the ephemeral ServiceAccount name in `jit-system`.
    When `allow_pvcs` is empty, preserves legacy `<prefix><short_id>` (zero PVC mounts permitted).
    When `allow_pvcs` is non-empty, encodes each exact claimName as `--pvc--<claimName>` terminated
    by `--end` so kube-apiserver CEL guardrails can verify exact claim membership without spoofing.
    """
    base = f"{sa_prefix}{short_id}"
    if not allow_pvcs:
        return base
    encoded = "".join(f"--pvc--{pvc}" for pvc in allow_pvcs)
    return f"{base}{encoded}--end"


class K8sTokenModule(BaseGateModule):
    name = "k8s_token"
    description = "Short-lived, namespace-scoped Kubernetes ServiceAccount JWT lease"
    default_ttl_seconds = 1800
    requires_root_caller = False

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        role = str(params.get("role", "jit-workload-operator")).strip()
        namespaces = params.get("namespaces", ["default"])
        reason = str(params.get("reason", "")).strip()

        allowed_roles = set(config.get("k8s_allowed_roles", DEFAULT_ALLOWED_ROLES))
        protected_ns = set(config.get("k8s_protected_namespaces", DEFAULT_PROTECTED_NAMESPACES))

        if role not in allowed_roles:
            return False, f"Role '{role}' is not in allowed roles: {sorted(allowed_roles)}"
        if not isinstance(namespaces, list) or not namespaces:
            return False, "namespaces must be a non-empty list"
        for ns in namespaces:
            if not isinstance(ns, str) or not ns.strip():
                return False, "Invalid namespace entry"
            clean_ns = ns.strip()
            if clean_ns == "*" or "*" in clean_ns:
                return (
                    False,
                    "Wildcard namespace '*' is forbidden to prevent cluster-wide read exposure; specify explicit workload namespaces",
                )
            if clean_ns in protected_ns or clean_ns.startswith("kube-"):
                return False, f"Namespace '{clean_ns}' is a protected control-plane namespace and cannot be targeted"

        pvc_ok, allow_pvcs, pvc_err = _normalize_allow_pvcs(params.get("allow_pvcs"))
        if not pvc_ok:
            return False, pvc_err
        if allow_pvcs and role == "view":
            return False, "allow_pvcs cannot be combined with read-only 'view' role"
        if allow_pvcs:
            sa_prefix = str(config.get("k8s_jit_sa_prefix", "jit-oob-"))
            candidate_sa = build_jit_sa_name(sa_prefix, "0" * 12, allow_pvcs)
            if len(candidate_sa) > MAX_SA_NAME_LENGTH:
                return (
                    False,
                    f"Encoded ServiceAccount name for allow_pvcs exceeds Kubernetes {MAX_SA_NAME_LENGTH}-char limit",
                )

        if not reason:
            return False, "A human-readable --reason is required"
        if len(reason) > 300:
            return False, "reason exceeds maximum displayable length (300 chars)"
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        role = sanitize_text(params.get("role", "jit-workload-operator"), max_len=64)
        namespaces: List[str] = params.get("namespaces", [])
        _, allow_pvcs, _ = _normalize_allow_pvcs(params.get("allow_pvcs"))
        reason = sanitize_text(params.get("reason", "Maintenance"), max_len=250)
        max_ttl = int(config.get("k8s_ttl_seconds", self.default_ttl_seconds))
        eff_ttl = max(60, min(int(params.get("ttl_seconds") or max_ttl), max_ttl))
        ttl_min = max(1, eff_ttl // 60)

        ns_display = sanitize_text(", ".join(namespaces), max_len=200)
        pvc_display = sanitize_text(", ".join(allow_pvcs), max_len=200) if allow_pvcs else ""
        title_role = f"{role} + PVC" if allow_pvcs else role
        title = f"🔐 K8s JIT Token ({title_role}) [{verify_code}]"
        caller_disp = caller.k8s_identity or caller.username

        pvc_line = f"Allowed PVCs: {pvc_display}\n" if allow_pvcs else ""
        pvc_suffix = f" (PVCs: {pvc_display})" if allow_pvcs else ""

        message = (
            f"Caller: {caller_disp}\n"
            f"Role: {role}\n"
            f"Namespaces: {ns_display}\n"
            f"{pvc_line}"
            f"Lease TTL: {ttl_min} minutes\n\n"
            f"Reason:\n{reason}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Grant {ttl_min}m [{verify_code}]",
            deny_title="Deny",
            approved_title=f"✅ K8s Token Granted [{verify_code}]",
            approved_message=f"Minted {ttl_min}m {role} token in [{ns_display}]{pvc_suffix} for {reason}",
            denied_title=f"❌ K8s Token Denied [{verify_code}]",
            denied_message=f"Rejected {role} in [{ns_display}]{pvc_suffix}",
            timeout_title=f"⏱️ K8s Token Timed Out [{verify_code}]",
            timeout_message=f"Expired without response: {role} in [{ns_display}]{pvc_suffix}",
            command_summary=f"{role} on {ns_display}{pvc_suffix}: {reason}",
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        max_ttl = int(config.get("k8s_ttl_seconds", self.default_ttl_seconds))
        ttl_seconds = max(60, min(int(ttl_seconds or max_ttl), max_ttl))
        broker_ns = str(config.get("k8s_broker_namespace", "jit-system"))
        sa_prefix = str(config.get("k8s_jit_sa_prefix", "jit-oob-"))
        label_domain = str(config.get("k8s_label_domain", "oob.gate")).rstrip("/")
        role = str(params["role"])
        namespaces: List[str] = list(params["namespaces"])
        _, allow_pvcs, _ = _normalize_allow_pvcs(params.get("allow_pvcs"))
        short_id = req_id.replace("-", "")[:12]
        sa_name = build_jit_sa_name(sa_prefix, short_id, allow_pvcs)
        exp_ts = int(time.time()) + ttl_seconds
        exp_iso = datetime.datetime.fromtimestamp(exp_ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        annotations = {
            f"{label_domain}/expires-at": str(exp_ts),
            f"{label_domain}/expires-iso": exp_iso,
            f"{label_domain}/reason": sanitize_text(params.get("reason", ""), max_len=200),
            f"{label_domain}/namespaces": ",".join(namespaces),
        }
        if allow_pvcs:
            annotations[f"{label_domain}/allowed-pvcs"] = ",".join(allow_pvcs)

        meta_common = {
            "labels": {
                f"{label_domain}/managed": "true",
                f"{label_domain}/request-id": short_id,
            },
            "annotations": annotations,
        }

        rollback_metadata = {
            "sa_name": sa_name,
            "broker_namespace": broker_ns,
            "namespaces": namespaces,
        }

        try:
            # 1. Create ephemeral ServiceAccount in jit-system
            k8s_api_request(
                "POST",
                f"/api/v1/namespaces/{broker_ns}/serviceaccounts",
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": sa_name, "namespace": broker_ns, **meta_common},
                },
                config=config,
            )

            # 2. Create ClusterRoleBinding only for jit-storage-operator (PV/StorageClass only, zero Pod/ConfigMap read)
            if role == "jit-storage-operator":
                k8s_api_request(
                    "POST",
                    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                    {
                        "apiVersion": "rbac.authorization.k8s.io/v1",
                        "kind": "ClusterRoleBinding",
                        "metadata": {"name": sa_name, **meta_common},
                        "roleRef": {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "ClusterRole",
                            "name": "jit-storage-operator",
                        },
                        "subjects": [{"kind": "ServiceAccount", "name": sa_name, "namespace": broker_ns}],
                    },
                    config=config,
                )

            ns_role = "jit-workload-operator" if role == "jit-storage-operator" else role
            for ns in namespaces:
                k8s_api_request(
                    "POST",
                    f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings",
                    {
                        "apiVersion": "rbac.authorization.k8s.io/v1",
                        "kind": "RoleBinding",
                        "metadata": {"name": sa_name, "namespace": ns, **meta_common},
                        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": ns_role},
                        "subjects": [{"kind": "ServiceAccount", "name": sa_name, "namespace": broker_ns}],
                    },
                    config=config,
                )

            # 3. Mint short-lived JWT via TokenRequest
            tok_resp = k8s_api_request(
                "POST",
                f"/api/v1/namespaces/{broker_ns}/serviceaccounts/{sa_name}/token",
                {
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "TokenRequest",
                    "spec": {"expirationSeconds": ttl_seconds},
                },
                config=config,
            )
            jwt_token = tok_resp["status"]["token"]
        except Exception:
            try:
                self.revoke(req_id, rollback_metadata, config)
            except Exception:
                pass
            raise

        return {
            "status": "approved",
            "token": jwt_token,
            "service_account": f"{broker_ns}:{sa_name}",
            "sa_name": sa_name,
            "broker_namespace": broker_ns,
            "role": role,
            "namespaces": namespaces,
            "allowed_pvcs": allow_pvcs,
            "expires_at": exp_iso,
            "ttl_seconds": ttl_seconds,
        }

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        sa_name = grant_metadata.get("sa_name")
        broker_ns = grant_metadata.get("broker_namespace", config.get("k8s_broker_namespace", "jit-system"))
        namespaces = grant_metadata.get("namespaces", [])
        if not sa_name:
            return False

        for ns in namespaces:
            if ns != "*":
                try:
                    k8s_api_request(
                        "DELETE",
                        f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{sa_name}",
                        config=config,
                    )
                except Exception:
                    pass
        try:
            k8s_api_request(
                "DELETE",
                f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{sa_name}",
                config=config,
            )
        except Exception:
            pass
        try:
            k8s_api_request(
                "DELETE",
                f"/api/v1/namespaces/{broker_ns}/serviceaccounts/{sa_name}",
                config=config,
            )
        except Exception:
            pass
        return True
