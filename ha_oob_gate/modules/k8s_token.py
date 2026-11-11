"""
k8s_token.py - Kubernetes Ephemeral JIT ServiceAccount & Scoped RBAC Token Module.

When approved via Home Assistant push notification, creates an ephemeral
ServiceAccount (`jit-oob-<id>`), binds the requested role to target namespaces,
mints a short-lived `TokenRequest` JWT, and automatically deletes the
ServiceAccount + RoleBindings upon TTL expiry or `oob-auth revoke`.
"""

from __future__ import annotations

import datetime
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
        reason = sanitize_text(params.get("reason", "Maintenance"), max_len=250)
        max_ttl = int(config.get("k8s_ttl_seconds", self.default_ttl_seconds))
        eff_ttl = max(60, min(int(params.get("ttl_seconds") or max_ttl), max_ttl))
        ttl_min = max(1, eff_ttl // 60)

        ns_display = sanitize_text(", ".join(namespaces), max_len=200)
        title = f"🔐 K8s JIT Token ({role}) [{verify_code}]"
        caller_disp = caller.k8s_identity or caller.username

        message = (
            f"Caller: {caller_disp}\n"
            f"Role: {role}\n"
            f"Namespaces: {ns_display}\n"
            f"Lease TTL: {ttl_min} minutes\n\n"
            f"Reason:\n{reason}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Grant {ttl_min}m [{verify_code}]",
            deny_title="Deny",
            approved_title=f"✅ K8s Token Granted [{verify_code}]",
            approved_message=f"Minted {ttl_min}m {role} token in [{ns_display}] for {reason}",
            denied_title=f"❌ K8s Token Denied [{verify_code}]",
            denied_message=f"Rejected {role} in [{ns_display}]",
            timeout_title=f"⏱️ K8s Token Timed Out [{verify_code}]",
            timeout_message=f"Expired without response: {role} in [{ns_display}]",
            command_summary=f"{role} on {ns_display}: {reason}",
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
        short_id = req_id.replace("-", "")[:12]
        sa_name = f"{sa_prefix}{short_id}"
        exp_ts = int(time.time()) + ttl_seconds
        exp_iso = datetime.datetime.fromtimestamp(exp_ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        meta_common = {
            "labels": {
                f"{label_domain}/managed": "true",
                f"{label_domain}/request-id": short_id,
            },
            "annotations": {
                f"{label_domain}/expires-at": str(exp_ts),
                f"{label_domain}/expires-iso": exp_iso,
                f"{label_domain}/reason": sanitize_text(params.get("reason", ""), max_len=200),
                f"{label_domain}/namespaces": ",".join(namespaces),
            },
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
