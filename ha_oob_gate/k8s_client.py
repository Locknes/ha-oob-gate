"""
k8s_client.py - Shared zero-dependency Kubernetes REST API & TokenReview client.

Used by both `daemon.py` (for HTTP `TokenReview` caller authentication and broker
token bootstrap) and `modules/k8s_token.py` (for JIT ServiceAccount & RBAC leases),
keeping `daemon.py` decoupled from concrete gate modules.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
HOST_BROKER_TOKEN_PATH = "/etc/ha-sudo/k8s_broker.token"
HOST_CA_PATH = "/etc/ha-sudo/k8s_ca.crt"
FALLBACK_SYSTEM_CA_PATHS = (
    "/etc/kubernetes/pki/ca.crt",
)
DEFAULT_HOST_APISERVER = os.environ.get("K8S_APISERVER_URL", "https://127.0.0.1:6443")


def k8s_api_request(
    method: str,
    path: str,
    body: Any = None,
    config: Optional[Dict[str, Any]] = None,
    override_token: str = "",
) -> Dict[str, Any]:
    """Invoke the Kubernetes API server using host broker token or in-cluster ServiceAccount credentials."""
    cfg = config or {}
    in_cluster = os.path.isfile(f"{SA_DIR}/token")
    default_api = "https://kubernetes.default.svc" if in_cluster else DEFAULT_HOST_APISERVER
    default_tok = f"{SA_DIR}/token" if in_cluster else HOST_BROKER_TOKEN_PATH
    default_ca = f"{SA_DIR}/ca.crt" if in_cluster else HOST_CA_PATH

    apiserver = str(cfg.get("k8s_apiserver") or default_api)
    token_path = str(cfg.get("k8s_token_path") or default_tok)
    ca_path = str(cfg.get("k8s_ca_path") or default_ca)

    if override_token:
        token = override_token.strip()
    else:
        if not os.path.isfile(token_path):
            raise RuntimeError(
                f"Kubernetes broker token not found at {token_path}. "
                "Bootstrap the jit-elevation-broker token first."
            )
        with open(token_path, "r", encoding="utf-8") as f:
            token = f.read().strip()

    resolved_ca = ""
    if os.path.isfile(ca_path) and os.path.getsize(ca_path) > 0:
        resolved_ca = ca_path
    else:
        for alt_ca in FALLBACK_SYSTEM_CA_PATHS:
            if os.path.isfile(alt_ca) and os.path.getsize(alt_ca) > 0:
                resolved_ca = alt_ca
                break
    if not resolved_ca:
        raise RuntimeError(
            f"Kubernetes CA certificate not found at {ca_path}. "
            "Refusing unverified TLS connection to Kubernetes API server."
        )

    ctx = ssl.create_default_context(cafile=resolved_ca)
    url = f"{apiserver.rstrip('/')}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        if method == "DELETE" and e.code == 404:
            return {}
        raise RuntimeError(f"K8s API {method} {path} failed ({e.code}): {err_body}") from e
