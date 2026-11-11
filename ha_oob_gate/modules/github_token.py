"""
GitHub Token Broker Module (`github_token`) — Hybrid Tag-Based GitHub App + Root Vault PAT Gate.

Supports two complementary modes:
1. **GitHub App + Tag/Custom Property Policy (Recommended for Organizations & Multi-Repo):**
   - Root daemon holds `/etc/ha-sudo/secrets/github_app.pem` (mode `0400 root:root`).
   - Before minting a token for `owner/repo`, the daemon queries GitHub's API for the
     repository's **Topics** (`oob-read`, `oob-write`, `oob-oob`, `oob-deny`) and
     **Organization Custom Properties** (`oob_access`: `read`, `write`, `oob`, `none`).
   - Enforces policy:
     - `deny` / `none` -> Immediately blocked (`403`).
     - `read` -> Silent 1-hour single-repo read token (`contents: read`); write is blocked.
     - `oob` -> Silent 1-hour single-repo read token; write requires **Home Assistant Phone Approval**.
     - `write` -> Silent 1-hour single-repo read/write token (`contents: write`).
   - Mints a downscoped 1-hour GitHub App Installation Token restricted strictly to
     `"repositories": [repo_name]` and revokes it via `DELETE /installation/token` on lease expiry.

2. **Hybrid Vault PAT Fallback (`/etc/ha-sudo/secrets/github_push_pat`):**
   - If no GitHub App is configured yet and `allow_vault_pat_fallback` is enabled, falls back
     to checking out `/etc/ha-sudo/secrets/github_push_pat` (`0400 root:root`) gated by
     **Home Assistant Phone Approval** on every request.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__
from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec

VALID_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_github_app_jwt(
    app_id: str,
    private_key_path: str = "",
    private_key_pem: str = "",
    now: Optional[int] = None,
) -> str:
    """
    Sign a short-lived (60s) RS256 JWT for GitHub App authentication.
    Uses Python `cryptography` if available; otherwise invokes `/usr/bin/openssl`
    directly against `private_key_path` without copying PEM material into `/tmp`.
    """
    ts = int(now if now is not None else time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iat": ts - 30,
        "exp": ts + 60,
        "iss": str(app_id),
    }
    signing_input = (
        f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    )

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        pem_text = private_key_pem
        if not pem_text:
            if not private_key_path or not os.path.isfile(private_key_path):
                raise RuntimeError("Missing GitHub App private key path or PEM data")
            with open(private_key_path, "r", encoding="utf-8") as f:
                pem_text = f.read()
        private_key = serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)
        signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{_b64url(signature)}"
    except ImportError:
        if not private_key_path or not os.path.isfile(private_key_path):
            raise RuntimeError(
                "GitHub App JWT signing without 'cryptography' requires an on-disk 'private_key_path' "
                "so private keys are never copied to temporary files."
            )
        proc = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", private_key_path],
            input=signing_input.encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return f"{signing_input}.{_b64url(proc.stdout)}"


def evaluate_repo_tag_policy(
    topics: List[str],
    custom_properties: Dict[str, str],
    requested_permission: str,
    default_policy: str = "deny",
) -> Tuple[str, str]:
    """
    Determine whether a token request for `requested_permission` ("read" or "write")
    should be:
      - ("deny", reason)
      - ("auto", reason)
      - ("oob", reason)

    Tag / Custom Property Precedence (Fail-Closed):
      1. `oob-deny` / `oob-none` topic or `oob_access` = `none|deny|blocked` -> ALWAYS "deny"
      2. Explicit Custom Property `oob_access` (`write`, `oob`, `read`)
      3. Explicit Repository Topic (`oob-write`, `oob-oob`, `oob-read`)
      4. `default_policy` (`deny`, `oob`, `read`)
    """
    norm_topics = {t.strip().lower() for t in (topics or [])}
    prop_oob = str(custom_properties.get("oob_access", "")).strip().lower()

    if norm_topics & {"oob-deny", "oob-none"} or prop_oob in ("deny", "none", "blocked"):
        return "deny", "Repository is explicitly tagged as denied (oob-deny or oob_access=none)"

    effective_tier = ""
    source_desc = ""
    if prop_oob in ("write", "oob", "read"):
        effective_tier = prop_oob
        source_desc = f"custom property oob_access={prop_oob}"
    elif "oob-write" in norm_topics:
        effective_tier = "write"
        source_desc = "topic 'oob-write'"
    elif "oob-oob" in norm_topics:
        effective_tier = "oob"
        source_desc = "topic 'oob-oob'"
    elif "oob-read" in norm_topics:
        effective_tier = "read"
        source_desc = "topic 'oob-read'"
    else:
        effective_tier = default_policy.lower()
        source_desc = f"default policy '{effective_tier}'"

    if effective_tier == "deny":
        return (
            "deny",
            f"Repository lacks an allowed tag (oob-read, oob-oob, oob-write) and {source_desc} is active",
        )

    if requested_permission == "read":
        if effective_tier in ("read", "oob", "write"):
            return "auto", f"Read access auto-approved via {source_desc}"
        return "deny", f"Read access denied via {source_desc}"

    if effective_tier == "write":
        return "auto", f"Write access auto-approved via {source_desc}"
    if effective_tier == "oob":
        return "oob", f"Write access requires Home Assistant OOB phone approval via {source_desc}"
    return "deny", f"Write access denied: repository is only tagged for '{effective_tier}' ({source_desc})"


def _github_api_request(
    url: str,
    token: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Dict[str, Any]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"ha-oob-gate/{__version__}",
    }
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            return resp.getcode(), (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(raw)
        except Exception:
            err_json = {"message": raw}
        return e.code, err_json


class GitHubTokenGateModule(BaseGateModule):
    name = "github_token"
    description = "Hybrid GitHub App tag-based single-repo token broker & root vault PAT gate"
    default_ttl_seconds = 3600
    requires_root_caller = False

    def retain_rate_limit_on_validate_error(self, params: Dict[str, Any]) -> bool:
        return bool(params.get("_gh_api_called"))

    def _get_gh_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        mod_cfg = config.get("module_config", {}).get("github_token", {})
        return {
            "api_url": mod_cfg.get("api_url", "https://api.github.com").rstrip("/"),
            "app_id": str(mod_cfg.get("app_id", os.environ.get("GITHUB_APP_ID", ""))).strip(),
            "installation_id": str(mod_cfg.get("installation_id", os.environ.get("GITHUB_INSTALLATION_ID", ""))).strip(),
            "private_key_path": mod_cfg.get("private_key_path", "/etc/ha-sudo/secrets/github_app.pem"),
            "vault_pat_path": mod_cfg.get("vault_pat_path", "/etc/ha-sudo/secrets/github_push_pat"),
            "allow_vault_pat_fallback": bool(mod_cfg.get("allow_vault_pat_fallback", True)),
            "default_repo_policy": mod_cfg.get("default_repo_policy", "deny"),
        }

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        repo_full = str(params.get("repo", "")).strip()
        if repo_full.endswith(".git"):
            repo_full = repo_full[:-4]
        params["repo"] = repo_full

        if not VALID_REPO_RE.match(repo_full):
            return False, f"Invalid repository '{repo_full}' (expected 'owner/repo')"

        perm = str(params.get("permission", "write")).strip().lower()
        if perm not in ("read", "write"):
            return False, "permission must be 'read' or 'write'"
        params["permission"] = perm

        gh_cfg = self._get_gh_config(config)
        app_id = gh_cfg["app_id"]
        key_path = gh_cfg["private_key_path"]
        vault_pat_path = gh_cfg["vault_pat_path"]

        # Mode 1: GitHub App with live Repository Tag / Custom Property inspection
        if app_id and os.path.isfile(key_path):
            try:
                app_jwt = create_github_app_jwt(app_id, private_key_path=key_path)
            except Exception as e:
                return False, f"Failed to sign GitHub App JWT: {e}"

            api_url = gh_cfg["api_url"]
            inst_id = gh_cfg["installation_id"]
            params["_gh_api_called"] = True
            if not inst_id:
                code, inst_data = _github_api_request(f"{api_url}/repos/{repo_full}/installation", app_jwt)
                if code != 200 or not inst_data.get("id"):
                    return False, f"GitHub App is not installed on '{repo_full}' (HTTP {code})"
                inst_id = str(inst_data["id"])

            _, repo_name = repo_full.split("/", 1)
            code, tok_data = _github_api_request(
                f"{api_url}/app/installations/{inst_id}/access_tokens",
                app_jwt,
                method="POST",
                payload={"repositories": [repo_name], "permissions": {"metadata": "read"}},
            )
            if code != 201 or not tok_data.get("token"):
                return (
                    False,
                    f"GitHub App cannot access repository '{repo_full}' (HTTP {code}: {tok_data.get('message', '')})",
                )

            meta_tok = tok_data["token"]
            try:
                _, topics_resp = _github_api_request(f"{api_url}/repos/{repo_full}/topics", meta_tok)
                topics = topics_resp.get("names", []) if isinstance(topics_resp, dict) else []

                prop_code, props_resp = _github_api_request(
                    f"{api_url}/repos/{repo_full}/properties/values", meta_tok
                )
                custom_props: Dict[str, str] = {}
                if prop_code == 200 and isinstance(props_resp, list):
                    for item in props_resp:
                        if isinstance(item, dict) and item.get("property_name"):
                            custom_props[str(item["property_name"])] = str(item.get("value") or "")
            finally:
                _github_api_request(f"{api_url}/installation/token", meta_tok, method="DELETE")

            decision, policy_reason = evaluate_repo_tag_policy(
                topics=topics,
                custom_properties=custom_props,
                requested_permission=perm,
                default_policy=gh_cfg["default_repo_policy"],
            )
            params["_gh_mode"] = "app"
            params["_gh_inst_id"] = inst_id
            params["_gh_decision"] = decision
            params["_gh_policy_reason"] = policy_reason
            params["_gh_topics"] = topics
            params["_gh_custom_props"] = custom_props

            if decision == "deny":
                return False, policy_reason
            return True, "ok"

        # Mode 2: Hybrid Fallback to Root Vault PAT (`/etc/ha-sudo/secrets/github_push_pat`)
        if not app_id and gh_cfg["allow_vault_pat_fallback"] and os.path.isfile(vault_pat_path):
            params["_gh_mode"] = "vault_pat"
            params["_gh_decision"] = "oob"
            params["_gh_policy_reason"] = "Root vault PAT checkout requires Home Assistant phone approval"
            return True, "ok"

        return (
            False,
            f"GitHub App credentials ({key_path}) are not configured or vault PAT fallback is disabled",
        )

    def can_auto_approve(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> bool:
        return params.get("_gh_mode") == "app" and params.get("_gh_decision") == "auto"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        repo_full = sanitize_text(params.get("repo", ""), max_len=100)
        perm = sanitize_text(params.get("permission", "write"), max_len=16).upper()
        mode = "GitHub App (1h Single-Repo)" if params.get("_gh_mode") == "app" else "Root Vault PAT (One-Shot)"
        reason = sanitize_text(params.get("reason", f"Git {perm} on {repo_full}"), max_len=200)
        tags_str = ", ".join(params.get("_gh_topics") or []) or "none"

        title = f"🐙 GitHub {perm}: {repo_full} [{verify_code}]"
        message = (
            f"Caller: {caller.username}@{hostname}\n"
            f"Repo: {repo_full}\n"
            f"Access: {perm} ({mode})\n"
            f"Repo Tags: {tags_str}\n"
            f"Reason: {reason}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Approve ({perm})",
            deny_title="Deny",
            approved_title=f"✅ GitHub {perm} Approved [{verify_code}]",
            approved_message=f"Granted {mode} {perm} access to {repo_full}.",
            denied_title=f"🛑 GitHub {perm} Denied [{verify_code}]",
            denied_message=f"Denied {perm} access to {repo_full}.",
            command_summary=f"github-token {perm.lower()} {repo_full} ({reason})",
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        gh_cfg = self._get_gh_config(config)
        repo_full = params["repo"]
        perm = params.get("permission", "write")

        if params.get("_gh_mode") == "app":
            app_jwt = create_github_app_jwt(gh_cfg["app_id"], private_key_path=gh_cfg["private_key_path"])
            _, repo_name = repo_full.split("/", 1)
            inst_id = params["_gh_inst_id"]

            gh_perms = {"metadata": "read", "contents": "read"}
            if perm == "write":
                gh_perms["contents"] = "write"
                gh_perms["pull_requests"] = "write"

            code, tok_data = _github_api_request(
                f"{gh_cfg['api_url']}/app/installations/{inst_id}/access_tokens",
                app_jwt,
                method="POST",
                payload={
                    "repositories": [repo_name],
                    "permissions": gh_perms,
                },
            )
            if code != 201 or not tok_data.get("token"):
                raise RuntimeError(f"GitHub App token mint failed (HTTP {code}): {tok_data.get('message', '')}")

            return {
                "mode": "github_app",
                "repo": repo_full,
                "permission": perm,
                "token": tok_data["token"],
                "expires_at": tok_data.get("expires_at", ""),
                "policy_reason": params.get("_gh_policy_reason", ""),
            }

        vault_pat_path = gh_cfg["vault_pat_path"]
        with open(vault_pat_path, "r", encoding="utf-8") as f:
            pat = f.read().strip()
        return {
            "mode": "vault_pat",
            "repo": repo_full,
            "permission": perm,
            "token": pat,
            "policy_reason": params.get("_gh_policy_reason", ""),
        }

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if grant_metadata.get("mode") == "github_app" and grant_metadata.get("token"):
            gh_cfg = self._get_gh_config(config)
            code, _ = _github_api_request(
                f"{gh_cfg['api_url']}/installation/token",
                grant_metadata["token"],
                method="DELETE",
            )
            return code in (204, 200, 404)
        return True
