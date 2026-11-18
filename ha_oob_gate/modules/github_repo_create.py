"""
GitHub Repository Creation Gate Module (`github_repo_create`).

Allows an unprivileged caller to request creation of a new GitHub repository
(`oob-auth github-create-repo` / MCP `oob_github_create_repo`) strictly gated by
human-in-the-loop Home Assistant mobile approval, with zero raw admin credential exposure.

Security Architecture:
1. **Unconditional Human Approval (`can_auto_approve() -> False`):**
   Creating a repository (especially a `public` repository) establishes a new external
   publication boundary and can never be auto-approved.
2. **Strict Owner Allowlist (Anti-Exfiltration):**
   Target `owner` must belong to `module_config.github_repo_create.allowed_owners` or,
   when unset, an account where the root-trusted GitHub App (`/etc/ha-sudo/secrets/github_app.pem`)
   is actively installed (or the exact authenticated `GET /user` login in token-only mode).
3. **No Clobbering or Topic Re-Tagging of Existing Repositories:**
   `validate()` verifies `GET /repos/{owner}/{repo}` returns `404` before sending a mobile
   prompt, and `grant()` requires `POST .../repos` to return `HTTP 201 Created` before setting
   initial `oob-<tier>` topics—preventing any overwrite of `oob-deny` on existing repos.
4. **Policy Topic Isolation:**
   Callers choose `--oob-tier` (`oob` default, `read`, `deny`, or `write` only when
   `allow_write_tier_on_create` is enabled in root config). Reserved `oob-*` / `agy-*`
   prefixes are rejected inside `--topics` to prevent smuggling `oob-write`.
5. **Zero Raw Admin Token Exposure:**
   Repository creation executes inside the root daemon using:
     - **Organization repos (`POST /orgs/{org}/repos`):** Short-lived GitHub App installation
       token (`administration: write`) revoked immediately after creation, OR root user token.
     - **Personal user repos (`POST /user/repos`):** Root-only GitHub App User OAuth token
       (`/etc/ha-sudo/secrets/github_user_oauth.json`, with automatic refresh-token rotation)
       or root-only Fine-Grained Repo-Admin PAT (`/etc/ha-sudo/secrets/github_repo_admin_pat`).
   If `--mint-token` is requested, only a downscoped 1-hour single-repo GitHub App token
   (`contents: write`, `pull_requests: write` — no `administration` scope, never a PAT) is returned.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__
from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec
from .github_token import VALID_REPO_RE, _github_api_request, create_github_app_jwt

TOPIC_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,49}$")
RESERVED_TOPIC_PREFIXES = ("oob-", "agy-")
RESERVED_TOPICS = frozenset({"oob", "agy"})
ALLOWED_VISIBILITIES = frozenset({"private", "public"})
ALLOWED_OOB_TIERS = frozenset({"oob", "read", "deny", "write"})

DEFAULT_REPO_ADMIN_PAT_PATH = "/etc/ha-sudo/secrets/github_repo_admin_pat"
DEFAULT_USER_OAUTH_PATH = "/etc/ha-sudo/secrets/github_user_oauth.json"
DEFAULT_OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token"


def _write_json_secret_atomic(path: str, data: Dict[str, Any]) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    tmp_path = f"{path}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp_path, flags, 0o400)
    try:
        try:
            os.fchmod(fd, 0o400)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        if os.geteuid() == 0:
            os.chown(tmp_path, 0, 0)
        os.replace(tmp_path, path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _refresh_github_user_oauth(oauth_data: Dict[str, Any], token_url: str = DEFAULT_OAUTH_TOKEN_URL) -> Dict[str, Any]:
    client_id = str(oauth_data.get("client_id") or "").strip()
    refresh_tok = str(oauth_data.get("refresh_token") or "").strip()
    if not client_id or not refresh_tok:
        raise RuntimeError("Missing client_id or refresh_token in github_user_oauth.json")

    form_fields = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_tok,
    }
    if oauth_data.get("client_secret"):
        form_fields["client_secret"] = str(oauth_data["client_secret"]).strip()

    encoded = urllib.parse.urlencode(form_fields).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=encoded,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": f"ha-oob-gate/{__version__}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    if payload.get("error") or not payload.get("access_token"):
        err_desc = payload.get("error_description") or payload.get("error") or "unknown OAuth refresh error"
        raise RuntimeError(f"GitHub user OAuth refresh failed: {err_desc}")

    now = int(time.time())
    updated = dict(oauth_data)
    updated["access_token"] = str(payload["access_token"]).strip()
    if payload.get("refresh_token"):
        updated["refresh_token"] = str(payload["refresh_token"]).strip()
    if payload.get("expires_in"):
        updated["expires_at"] = now + int(payload["expires_in"])
    updated["refreshed_at"] = now
    return updated


def _load_root_user_token(cfg: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """
    Load a root-only user-level GitHub token capable of calling `POST /user/repos` (or org fallback).
    Priority:
      1. `github_user_oauth.json` (GitHub App Device Flow user token, auto-refreshed if expiring)
      2. `github_repo_admin_pat` (Fine-Grained PAT scoped strictly to Administration: write)
      3. `github_push_pat` (legacy root vault PAT fallback when enabled)
    Returns `(token_or_None, source_label)`.
    """
    oauth_path = cfg["user_oauth_path"]
    if oauth_path and os.path.isfile(oauth_path):
        try:
            with open(oauth_path, "r", encoding="utf-8") as f:
                oauth_data = json.load(f)
            if isinstance(oauth_data, dict):
                exp = int(oauth_data.get("expires_at") or 0)
                if exp and exp <= int(time.time()) + 120 and oauth_data.get("refresh_token"):
                    oauth_data = _refresh_github_user_oauth(oauth_data, token_url=cfg["oauth_token_url"])
                    _write_json_secret_atomic(oauth_path, oauth_data)
                tok = str(oauth_data.get("access_token") or "").strip()
                if tok:
                    return tok, "github_user_oauth"
        except Exception:
            pass

    admin_pat_path = cfg["repo_admin_pat_path"]
    if admin_pat_path and os.path.isfile(admin_pat_path):
        try:
            with open(admin_pat_path, "r", encoding="utf-8") as f:
                tok = f.read().strip()
            if tok:
                return tok, "github_repo_admin_pat"
        except Exception:
            pass

    vault_pat_path = cfg["vault_pat_path"]
    if cfg["allow_vault_pat_fallback"] and vault_pat_path and os.path.isfile(vault_pat_path):
        try:
            with open(vault_pat_path, "r", encoding="utf-8") as f:
                tok = f.read().strip()
            if tok:
                return tok, "vault_pat"
        except Exception:
            pass

    return None, ""


class GitHubRepoCreateModule(BaseGateModule):
    name = "github_repo_create"
    description = "OOB-gated GitHub repository creation with automatic policy tagging & zero admin token leak"
    default_ttl_seconds = 3600
    requires_root_caller = False

    def can_auto_approve(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> bool:
        return False

    def retain_rate_limit_on_validate_error(self, params: Dict[str, Any]) -> bool:
        return bool(params.get("_gh_api_called"))

    def _get_create_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        mod_root = config.get("module_config", {})
        gh_tok_cfg = mod_root.get("github_token", {})
        create_cfg = mod_root.get("github_repo_create", {})
        raw_owners = create_cfg.get("allowed_owners") or []
        allowed_owners = [str(o).strip().lower() for o in raw_owners if str(o).strip()]
        return {
            "api_url": str(create_cfg.get("api_url") or gh_tok_cfg.get("api_url") or "https://api.github.com").rstrip("/"),
            "oauth_token_url": str(create_cfg.get("oauth_token_url") or DEFAULT_OAUTH_TOKEN_URL),
            "app_id": str(create_cfg.get("app_id") or gh_tok_cfg.get("app_id") or os.environ.get("GITHUB_APP_ID", "")).strip(),
            "private_key_path": str(
                create_cfg.get("private_key_path")
                or gh_tok_cfg.get("private_key_path")
                or "/etc/ha-sudo/secrets/github_app.pem"
            ),
            "repo_admin_pat_path": str(create_cfg.get("repo_admin_pat_path") or DEFAULT_REPO_ADMIN_PAT_PATH),
            "user_oauth_path": str(create_cfg.get("user_oauth_path") or DEFAULT_USER_OAUTH_PATH),
            "vault_pat_path": str(
                create_cfg.get("vault_pat_path")
                or gh_tok_cfg.get("vault_pat_path")
                or "/etc/ha-sudo/secrets/github_push_pat"
            ),
            "allow_vault_pat_fallback": bool(
                create_cfg.get("allow_vault_pat_fallback", gh_tok_cfg.get("allow_vault_pat_fallback", True))
            ),
            "allow_write_tier_on_create": bool(create_cfg.get("allow_write_tier_on_create", False)),
            "allowed_owners": allowed_owners,
        }

    def _discover_app_installations(self, cfg: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        app_id = cfg["app_id"]
        key_path = cfg["private_key_path"]
        if not app_id or not os.path.isfile(key_path):
            return {}
        app_jwt = create_github_app_jwt(app_id, private_key_path=key_path)
        code, inst_list = _github_api_request(f"{cfg['api_url']}/app/installations", app_jwt, method="GET")
        if code != 200 or not isinstance(inst_list, list):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for item in inst_list:
            if not isinstance(item, dict):
                continue
            acct = item.get("account") or {}
            login = str(acct.get("login") or "").strip()
            inst_id = item.get("id")
            if login and inst_id:
                out[login.lower()] = {
                    "id": str(inst_id),
                    "login": login,
                    "type": str(acct.get("type") or "User"),
                    "repository_selection": str(item.get("repository_selection") or "all"),
                }
        return out

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        repo_full = str(params.get("repo") or "").strip()
        if repo_full.endswith(".git"):
            repo_full = repo_full[:-4]
        if not VALID_REPO_RE.match(repo_full):
            return False, f"Invalid repository '{repo_full}' (expected 'owner/repo')"

        owner, repo_name = repo_full.split("/", 1)
        if repo_name in (".", "..") or len(repo_name) > 100:
            return False, f"Invalid repository name '{repo_name}'"
        params["repo"] = repo_full

        visibility = str(params.get("visibility") or "private").strip().lower()
        if visibility not in ALLOWED_VISIBILITIES:
            return False, "visibility must be 'private' or 'public'"
        params["visibility"] = visibility

        oob_tier = str(params.get("oob_tier") or "oob").strip().lower()
        if oob_tier not in ALLOWED_OOB_TIERS:
            return False, "oob_tier must be one of: oob, read, deny, write"

        cfg = self._get_create_config(config)
        if oob_tier == "write" and not cfg["allow_write_tier_on_create"]:
            return (
                False,
                "Security policy: creating a repository pre-tagged 'oob-write' (silent future pushes) is disabled; "
                "use --oob-tier oob (default), read, or deny",
            )
        params["oob_tier"] = oob_tier

        raw_topics = params.get("topics") or []
        if isinstance(raw_topics, str):
            raw_topics = [t.strip() for t in raw_topics.split(",") if t.strip()]
        if not isinstance(raw_topics, list) or len(raw_topics) > 10:
            return False, "topics must be a list of up to 10 GitHub repository topics"

        clean_topics: List[str] = []
        for raw_t in raw_topics:
            t_low = str(raw_t).strip().lower()
            if not t_low:
                continue
            if not TOPIC_RE.match(t_low):
                return False, f"Invalid GitHub topic '{raw_t}' (must be lowercase alphanumeric/hyphens, max 50 chars)"
            if t_low in RESERVED_TOPICS or t_low.startswith(RESERVED_TOPIC_PREFIXES):
                return (
                    False,
                    f"Security policy: reserved policy topic '{t_low}' cannot be passed in --topics; use --oob-tier instead",
                )
            if t_low not in clean_topics:
                clean_topics.append(t_low)
        params["topics"] = clean_topics

        desc = sanitize_text(str(params.get("description") or "").strip(), max_len=350)
        params["description"] = desc

        reason = str(params.get("reason") or "").strip()
        if not reason:
            return False, "A human-readable --reason is required to create a GitHub repository"
        if len(reason) > 200:
            return False, "reason exceeds maximum displayable length (200 chars)"
        params["reason"] = reason

        mint_token = bool(params.get("mint_token", False))
        params["mint_token"] = mint_token

        api_url = cfg["api_url"]
        params["_gh_api_called"] = True

        try:
            inst_map = self._discover_app_installations(cfg)
        except Exception as e:
            return False, f"Failed querying GitHub App installations: {e}"

        owner_low = owner.lower()
        inst_info = inst_map.get(owner_low)

        if mint_token and not inst_info:
            return (
                False,
                f"--mint-token requires the GitHub App to be installed on '{owner}' so a downscoped single-repo token can be minted",
            )

        if cfg["allowed_owners"] and owner_low not in cfg["allowed_owners"]:
            return False, f"Security policy: owner '{owner}' is not in allowed_owners ({cfg['allowed_owners']})"

        if inst_map and not cfg["allowed_owners"] and not inst_info:
            return (
                False,
                f"Security policy: owner '{owner}' does not have the trusted GitHub App installed "
                f"(installed on: {sorted(v['login'] for v in inst_map.values())})",
            )

        # Path 1: Organization owner via GitHub App Installation Token (`administration: write`)
        if inst_info and inst_info["type"].lower() == "organization":
            app_jwt = create_github_app_jwt(cfg["app_id"], private_key_path=cfg["private_key_path"])
            code_tok, tok_data = _github_api_request(
                f"{api_url}/app/installations/{inst_info['id']}/access_tokens",
                app_jwt,
                method="POST",
                payload={"permissions": {"administration": "write", "metadata": "read"}},
            )
            if code_tok == 201 and tok_data.get("token"):
                adm_tok = tok_data["token"]
                try:
                    code_ex, _ = _github_api_request(f"{api_url}/repos/{repo_full}", adm_tok, method="GET")
                finally:
                    _github_api_request(f"{api_url}/installation/token", adm_tok, method="DELETE")
                if code_ex == 200:
                    return False, f"Repository '{repo_full}' already exists"
                if code_ex != 404:
                    return False, f"Unexpected HTTP {code_ex} checking '{repo_full}'"
                params["_create_mode"] = "github_app_org"
                params["_owner_login"] = inst_info["login"]
                params["_inst_id"] = inst_info["id"]
                params["_inst_selection"] = inst_info["repository_selection"]
                return True, "ok"

        # Path 2: Personal User owner (`POST /user/repos`) or Organization fallback via root user token
        user_tok, tok_source = _load_root_user_token(cfg)
        if not user_tok:
            if inst_info and inst_info["type"].lower() == "organization":
                return (
                    False,
                    f"GitHub App on organization '{owner}' lacks Organization/Repository 'Administration: Read and write' "
                    "permission (enable it in GitHub App settings -> Permissions & events, then accept on the org installation)",
                )
            return (
                False,
                f"Creating personal user repositories under '{owner}' requires a one-time GitHub App user authorization "
                "('python3 -m ha_oob_gate.setup_github_app --authorize-user' as root) or an Administration-only "
                f"Fine-Grained PAT at {cfg['repo_admin_pat_path']} (alternatively, create under your GitHub Organization)",
            )

        code_u, user_info = _github_api_request(f"{api_url}/user", user_tok, method="GET")
        if code_u != 200 or not user_info.get("login"):
            return False, f"Root GitHub user credential ({tok_source}) failed authentication (HTTP {code_u})"

        auth_login = str(user_info["login"]).strip()
        is_org_target = bool(inst_info and inst_info["type"].lower() == "organization")
        if not is_org_target and auth_login.lower() != owner_low:
            if not cfg["allowed_owners"]:
                return (
                    False,
                    f"Security policy: user credential belongs to '{auth_login}', cannot create under '{owner}'",
                )
            code_org, org_info = _github_api_request(f"{api_url}/orgs/{owner}", user_tok, method="GET")
            if code_org != 200 or not org_info.get("login"):
                return False, f"Target owner '{owner}' is neither authenticated user '{auth_login}' nor an accessible organization"
            is_org_target = True

        code_ex, _ = _github_api_request(f"{api_url}/repos/{repo_full}", user_tok, method="GET")
        if code_ex == 200:
            return False, f"Repository '{repo_full}' already exists"
        if code_ex != 404:
            return False, f"Unexpected HTTP {code_ex} checking '{repo_full}'"

        params["_create_mode"] = "user_token_org" if is_org_target else "user_token_user"
        params["_token_source"] = tok_source
        params["_owner_login"] = inst_info["login"] if inst_info else (owner if is_org_target else auth_login)
        if inst_info:
            params["_inst_id"] = inst_info["id"]
            params["_inst_selection"] = inst_info["repository_selection"]
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        repo_full = sanitize_text(params.get("repo", ""), max_len=100)
        vis = params.get("visibility", "private")
        is_pub = vis == "public"
        oob_tier = params.get("oob_tier", "oob")
        extra_topics = params.get("topics") or []
        all_topics = [f"oob-{oob_tier}", *extra_topics]
        desc = sanitize_text(params.get("description", "") or "(none)", max_len=140)
        reason = sanitize_text(params.get("reason", ""), max_len=200)
        mint_note = "Yes (1h single-repo push token)" if params.get("mint_token") else "No"

        vis_badge = "🌐 PUBLIC (WORLD-READABLE)" if is_pub else "🔒 PRIVATE"
        title = (
            f"🌐 Create PUBLIC Repo: {repo_full} [{verify_code}]"
            if is_pub
            else f"🔒 Create PRIVATE Repo: {repo_full} [{verify_code}]"
        )
        message = (
            f"Caller: {caller.username}@{hostname}\n"
            f"Repo: {repo_full}\n"
            f"Visibility: {vis_badge}\n"
            f"Topics: {', '.join(all_topics)}\n"
            f"Mint Push Token: {mint_note}\n"
            f"Description: {desc}\n"
            f"Reason: {reason}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Create {'PUBLIC' if is_pub else 'Private'} [{verify_code}]",
            deny_title="Deny",
            approved_title=f"✅ Repo Created: {repo_full}",
            approved_message=f"Created {vis} repository {repo_full} ({', '.join(all_topics)}).",
            denied_title=f"🛑 Repo Creation Denied [{verify_code}]",
            denied_message=f"Denied creation of {vis} repository {repo_full}.",
            command_summary=f"github-create-repo {vis} {repo_full} ({reason})",
            icon="mdi:earth-plus" if is_pub else "mdi:source-repository-plus",
            color="#F59E0B" if is_pub else "#8B5CF6",
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        cfg = self._get_create_config(config)
        api_url = cfg["api_url"]
        repo_full = params["repo"]
        owner, repo_name = repo_full.split("/", 1)
        visibility = params.get("visibility", "private")
        oob_tier = params.get("oob_tier", "oob")
        extra_topics = params.get("topics") or []
        all_topics = [f"oob-{oob_tier}", *extra_topics]
        create_mode = params.get("_create_mode", "")
        inst_id = params.get("_inst_id", "")

        create_payload = {
            "name": repo_name,
            "private": visibility != "public",
            "description": params.get("description", ""),
            "auto_init": False,
            "has_issues": True,
        }

        temp_app_admin_tok = ""
        try:
            if create_mode == "github_app_org":
                app_jwt = create_github_app_jwt(cfg["app_id"], private_key_path=cfg["private_key_path"])
                code_t, tok_data = _github_api_request(
                    f"{api_url}/app/installations/{inst_id}/access_tokens",
                    app_jwt,
                    method="POST",
                    payload={"permissions": {"administration": "write", "metadata": "read"}},
                )
                if code_t != 201 or not tok_data.get("token"):
                    raise RuntimeError(f"Failed minting GitHub App org admin token (HTTP {code_t})")
                temp_app_admin_tok = tok_data["token"]
                auth_tok = temp_app_admin_tok
                create_url = f"{api_url}/orgs/{owner}/repos"
            else:
                user_tok, _ = _load_root_user_token(cfg)
                if not user_tok:
                    raise RuntimeError("Root GitHub user credential is no longer available")
                auth_tok = user_tok
                create_url = f"{api_url}/orgs/{owner}/repos" if create_mode == "user_token_org" else f"{api_url}/user/repos"

            code_c, created = _github_api_request(create_url, auth_tok, method="POST", payload=create_payload)
            if code_c != 201 or not created.get("full_name"):
                raise RuntimeError(
                    f"GitHub repository creation failed (HTTP {code_c}): {created.get('message', '')}"
                )

            canonical_full = str(created["full_name"])
            repo_id = created.get("id")

            # Immediately apply initial OOB policy topic + optional extra topics
            code_top, top_resp = _github_api_request(
                f"{api_url}/repos/{canonical_full}/topics",
                auth_tok,
                method="PUT",
                payload={"names": all_topics},
            )
            applied_topics = top_resp.get("names", all_topics) if code_top == 200 else []

            # If created via user token and the GitHub App installation uses "selected" repos, attach this repo
            app_attached = params.get("_inst_selection") == "all"
            if (
                create_mode != "github_app_org"
                and inst_id
                and repo_id
                and params.get("_inst_selection") == "selected"
            ):
                code_att, _ = _github_api_request(
                    f"{api_url}/user/installations/{inst_id}/repositories/{repo_id}",
                    auth_tok,
                    method="PUT",
                )
                app_attached = code_att in (204, 304)
        finally:
            if temp_app_admin_tok:
                _github_api_request(f"{api_url}/installation/token", temp_app_admin_tok, method="DELETE")

        result: Dict[str, Any] = {
            "repo": canonical_full,
            "html_url": str(created.get("html_url") or f"https://github.com/{canonical_full}"),
            "clone_url": str(created.get("clone_url") or f"https://github.com/{canonical_full}.git"),
            "ssh_url": str(created.get("ssh_url") or f"git@github.com:{canonical_full}.git"),
            "visibility": "private" if created.get("private") else "public",
            "oob_tier": oob_tier,
            "topics": applied_topics,
            "app_installed": bool(inst_id) and (create_mode == "github_app_org" or app_attached),
        }

        if params.get("mint_token") and inst_id:
            app_jwt = create_github_app_jwt(cfg["app_id"], private_key_path=cfg["private_key_path"])
            _, created_name = canonical_full.split("/", 1)
            code_m, mint_data = _github_api_request(
                f"{api_url}/app/installations/{inst_id}/access_tokens",
                app_jwt,
                method="POST",
                payload={
                    "repositories": [created_name],
                    "permissions": {
                        "metadata": "read",
                        "contents": "write",
                        "pull_requests": "write",
                    },
                },
            )
            if code_m != 201 or not mint_data.get("token"):
                raise RuntimeError(
                    f"Repository '{canonical_full}' was created, but single-repo token mint failed (HTTP {code_m}): "
                    f"{mint_data.get('message', '')}"
                )
            result["mode"] = "github_app"
            result["token"] = mint_data["token"]
            result["expires_at"] = mint_data.get("expires_at", "")

        return result

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if grant_metadata.get("mode") == "github_app" and grant_metadata.get("token"):
            cfg = self._get_create_config(config)
            code, _ = _github_api_request(
                f"{cfg['api_url']}/installation/token",
                grant_metadata["token"],
                method="DELETE",
            )
            return code in (204, 200, 404)
        return True
