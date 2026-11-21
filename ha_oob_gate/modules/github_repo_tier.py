"""
GitHub Repository OOB Tier Promotion / Tightening Gate Module (`github_repo_tier`).

Allows an unprivileged caller to request changing an existing GitHub repository's
`oob-<tier>` policy topic (`oob-auth github-set-tier` / MCP `oob_github_set_tier`)
strictly gated by Home Assistant mobile approval, preserving all non-policy topics
and refusing to promote protected Tier-0 repositories (such as `ha-oob-gate`) to `oob-write`.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple, TypeVar

from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec
from .github_repo_create import (
    ALLOWED_OOB_TIERS,
    RESERVED_TOPICS,
    RESERVED_TOPIC_PREFIXES,
    _load_root_user_token,
    discover_app_installations,
    resolve_repo_admin_config,
)
from .github_token import VALID_REPO_RE, _github_api_request, create_github_app_jwt
from .self_update import DEFAULT_SELF_UPDATE_REPO

_T = TypeVar("_T")


class GitHubRepoTierModule(BaseGateModule):
    name = "github_repo_tier"
    description = "OOB-gated promotion or tightening of GitHub repository `oob-<tier>` topics"
    default_ttl_seconds = 600
    requires_root_caller = False

    def can_auto_approve(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> bool:
        return False

    def retain_rate_limit_on_validate_error(self, params: Dict[str, Any]) -> bool:
        return bool(params.get("_gh_api_called"))

    def _get_tier_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        cfg = resolve_repo_admin_config(config, section="github_repo_tier", fallback_section="github_repo_create")
        mod_root = config.get("module_config", {})
        tier_cfg = mod_root.get("github_repo_tier", {})
        self_update_repo = str(
            mod_root.get("self_update", {}).get("repo") or DEFAULT_SELF_UPDATE_REPO
        ).strip().lower()
        protected = {str(r).strip().lower() for r in (tier_cfg.get("protected_repos") or []) if str(r).strip()}
        if self_update_repo:
            protected.add(self_update_repo)
        cfg["protected_repos"] = protected
        return cfg

    def _with_repo_admin_token(
        self,
        cfg: Dict[str, Any],
        auth_mode: str,
        inst_id: str,
        fn: Callable[[str], _T],
    ) -> _T:
        api_url = cfg["api_url"]
        if auth_mode == "github_app_org":
            app_jwt = create_github_app_jwt(cfg["app_id"], private_key_path=cfg["private_key_path"])
            code_t, tok_data = _github_api_request(
                f"{api_url}/app/installations/{inst_id}/access_tokens",
                app_jwt,
                method="POST",
                payload={"permissions": {"administration": "write", "metadata": "read"}},
            )
            if code_t != 201 or not tok_data.get("token"):
                raise RuntimeError(f"Failed minting GitHub App org admin token (HTTP {code_t})")
            adm_tok = str(tok_data["token"])
            try:
                return fn(adm_tok)
            finally:
                _github_api_request(f"{api_url}/installation/token", adm_tok, method="DELETE")

        user_tok, _ = _load_root_user_token(cfg)
        if not user_tok:
            raise RuntimeError("Root GitHub user credential is not available")
        return fn(user_tok)

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

        raw_tier = str(params.get("oob_tier") or "").strip().lower()
        if raw_tier not in ALLOWED_OOB_TIERS:
            return False, "oob_tier is required and must be one of: oob, read, write, deny"
        params["oob_tier"] = raw_tier

        reason = str(params.get("reason") or "").strip()
        if not reason:
            return False, "A human-readable --reason is required to update a repository OOB tier"
        if len(reason) > 200:
            return False, "reason exceeds maximum displayable length (200 chars)"
        params["reason"] = reason

        cfg = self._get_tier_config(config)
        if raw_tier == "write" and repo_full.lower() in cfg["protected_repos"]:
            return False, f"Security policy: protected Tier-0 repository '{repo_full}' cannot be promoted to 'oob-write'"

        api_url = cfg["api_url"]
        params["_gh_api_called"] = True

        try:
            creator_inst_map = discover_app_installations(api_url, cfg["app_id"], cfg["private_key_path"])
            if cfg["token_app_id"] and (
                cfg["token_app_id"] != cfg["app_id"] or cfg["token_private_key_path"] != cfg["private_key_path"]
            ):
                token_inst_map = discover_app_installations(
                    api_url, cfg["token_app_id"], cfg["token_private_key_path"]
                )
            else:
                token_inst_map = creator_inst_map
        except Exception as e:
            return False, f"Failed querying GitHub App installations: {e}"

        owner_low = owner.lower()
        inst_info = creator_inst_map.get(owner_low)
        known_installs = creator_inst_map or token_inst_map

        if cfg["allowed_owners"] and owner_low not in cfg["allowed_owners"]:
            return False, f"Security policy: owner '{owner}' is not in allowed_owners ({cfg['allowed_owners']})"

        if known_installs and not cfg["allowed_owners"] and (owner_low not in creator_inst_map and owner_low not in token_inst_map):
            all_logins = sorted({v["login"] for v in (*creator_inst_map.values(), *token_inst_map.values())})
            return (
                False,
                f"Security policy: owner '{owner}' does not have a trusted GitHub App installed "
                f"(installed on: {all_logins})",
            )

        auth_mode = ""
        inst_id = ""
        if inst_info and inst_info["type"].lower() == "organization" and inst_info["repository_selection"] == "all":
            auth_mode = "github_app_org"
            inst_id = inst_info["id"]
        else:
            user_tok, _ = _load_root_user_token(cfg)
            if not user_tok:
                return (
                    False,
                    f"Updating OOB topics for '{repo_full}' requires either an organization GitHub App installation "
                    f"(repository_selection='all') or a root repo-admin user credential ({cfg['user_oauth_path']})",
                )
            auth_mode = "user_token"

        def inspect_repo(tok: str) -> Tuple[bool, str]:
            code_r, repo_info = _github_api_request(f"{api_url}/repos/{repo_full}", tok, method="GET")
            if code_r == 404:
                return False, f"Repository '{repo_full}' does not exist"
            if code_r != 200 or not isinstance(repo_info, dict):
                return False, f"Unexpected HTTP {code_r} inspecting '{repo_full}'"

            canonical_full = str(repo_info.get("full_name") or repo_full)
            code_t, topics_resp = _github_api_request(f"{api_url}/repos/{canonical_full}/topics", tok, method="GET")
            if code_t != 200 or not isinstance(topics_resp, dict):
                return False, f"Failed reading repository topics for '{canonical_full}' (HTTP {code_t})"

            prop_code, props_resp = _github_api_request(
                f"{api_url}/repos/{canonical_full}/properties/values", tok, method="GET"
            )
            if prop_code == 200 and isinstance(props_resp, list):
                for item in props_resp:
                    if not isinstance(item, dict):
                        continue
                    pname = str(item.get("property_name") or "").strip().lower()
                    pval = str(item.get("value") or "").strip()
                    if pname in ("oob_access", "agy_access") and pval:
                        return (
                            False,
                            f"Repository '{canonical_full}' is governed by organization custom property "
                            f"{pname}={pval!r}, which overrides repository topics",
                        )

            current_topics = [str(t).strip().lower() for t in (topics_resp.get("names") or []) if str(t).strip()]
            prev_oob: List[str] = []
            kept: List[str] = []
            for topic in current_topics:
                if topic in RESERVED_TOPICS or topic.startswith(RESERVED_TOPIC_PREFIXES):
                    prev_oob.append(topic)
                else:
                    kept.append(topic)

            params["repo"] = canonical_full
            params["_auth_mode"] = auth_mode
            params["_inst_id"] = inst_id
            params["_prev_oob_topics"] = prev_oob
            params["_kept_topics"] = kept
            return True, "ok"

        try:
            return self._with_repo_admin_token(cfg, auth_mode, inst_id, inspect_repo)
        except Exception as e:
            return False, f"Failed inspecting repository '{repo_full}': {e}"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        repo_full = sanitize_text(params.get("repo", ""), max_len=100)
        oob_tier = str(params.get("oob_tier", "oob"))
        target_topic = f"oob-{oob_tier}"
        prev_disp = sanitize_text(", ".join(params.get("_prev_oob_topics") or []) or "(untagged)", max_len=80)
        kept_disp = sanitize_text(", ".join(params.get("_kept_topics") or []) or "(none)", max_len=120)
        reason = sanitize_text(params.get("reason", ""), max_len=200)

        if oob_tier == "write":
            title = f"⚠️ Set Repo Tier oob-write: {repo_full} [{verify_code}]"
            banner = "⚠️ ENABLES SILENT FUTURE PUSHES WITHOUT PHONE PROMPTS\n"
            approve_title = f"Set oob-write [{verify_code}]"
            color = "#F59E0B"
            icon = "mdi:shield-alert-outline"
        else:
            title = f"🏷️ Set Repo Tier {target_topic}: {repo_full} [{verify_code}]"
            banner = ""
            approve_title = f"Set {target_topic} [{verify_code}]"
            color = "#10B981"
            icon = "mdi:tag-check-outline"

        message = (
            f"{banner}"
            f"Caller: {caller.username}@{hostname}\n"
            f"Repo: {repo_full}\n"
            f"Transition: {prev_disp} -> {target_topic}\n"
            f"Kept Topics: {kept_disp}\n"
            f"Reason: {reason}"
        )
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=approve_title,
            deny_title="Deny",
            approved_title=f"✅ Repo Tier Updated: {repo_full}",
            approved_message=f"Updated {repo_full} OOB tier ({prev_disp} -> {target_topic}).",
            denied_title=f"🛑 Repo Tier Update Denied [{verify_code}]",
            denied_message=f"Denied setting {repo_full} to {target_topic}.",
            command_summary=f"github-set-tier {repo_full} {target_topic} ({reason})",
            icon=icon,
            color=color,
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        cfg = self._get_tier_config(config)
        api_url = cfg["api_url"]
        repo_full = str(params["repo"])
        oob_tier = str(params["oob_tier"])
        target_topic = f"oob-{oob_tier}"
        prev_oob = list(params.get("_prev_oob_topics") or [])
        kept = list(params.get("_kept_topics") or [])
        new_topics = [target_topic, *[t for t in kept if t != target_topic]]
        auth_mode = str(params.get("_auth_mode") or "user_token")
        inst_id = str(params.get("_inst_id") or "")

        def apply_topics(tok: str) -> Dict[str, Any]:
            code, resp = _github_api_request(
                f"{api_url}/repos/{repo_full}/topics",
                tok,
                method="PUT",
                payload={"names": new_topics},
            )
            if code != 200:
                msg = resp.get("message", "") if isinstance(resp, dict) else ""
                raise RuntimeError(f"Failed updating repository topics for '{repo_full}' (HTTP {code}): {msg}")
            applied = resp.get("names", new_topics) if isinstance(resp, dict) else new_topics
            return {
                "repo": repo_full,
                "oob_tier": oob_tier,
                "topic": target_topic,
                "previous_oob_topics": prev_oob,
                "topics": applied,
            }

        return self._with_repo_admin_token(cfg, auth_mode, inst_id, apply_topics)
