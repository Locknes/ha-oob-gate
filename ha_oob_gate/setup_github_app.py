#!/usr/bin/env python3
"""Provision and verify a multi-owner GitHub App for ha-oob-gate (`github_token` module).

100% Python standard library implementation (no third-party packages required).
Supports two zero-leak provisioning workflows:
1. GitHub App Manifest Code Exchange (`--code <ONE_TIME_CODE>`):
   Calls `POST https://api.github.com/app-manifests/{code}/conversions` directly
   from the host over TLS, receiving `app_id`, `slug`, and the RSA `pem` private
   key without copying private key material through a chat window or clipboard.
2. Local Key Provisioning (`--app-id <ID> --pem-file <PATH>`):
   Validates an existing GitHub App ID and downloaded `.pem` file against
   `GET https://api.github.com/app`, installs the private key atomically to
   `/etc/ha-sudo/secrets/github_app.pem` (`0400 root:root`), updates
   `/etc/ha-sudo/config.json` (`installation_id: ""` so multi-owner personal +
   organization installations are discovered dynamically per repository), and
   optionally shreds the temporary source `.pem` file (`--shred-source`).
"""

from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .modules.github_repo_create import (
    DEFAULT_REPO_CREATOR_PEM_PATH,
    DEFAULT_USER_OAUTH_PATH,
    _write_json_secret_atomic,
)
from .modules.github_token import _github_api_request, create_github_app_jwt

DEFAULT_CONFIG_PATH = Path("/etc/ha-sudo/config.json")
DEFAULT_PEM_PATH = Path("/etc/ha-sudo/secrets/github_app.pem")
DEFAULT_CREATOR_PEM = Path(DEFAULT_REPO_CREATOR_PEM_PATH)
DEFAULT_API_URL = "https://api.github.com"


def build_app_manifest(
    app_name: str = "locklab-oob-gate",
    homepage_url: str = "https://github.com/Locknes/ha-oob-gate",
    redirect_url: str = "http://127.0.0.1:8788/callback",
    role: str = "token-broker",
) -> Dict[str, Any]:
    """Return a GitHub App Manifest dictionary for `token-broker` or isolated `repo-creator`."""
    if role == "repo-creator":
        effective_name = "locklab-repo-creator" if app_name == "locklab-oob-gate" else app_name
        perms = {
            "administration": "write",
            "metadata": "read",
        }
    else:
        effective_name = app_name
        perms = {
            "actions": "read",
            "checks": "read",
            "contents": "write",
            "pull_requests": "write",
            "workflows": "write",
            "metadata": "read",
        }
    return {
        "name": effective_name,
        "url": homepage_url,
        "redirect_url": redirect_url,
        "public": True,
        "default_permissions": perms,
        "default_events": [],
    }


def render_manifest_html(
    app_name: str = "locklab-oob-gate",
    homepage_url: str = "https://github.com/Locknes/ha-oob-gate",
    redirect_url: str = "http://127.0.0.1:8788/callback",
    role: str = "token-broker",
) -> str:
    """Render a self-contained HTML page with a 1-click form that registers the GitHub App via Manifest."""
    manifest_obj = build_app_manifest(app_name, homepage_url, redirect_url, role=role)
    manifest_json = json.dumps(manifest_obj)
    escaped_manifest = html.escape(manifest_json, quote=True)
    disp_name = manifest_obj["name"]
    if role == "repo-creator":
        perm_desc = (
            "isolated repo-creation permissions (<code>administration: write</code>, "
            "<code>metadata: read</code> — <strong>zero <code>contents</code> access</strong>). "
            "Install with <strong>Only select repositories</strong> so existing Tier-0 repos remain unreachable."
        )
    else:
        perm_desc = (
            "least-privilege permissions (<code>contents: write</code>, "
            "<code>pull_requests: write</code>, <code>actions: read</code>, "
            "<code>checks: read</code>, <code>workflows: write</code> "
            "minted only on explicit OOB <code>--workflows</code> approval, "
            "<code>metadata: read</code>) and no webhooks."
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Create {html.escape(disp_name)} GitHub App</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1.5rem; background: #0f172a; color: #f8fafc; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.75rem; }}
    button {{ background: #10b981; color: #052e16; font-weight: 700; font-size: 1rem; border: none; border-radius: 8px; padding: 0.85rem 1.4rem; cursor: pointer; }}
    code {{ background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 4px; color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>1-Click GitHub App Setup (<code>{html.escape(disp_name)}</code>)</h2>
    <p>This registers a <strong>public: true</strong> GitHub App (for <code>Locknes</code> and <code>locklabs</code>) with {perm_desc}</p>
    <form action="https://github.com/settings/apps/new" method="post">
      <input type="hidden" name="manifest" value="{escaped_manifest}">
      <button type="submit">Create GitHub App on GitHub &rarr;</button>
    </form>
  </div>
</body>
</html>
"""


def write_private_key_atomic(target_path: Path, pem_text: str, mode: int = 0o400) -> None:
    """Atomically write `pem_text` to `target_path` with `0400` permissions and `O_NOFOLLOW`."""
    cleaned = pem_text.strip()
    if "BEGIN" not in cleaned or "PRIVATE KEY" not in cleaned:
        raise ValueError("Invalid PEM private key (missing BEGIN ... PRIVATE KEY header)")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_name(f".{target_path.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, mode)
    try:
        try:
            os.fchmod(fd, mode)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(cleaned + "\n")
            f.flush()
            os.fsync(f.fileno())
        if os.geteuid() == 0:
            os.chown(str(tmp_path), 0, 0)
        os.replace(str(tmp_path), str(target_path))
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise


def update_github_app_config(
    config_path: Path,
    app_id: str,
    private_key_path: Path = DEFAULT_PEM_PATH,
    default_repo_policy: str = "oob",
    allow_vault_pat_fallback: bool = True,
    legacy_http_callback: bool = False,
) -> Dict[str, Any]:
    """Atomically update `module_config.github_token` in `/etc/ha-sudo/config.json`."""
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    else:
        cfg = {}

    if legacy_http_callback:
        cfg["tls_enabled"] = False
        cfg["ha_approval_token"] = ""

    enabled = cfg.get("enabled_modules")
    if isinstance(enabled, list):
        if enabled == ["github_token"]:
            # Restore full module discovery if a prior run collapsed a None list into ["github_token"]
            cfg.pop("enabled_modules", None)
        elif "github_token" not in enabled:
            enabled.append("github_token")
            cfg["enabled_modules"] = enabled

    if legacy_http_callback:
        cfg.setdefault("k8s_apiserver", "https://192.0.2.50:6443")
        cfg.setdefault("k8s_jit_sa_prefix", "jit-agy-")
        cfg.setdefault("k8s_label_domain", "jit.homelab")

    mod_cfg = cfg.setdefault("module_config", {})
    gh_cfg = mod_cfg.setdefault("github_token", {})
    gh_cfg["app_id"] = str(app_id).strip()
    # Keep installation_id empty so ha-oob-gate dynamically queries GET /repos/{owner}/{repo}/installation
    # across personal (Locknes) and organization (locklabs) installations.
    gh_cfg["installation_id"] = ""
    gh_cfg["private_key_path"] = str(private_key_path)
    gh_cfg["default_repo_policy"] = default_repo_policy
    gh_cfg["allow_vault_pat_fallback"] = bool(allow_vault_pat_fallback)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = config_path.with_name(f".{config_path.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(cfg, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    if os.geteuid() == 0:
        os.chown(str(tmp_path), 0, 0)
    os.replace(str(tmp_path), str(config_path))
    return cfg


def update_github_repo_creator_config(
    config_path: Path,
    app_id: str,
    private_key_path: Path = DEFAULT_CREATOR_PEM,
    user_oauth_path: Path = Path(DEFAULT_USER_OAUTH_PATH),
) -> Dict[str, Any]:
    """Atomically update `module_config.github_repo_create` without altering `github_token`."""
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    else:
        cfg = {}

    enabled = cfg.get("enabled_modules")
    if isinstance(enabled, list):
        for req_mod in ("github_repo_create", "github_repo_tier"):
            if req_mod not in enabled:
                enabled.append(req_mod)
        cfg["enabled_modules"] = enabled

    mod_cfg = cfg.setdefault("module_config", {})
    rc_cfg = mod_cfg.setdefault("github_repo_create", {})
    rc_cfg["app_id"] = str(app_id).strip()
    rc_cfg["private_key_path"] = str(private_key_path)
    rc_cfg["user_oauth_path"] = str(user_oauth_path)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = config_path.with_name(f".{config_path.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(cfg, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    if os.geteuid() == 0:
        os.chown(str(tmp_path), 0, 0)
    os.replace(str(tmp_path), str(config_path))
    return cfg


def exchange_manifest_code(code: str, api_url: str = DEFAULT_API_URL) -> Dict[str, Any]:
    """Exchange a one-time GitHub App Manifest `code` for `{id, slug, pem, html_url}`."""
    clean_code = str(code).strip()
    if not clean_code:
        raise ValueError("Manifest code cannot be empty")
    status, data = _github_api_request(
        f"{api_url.rstrip('/')}/app-manifests/{clean_code}/conversions",
        token="",
        method="POST",
        payload={},
    )
    if status not in (200, 201) or not data.get("id") or not data.get("pem"):
        raise RuntimeError(
            f"GitHub App Manifest code exchange failed (HTTP {status}): {data.get('message', data)}"
        )
    return data


def verify_github_app_credentials(
    app_id: str,
    private_key_path: Path,
    api_url: str = DEFAULT_API_URL,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Verify RS256 JWT signing against `GET /app` and list active account installations."""
    app_jwt = create_github_app_jwt(str(app_id), private_key_path=str(private_key_path))
    base = api_url.rstrip("/")
    code_app, app_info = _github_api_request(f"{base}/app", app_jwt, method="GET")
    if code_app != 200 or not app_info.get("id"):
        raise RuntimeError(
            f"Failed to authenticate as GitHub App {app_id} (HTTP {code_app}): {app_info.get('message', '')}"
        )
    code_inst, inst_list = _github_api_request(f"{base}/app/installations", app_jwt, method="GET")
    installations = inst_list if (code_inst == 200 and isinstance(inst_list, list)) else []
    return app_info, installations


def authorize_github_app_user_device_flow(
    client_id: str,
    target_oauth_path: Path = Path(DEFAULT_USER_OAUTH_PATH),
    github_web_url: str = "https://github.com",
) -> Dict[str, Any]:
    """
    Run GitHub's OAuth 2.0 Device Flow for a GitHub App (`client_id` = `Iv...`) so personal
    account repository creation (`POST /user/repos`) works without creating static PATs.
    Requires 'Enable Device Flow' checked in the GitHub App's General settings and
    Repository permission 'Administration: Read and write'.
    """
    clean_cid = str(client_id).strip()
    if not clean_cid:
        raise ValueError("GitHub App client_id is missing from GET /app response")

    base_web = github_web_url.rstrip("/")
    dev_req = urllib.request.Request(
        f"{base_web}/login/device/code",
        data=urllib.parse.urlencode({"client_id": clean_cid}).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "ha-oob-gate/setup-github-app",
        },
        method="POST",
    )
    with urllib.request.urlopen(dev_req, timeout=10) as resp:
        dev_data = json.loads(resp.read().decode("utf-8"))

    device_code = str(dev_data.get("device_code") or "").strip()
    user_code = str(dev_data.get("user_code") or "").strip()
    verify_uri = str(dev_data.get("verification_uri") or f"{base_web}/login/device").strip()
    interval = max(5, int(dev_data.get("interval") or 5))
    expires_in = int(dev_data.get("expires_in") or 900)
    if not device_code or not user_code:
        raise RuntimeError(
            f"GitHub Device Flow initialization failed: {dev_data.get('error_description') or dev_data}"
        )

    print(f"\n[setup-github-app] 🔐 Authorize GitHub App User Token (for personal repo creation):")
    print(f"[setup-github-app]   1. Open:  {verify_uri}")
    print(f"[setup-github-app]   2. Enter: {user_code}\n", flush=True)

    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        poll_req = urllib.request.Request(
            f"{base_web}/login/oauth/access_token",
            data=urllib.parse.urlencode(
                {
                    "client_id": clean_cid,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }
            ).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "ha-oob-gate/setup-github-app",
            },
            method="POST",
        )
        with urllib.request.urlopen(poll_req, timeout=10) as p_resp:
            tok_data = json.loads(p_resp.read().decode("utf-8"))

        err = str(tok_data.get("error") or "")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval = max(interval + 5, int(tok_data.get("interval") or (interval + 5)))
            continue
        if err:
            raise RuntimeError(
                f"GitHub Device Flow authorization failed ({err}): {tok_data.get('error_description', '')}"
            )
        if tok_data.get("access_token"):
            now = int(time.time())
            saved: Dict[str, Any] = {
                "client_id": clean_cid,
                "access_token": str(tok_data["access_token"]).strip(),
                "token_type": str(tok_data.get("token_type") or "bearer"),
                "created_at": now,
            }
            if tok_data.get("refresh_token"):
                saved["refresh_token"] = str(tok_data["refresh_token"]).strip()
            if tok_data.get("expires_in"):
                saved["expires_at"] = now + int(tok_data["expires_in"])
            _write_json_secret_atomic(str(target_oauth_path), saved)
            return saved

    raise RuntimeError("Timed out waiting for GitHub Device Flow authorization")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision and verify a multi-owner GitHub App for ha-oob-gate."
    )
    parser.add_argument(
        "--role",
        default="token-broker",
        choices=["token-broker", "repo-creator"],
        help="GitHub App privilege role: 'token-broker' (contents/PRs) or isolated 'repo-creator' (administration only)",
    )
    parser.add_argument("--code", help="One-time GitHub App Manifest conversion code from redirect URL")
    parser.add_argument("--app-id", help="Existing GitHub App ID")
    parser.add_argument("--pem-file", help="Path to downloaded GitHub App RSA private key (.pem)")
    parser.add_argument(
        "--shred-source",
        action="store_true",
        help="Remove the source --pem-file after copying to /etc/ha-sudo/secrets/",
    )
    parser.add_argument(
        "--write-manifest-html",
        help="Write a 1-click GitHub App Manifest registration HTML file to the given path and exit",
    )
    parser.add_argument(
        "--authorize-user",
        action="store_true",
        help="Run OAuth Device Flow using the configured GitHub App to authorize personal-account repo creation",
    )
    parser.add_argument(
        "--target-oauth",
        default=DEFAULT_USER_OAUTH_PATH,
        help="Target JSON path for GitHub App user OAuth credentials",
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--target-pem", default="", help="Target PEM path (defaults by --role)")
    parser.add_argument("--default-policy", default="oob", choices=["deny", "read", "oob", "write"])
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help="GitHub API base URL")
    parser.add_argument(
        "--legacy-http-callback",
        action="store_true",
        help="Configure tls_enabled=false and ha_approval_token='' for Home Assistant http:// rest_command compatibility",
    )
    parser.add_argument("--restart", action="store_true", help="Restart ha-sudo-gate.service after setup")
    args = parser.parse_args(argv)

    if args.write_manifest_html:
        out_path = Path(args.write_manifest_html)
        out_path.write_text(render_manifest_html(role=args.role), encoding="utf-8")
        print(f"[setup-github-app] Wrote 1-click GitHub App Manifest launcher ({args.role}) to {out_path}")
        return 0

    default_pem = DEFAULT_CREATOR_PEM if args.role == "repo-creator" else DEFAULT_PEM_PATH
    target_pem = Path(args.target_pem) if args.target_pem else default_pem
    config_path = Path(args.config)

    if args.authorize_user:
        app_id_auth = str(args.app_id or "").strip()
        if not app_id_auth and config_path.is_file():
            cfg_existing = json.loads(config_path.read_text(encoding="utf-8"))
            mod_section = "github_repo_create" if args.role == "repo-creator" else "github_token"
            app_id_auth = str(cfg_existing.get("module_config", {}).get(mod_section, {}).get("app_id") or "").strip()
            if not app_id_auth and args.role == "repo-creator":
                app_id_auth = str(cfg_existing.get("module_config", {}).get("github_token", {}).get("app_id") or "").strip()
        if not app_id_auth or not target_pem.is_file():
            parser.error(f"--authorize-user requires an installed GitHub App (app_id + {target_pem})")
            return 2
        app_info_auth, _ = verify_github_app_credentials(app_id_auth, target_pem, api_url=args.api_url)
        authorize_github_app_user_device_flow(
            client_id=str(app_info_auth.get("client_id") or ""),
            target_oauth_path=Path(args.target_oauth),
        )
        print(f"[setup-github-app] ✅ Saved GitHub user OAuth token ({args.role}) to {args.target_oauth} (0400)")
        return 0

    if args.code:
        conv = exchange_manifest_code(args.code, api_url=args.api_url)
        app_id = str(conv["id"])
        pem_text = str(conv["pem"])
        write_private_key_atomic(target_pem, pem_text, mode=0o400)
    elif args.app_id and args.pem_file:
        app_id = str(args.app_id).strip()
        src_pem = Path(args.pem_file)
        if not src_pem.is_file():
            print(f"Error: PEM file not found at {src_pem}", file=sys.stderr)
            return 1
        pem_text = src_pem.read_text(encoding="utf-8")
        write_private_key_atomic(target_pem, pem_text, mode=0o400)
    elif args.app_id and target_pem.is_file():
        app_id = str(args.app_id).strip()
    else:
        parser.error("Provide --code <MANIFEST_CODE>, --app-id <ID> [--pem-file <PATH>], or --write-manifest-html <PATH>")
        return 2

    if args.role == "repo-creator":
        update_github_repo_creator_config(
            config_path=config_path,
            app_id=app_id,
            private_key_path=target_pem,
            user_oauth_path=Path(args.target_oauth),
        )
    else:
        update_github_app_config(
            config_path=config_path,
            app_id=app_id,
            private_key_path=target_pem,
            default_repo_policy=args.default_policy,
            legacy_http_callback=args.legacy_http_callback,
        )

    if args.pem_file and args.shred_source:
        src_pem = Path(args.pem_file)
        if src_pem.resolve() != target_pem.resolve() and src_pem.exists():
            src_pem.unlink()

    app_info, installations = verify_github_app_credentials(
        app_id=app_id,
        private_key_path=target_pem,
        api_url=args.api_url,
    )
    slug = app_info.get("slug", "app")
    installed_accounts = [
        inst.get("account", {}).get("login", "unknown")
        for inst in installations
        if isinstance(inst, dict)
    ]

    print(f"[setup-github-app] ✅ Verified GitHub App '{app_info.get('name')}' (App ID: {app_id}, slug: {slug})")
    print(f"[setup-github-app] 🔒 Private key saved to {target_pem} (0400)")
    print(f"[setup-github-app] ⚙️  Updated {config_path} (default_repo_policy={args.default_policy}, dynamic multi-owner installation lookup)")
    if installed_accounts:
        print(f"[setup-github-app] 📦 Currently installed on accounts: {', '.join(installed_accounts)}")
    else:
        print("[setup-github-app] ⚠️  Not installed on any accounts yet!")
    print(f"[setup-github-app] 👉 Install on both Locknes & locklabs at: https://github.com/apps/{slug}/installations/new")

    if args.restart:
        subprocess.run(["systemctl", "restart", "ha-sudo-gate.service"], check=True)
        print("[setup-github-app] 🔄 Restarted ha-sudo-gate.service")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
