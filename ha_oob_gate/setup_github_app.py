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
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .modules.github_token import _github_api_request, create_github_app_jwt

DEFAULT_CONFIG_PATH = Path("/etc/ha-sudo/config.json")
DEFAULT_PEM_PATH = Path("/etc/ha-sudo/secrets/github_app.pem")
DEFAULT_API_URL = "https://api.github.com"


def build_app_manifest(
    app_name: str = "locklab-oob-gate",
    homepage_url: str = "https://github.com/Locknes/ha-oob-gate",
    redirect_url: str = "http://127.0.0.1:8788/callback",
) -> Dict[str, Any]:
    """Return a GitHub App Manifest dictionary configured for multi-owner single-repo token brokering."""
    return {
        "name": app_name,
        "url": homepage_url,
        "redirect_url": redirect_url,
        "public": True,
        "default_permissions": {
            "contents": "write",
            "pull_requests": "write",
            "metadata": "read",
        },
        "default_events": [],
    }


def render_manifest_html(
    app_name: str = "locklab-oob-gate",
    homepage_url: str = "https://github.com/Locknes/ha-oob-gate",
    redirect_url: str = "http://127.0.0.1:8788/callback",
) -> str:
    """Render a self-contained HTML page with a 1-click form that registers the GitHub App via Manifest."""
    manifest_json = json.dumps(build_app_manifest(app_name, homepage_url, redirect_url))
    escaped_manifest = html.escape(manifest_json, quote=True)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Create {html.escape(app_name)} GitHub App</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1.5rem; background: #0f172a; color: #f8fafc; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.75rem; }}
    button {{ background: #10b981; color: #052e16; font-weight: 700; font-size: 1rem; border: none; border-radius: 8px; padding: 0.85rem 1.4rem; cursor: pointer; }}
    code {{ background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 4px; color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>1-Click GitHub App Setup (<code>{html.escape(app_name)}</code>)</h2>
    <p>This registers a <strong>public: true</strong> GitHub App (so you can install it on both <code>Locknes</code> and <code>locklabs</code>) with least-privilege permissions (<code>contents: write</code>, <code>pull_requests: write</code>, <code>metadata: read</code>) and no webhooks.</p>
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision and verify a multi-owner GitHub App for ha-oob-gate."
    )
    parser.add_argument("--code", help="One-time GitHub App Manifest conversion code from redirect URL")
    parser.add_argument("--app-id", help="Existing GitHub App ID")
    parser.add_argument("--pem-file", help="Path to downloaded GitHub App RSA private key (.pem)")
    parser.add_argument(
        "--shred-source",
        action="store_true",
        help="Remove the source --pem-file after copying to /etc/ha-sudo/secrets/github_app.pem",
    )
    parser.add_argument(
        "--write-manifest-html",
        help="Write a 1-click GitHub App Manifest registration HTML file to the given path and exit",
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--target-pem", default=str(DEFAULT_PEM_PATH), help="Target PEM path")
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
        out_path.write_text(render_manifest_html(), encoding="utf-8")
        print(f"[setup-github-app] Wrote 1-click GitHub App Manifest launcher to {out_path}")
        return 0

    target_pem = Path(args.target_pem)
    config_path = Path(args.config)

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
