"""
self_update.py - GitHub-Pinned, CI-Verified Tier-0 Gate Self-Update Module (`self_update`).

Security & Anti-Brick Architecture:
1. **Zero Local Agent Disk Trust:**
   Unprivileged callers (`ai-agent`) cannot supply a local file path, custom repository,
   branch, or URL. The root daemon fetches commit metadata, GitHub Actions check-runs,
   and source tarballs strictly from the root-configured repository (`Locknes/ha-oob-gate`,
   branch `main`).
2. **Mandatory Green CI & Zero-TOCTOU Preflight Staging:**
   Before sending a mobile prompt, `validate()` verifies that GitHub Actions CI checks
   completed with `"success"` on the exact 40-char commit SHA, downloads the commit tarball
   into root-owned `/run/ha-sudo/staged/` (`0700 root:root`), validates tar members against
   path traversal / symlinks / special files, compiles all Python bytecode (`-I -m compileall`),
   and pins the tarball's SHA-256 digest.
3. **Dedicated High-Salience Notification Channel (`OOB GATE UPDATE: <hostname>`):**
   Dispatches on a separate Android Companion notification channel and group with a crimson
   (`#DC2626`) alert banner, `mdi:shield-sync` icon, commit SHA diff, CI status, and touched
   file list so a Tier-0 bouncer update can never blend into routine elevation prompts.
4. **Detached `systemd-run` Atomic Swap + 8s Anti-Brick Auto-Rollback Watchdog:**
   `grant()` stages `/usr/local/libexec/ha-sudo.next.<id>`, runs `--help` smoke preflight,
   and launches an independent transient systemd unit outside `ha-sudo-gate.service`'s
   `KillMode=control-group` cgroup. If the restarted daemon fails to answer `gate_health`
   on `/run/ha-sudo/daemon.sock` with the new commit SHA within 8 seconds, the watchdog
   atomically restores `/usr/local/libexec/ha-sudo.prev` and restarts the known-good daemon.
"""

from __future__ import annotations

import hmac
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__
from ..sanitize import sanitize_text, sha256_hex
from . import BaseGateModule, CallerInfo, NotificationSpec
from .github_token import VALID_REPO_RE, _github_api_request, create_github_app_jwt

DEFAULT_SELF_UPDATE_REPO = "Locknes/ha-oob-gate"
DEFAULT_SELF_UPDATE_BRANCH = "main"
DEFAULT_INSTALL_DIR = "/usr/local/libexec/ha-sudo"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
MAX_TARBALL_BYTES = 32 * 1024 * 1024  # 32 MiB download cap
MAX_EXTRACTED_BYTES = 64 * 1024 * 1024  # 64 MiB uncompressed cap
MAX_EXTRACTED_FILES = 1000


def read_installed_commit(install_dir: str = DEFAULT_INSTALL_DIR) -> str:
    """Read the 40-char commit SHA recorded in `<install_dir>/.installed_commit`, or return `""`."""
    marker = os.path.join(install_dir, ".installed_commit")
    if not os.path.isfile(marker):
        return ""
    try:
        with open(marker, "r", encoding="utf-8") as f:
            val = f.read().strip().lower()
            return val if SHA40_RE.match(val) else ""
    except OSError:
        return ""


def _safe_extract_repo_tarball(tar_path: str, dest_dir: str) -> None:
    """
    Safely extract a GitHub commit tarball into `dest_dir`, stripping the single top-level
    `<owner>-<repo>-<sha>/` prefix while rejecting symlinks, hardlinks, device nodes,
    path traversal (`..`), and zip-bomb payloads.
    """
    os.makedirs(dest_dir, mode=0o755, exist_ok=True)
    real_dest = os.path.realpath(dest_dir)
    total_bytes = 0
    file_count = 0

    with tarfile.open(tar_path, mode="r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_EXTRACTED_FILES:
            raise RuntimeError(f"Tarball exceeds maximum file count ({MAX_EXTRACTED_FILES})")

        for member in members:
            raw_name = member.name.replace("\\", "/")
            if raw_name in ("", ".") or raw_name.endswith("/pax_global_header") or raw_name == "pax_global_header":
                continue
            if raw_name.startswith("/") or ".." in raw_name.split("/"):
                raise RuntimeError(f"Unsafe path in tarball rejected: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                raise RuntimeError(f"Disallowed non-regular tar entry rejected: {member.name!r}")

            parts = [p for p in raw_name.split("/") if p and p != "."]
            if len(parts) <= 1:
                # Top-level wrapper directory (`Locknes-ha-oob-gate-<sha>`)
                continue
            rel_path = os.path.join(*parts[1:])
            target_path = os.path.realpath(os.path.join(real_dest, rel_path))
            if target_path != real_dest and not target_path.startswith(real_dest + os.sep):
                raise RuntimeError(f"Tarball path escaped destination: {member.name!r}")

            if member.isdir():
                os.makedirs(target_path, mode=0o755, exist_ok=True)
                continue

            file_count += 1
            total_bytes += max(0, int(member.size))
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise RuntimeError(f"Extracted tarball exceeds {MAX_EXTRACTED_BYTES} byte limit")

            os.makedirs(os.path.dirname(target_path), mode=0o755, exist_ok=True)
            src_f = tf.extractfile(member)
            if src_f is None:
                continue
            oflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target_path, oflags, 0o644)
            with src_f, os.fdopen(fd, "wb") as out_f:
                shutil.copyfileobj(src_f, out_f, length=65536)

    required = (
        os.path.join(real_dest, "ha_sudo_gate.py"),
        os.path.join(real_dest, "ha_oob_gate", "__init__.py"),
        os.path.join(real_dest, "ha_oob_gate", "daemon.py"),
        os.path.join(real_dest, "ha_oob_gate", "cli.py"),
    )
    for req_file in required:
        if not os.path.isfile(req_file):
            raise RuntimeError(f"Extracted archive is missing required file: {os.path.basename(req_file)}")


def _stage_install_tree(extracted_src: str, next_install_dir: str, commit_sha: str) -> None:
    """Assemble a clean `/usr/local/libexec/ha-sudo` layout inside `next_install_dir`."""
    if os.path.exists(next_install_dir):
        shutil.rmtree(next_install_dir)
    os.makedirs(next_install_dir, mode=0o755, exist_ok=True)

    shutil.copytree(
        os.path.join(extracted_src, "ha_oob_gate"),
        os.path.join(next_install_dir, "ha_oob_gate"),
        symlinks=False,
    )
    shutil.copy2(
        os.path.join(extracted_src, "ha_sudo_gate.py"),
        os.path.join(next_install_dir, "ha_sudo_gate.py"),
    )

    optional_files = [
        (os.path.join(extracted_src, "systemd", "pam_ha_sudo.sh"), "pam_ha_sudo.sh", 0o755),
        (os.path.join(extracted_src, "systemd", "ha-sudo-gate.service"), "ha-sudo-gate.service", 0o644),
        (
            os.path.join(extracted_src, "homeassistant", "universal_oob_auth_blueprint.yaml"),
            "universal_oob_auth_blueprint.yaml",
            0o644,
        ),
        (
            os.path.join(extracted_src, "kubernetes", "k8s-jit-rbac-and-guardrails.yaml"),
            "k8s-jit-rbac-and-guardrails.yaml",
            0o644,
        ),
    ]
    for src_p, dst_name, mode in optional_files:
        if os.path.isfile(src_p):
            dst_p = os.path.join(next_install_dir, dst_name)
            shutil.copy2(src_p, dst_p)
            os.chmod(dst_p, mode)

    for root, dirs, files in os.walk(next_install_dir):
        os.chmod(root, 0o755)
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o755)
        for fn in files:
            fp = os.path.join(root, fn)
            st_mode = stat.S_IMODE(os.stat(fp).st_mode)
            if st_mode not in (0o755, 0o644):
                os.chmod(fp, 0o644)

    for exec_rel in (
        "ha_sudo_gate.py",
        os.path.join("ha_oob_gate", "cli.py"),
        os.path.join("ha_oob_gate", "daemon.py"),
        "pam_ha_sudo.sh",
    ):
        ep = os.path.join(next_install_dir, exec_rel)
        if os.path.isfile(ep):
            os.chmod(ep, 0o755)

    marker_path = os.path.join(next_install_dir, ".installed_commit")
    mfd = os.open(marker_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(mfd, "w", encoding="utf-8") as mf:
        mf.write(commit_sha.strip().lower() + "\n")


class SelfUpdateModule(BaseGateModule):
    name = "self_update"
    description = "CI-verified GitHub main self-updater with dedicated alert channel & auto-rollback watchdog"
    default_ttl_seconds = 300
    requires_root_caller = False

    def retain_rate_limit_on_validate_error(self, params: Dict[str, Any]) -> bool:
        return bool(params.get("_gh_api_called"))

    def _get_update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        mod_cfg = config.get("module_config", {}).get("self_update", {})
        gh_cfg = config.get("module_config", {}).get("github_token", {})
        return {
            "enabled": bool(mod_cfg.get("enabled", True)),
            "api_url": str(mod_cfg.get("api_url") or gh_cfg.get("api_url") or "https://api.github.com").rstrip("/"),
            "repo": str(mod_cfg.get("repo") or DEFAULT_SELF_UPDATE_REPO).strip(),
            "branch": str(mod_cfg.get("branch") or DEFAULT_SELF_UPDATE_BRANCH).strip(),
            "require_ci_green": bool(mod_cfg.get("require_ci_green", True)),
            "install_dir": str(mod_cfg.get("install_dir") or DEFAULT_INSTALL_DIR).strip(),
            "service_name": str(mod_cfg.get("service_name") or "ha-sudo-gate.service").strip(),
            "notification_channel": str(mod_cfg.get("notification_channel") or "").strip(),
            "app_id": str(gh_cfg.get("app_id", "")).strip(),
            "installation_id": str(gh_cfg.get("installation_id", "")).strip(),
            "private_key_path": str(gh_cfg.get("private_key_path", "/etc/ha-sudo/secrets/github_app.pem")),
        }

    def handle_ipc_action(
        self,
        action: str,
        req: Dict[str, Any],
        caller: CallerInfo,
        config: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if action != "gate_health":
            return None
        ucfg = self._get_update_config(config)
        return {
            "status": "ok",
            "version": __version__,
            "installed_commit": read_installed_commit(ucfg["install_dir"]),
        }

    def _mint_optional_read_token(self, ucfg: Dict[str, Any]) -> Tuple[str, str]:
        """
        Mint an ephemeral read-only GitHub App token if configured (returning `(token, api_url)`),
        or `("", api_url)` for unauthenticated public GitHub API access.
        """
        api_url = ucfg["api_url"]
        app_id = ucfg["app_id"]
        key_path = ucfg["private_key_path"]
        repo_full = ucfg["repo"]
        if not (app_id and os.path.isfile(key_path)):
            return "", api_url
        try:
            app_jwt = create_github_app_jwt(app_id, private_key_path=key_path)
            inst_id = ucfg["installation_id"]
            if not inst_id:
                code, inst_data = _github_api_request(f"{api_url}/repos/{repo_full}/installation", app_jwt)
                if code != 200 or not inst_data.get("id"):
                    return "", api_url
                inst_id = str(inst_data["id"])
            _, repo_name = repo_full.split("/", 1)
            code, tok_data = _github_api_request(
                f"{api_url}/app/installations/{inst_id}/access_tokens",
                app_jwt,
                method="POST",
                payload={"repositories": [repo_name], "permissions": {"contents": "read", "metadata": "read"}},
            )
            if code == 201 and tok_data.get("token"):
                return str(tok_data["token"]), api_url
        except Exception:
            pass
        return "", api_url

    def _download_tarball(self, url: str, token: str, dest_file: str) -> str:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"ha-oob-gate/{__version__}",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        oflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(dest_file, oflags, 0o400)
        total = 0
        import hashlib

        hasher = hashlib.sha256()
        with urllib.request.urlopen(req, timeout=20) as resp, os.fdopen(fd, "wb") as out_f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TARBALL_BYTES:
                    raise RuntimeError(f"Tarball download exceeded {MAX_TARBALL_BYTES} byte limit")
                hasher.update(chunk)
                out_f.write(chunk)
        return hasher.hexdigest()

    def cleanup_pending_request(self, params: Dict[str, Any]) -> None:
        staged_dir = str(params.get("_staged_dir") or "")
        if staged_dir and os.path.isdir(staged_dir):
            shutil.rmtree(staged_dir, ignore_errors=True)

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        ucfg = self._get_update_config(config)
        if not ucfg["enabled"]:
            return False, "Security policy: self_update module is disabled in /etc/ha-sudo/config.json"

        # Callers may NEVER override repository, branch, URL, or install directory
        for forbidden_override in ("repo", "branch", "url", "tarball_url", "install_dir", "source_dir"):
            if forbidden_override in params and params[forbidden_override] not in ("", None):
                val = str(params[forbidden_override]).strip()
                if forbidden_override == "repo" and val == ucfg["repo"]:
                    continue
                if forbidden_override == "branch" and val == ucfg["branch"]:
                    continue
                return (
                    False,
                    f"Security policy: caller cannot override '{forbidden_override}' on self_update "
                    f"(pinned to {ucfg['repo']}@{ucfg['branch']})",
                )

        reason = str(params.get("reason") or "").strip()
        if not reason:
            return False, "A human-readable --reason is required for self-update"
        if len(reason) > 200:
            return False, "reason exceeds maximum displayable length (200 chars)"

        repo_full = ucfg["repo"]
        branch = ucfg["branch"]
        if not VALID_REPO_RE.match(repo_full) or not SAFE_BRANCH_RE.match(branch) or ".." in branch:
            return False, "Invalid self_update repository or branch in root configuration"

        params["_gh_api_called"] = True
        gh_tok, api_url = self._mint_optional_read_token(ucfg)
        try:
            code, commit_data = _github_api_request(f"{api_url}/repos/{repo_full}/commits/{branch}", gh_tok)
            if code != 200 or not isinstance(commit_data, dict):
                return (
                    False,
                    f"Failed to query {repo_full}@{branch} on GitHub (HTTP {code}: {commit_data.get('message', '')})",
                )

            commit_sha = str(commit_data.get("sha") or "").strip().lower()
            if not SHA40_RE.match(commit_sha):
                return False, "GitHub API returned malformed commit SHA"

            commit_info = commit_data.get("commit") or {}
            raw_msg = str(commit_info.get("message") or "").strip()
            commit_title = raw_msg.splitlines()[0] if raw_msg else commit_sha[:12]
            author_info = commit_data.get("author") or commit_info.get("author") or {}
            commit_author = str(author_info.get("login") or author_info.get("name") or "unknown")

            raw_files = commit_data.get("files")
            changed_files: List[str] = []
            if isinstance(raw_files, list):
                for f_item in raw_files[:12]:
                    if isinstance(f_item, dict) and f_item.get("filename"):
                        adds = int(f_item.get("additions") or 0)
                        dels = int(f_item.get("deletions") or 0)
                        changed_files.append(f"{f_item['filename']} (+{adds}/-{dels})")
                if len(raw_files) > 12:
                    changed_files.append(f"... (+{len(raw_files) - 12} more files)")

            # Verify GitHub Actions CI check-runs on the exact commit SHA
            passed_checks = 0
            total_checks = 0
            if ucfg["require_ci_green"]:
                chk_code, chk_data = _github_api_request(
                    f"{api_url}/repos/{repo_full}/commits/{commit_sha}/check-runs", gh_tok
                )
                if chk_code in (401, 403) and gh_tok:
                    # GitHub App token without `checks: read` on a public repo: retry unauthenticated
                    chk_code, chk_data = _github_api_request(
                        f"{api_url}/repos/{repo_full}/commits/{commit_sha}/check-runs", ""
                    )
                if chk_code != 200 or not isinstance(chk_data, dict):
                    return False, f"Cannot verify CI check-runs for {commit_sha[:12]} (HTTP {chk_code})"
                runs = chk_data.get("check_runs") or []
                total_checks = len(runs)
                if total_checks < 1:
                    return (
                        False,
                        f"Refusing self-update to {commit_sha[:12]}: 0 GitHub Actions CI check-runs found",
                    )
                for r in runs:
                    st = str(r.get("status") or "")
                    concl = str(r.get("conclusion") or "")
                    r_name = str(r.get("name") or "check")
                    if st != "completed":
                        return (
                            False,
                            f"Refusing self-update to {commit_sha[:12]}: CI check '{r_name}' is still '{st}'",
                        )
                    if concl not in ("success", "skipped", "neutral"):
                        return (
                            False,
                            f"Refusing self-update to {commit_sha[:12]}: CI check '{r_name}' concluded '{concl}'",
                        )
                    if concl == "success":
                        passed_checks += 1
                if passed_checks < 1:
                    return False, f"Refusing self-update to {commit_sha[:12]}: no passing CI checks"

            # Zero-TOCTOU staging & bytecode compilation preflight BEFORE sending notification
            ticket_dir = str(config.get("ticket_dir", "/run/ha-sudo"))
            stage_id = uuid.uuid4().hex
            staged_dir = os.path.join(ticket_dir, "staged", f"self_update_{stage_id}")
            os.makedirs(staged_dir, mode=0o700, exist_ok=True)
            os.chmod(staged_dir, 0o700)
            params["_staged_dir"] = staged_dir

            tarball_path = os.path.join(staged_dir, "source.tar.gz")
            tarball_url = f"{api_url}/repos/{repo_full}/tarball/{commit_sha}"
            try:
                tarball_sha256 = self._download_tarball(tarball_url, gh_tok, tarball_path)
                preview_dir = os.path.join(staged_dir, "preview")
                _safe_extract_repo_tarball(tarball_path, preview_dir)
                comp = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-m",
                        "compileall",
                        "-q",
                        os.path.join(preview_dir, "ha_oob_gate"),
                        os.path.join(preview_dir, "ha_sudo_gate.py"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if comp.returncode != 0:
                    return False, f"Preflight bytecode compilation failed: {comp.stderr or comp.stdout}"
                shutil.rmtree(preview_dir, ignore_errors=True)
            except Exception as e:
                shutil.rmtree(staged_dir, ignore_errors=True)
                params.pop("_staged_dir", None)
                return False, f"Failed to stage and preflight {repo_full}@{commit_sha[:12]}: {e}"
        finally:
            if gh_tok:
                try:
                    _github_api_request(f"{api_url}/installation/token", gh_tok, method="DELETE")
                except Exception:
                    pass

        installed_sha = read_installed_commit(ucfg["install_dir"])
        params["_stage_id"] = stage_id
        params["_tarball_path"] = tarball_path
        params["_tarball_sha256"] = tarball_sha256
        params["_target_sha"] = commit_sha
        params["_installed_sha"] = installed_sha
        params["_commit_title"] = commit_title
        params["_commit_author"] = commit_author
        params["_changed_files"] = changed_files
        params["_ci_passed"] = passed_checks
        params["_ci_total"] = total_checks
        params["_repo"] = repo_full
        params["_branch"] = branch
        return True, "ok"

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        ucfg = self._get_update_config(config)
        channel = ucfg["notification_channel"] or f"OOB GATE UPDATE: {hostname}"
        group = f"oob_gate_update_{hostname}"

        repo_full = sanitize_text(params.get("_repo", DEFAULT_SELF_UPDATE_REPO), max_len=100)
        branch = sanitize_text(params.get("_branch", DEFAULT_SELF_UPDATE_BRANCH), max_len=64)
        target_sha = str(params.get("_target_sha") or "")
        short_target = target_sha[:10]
        installed_sha = str(params.get("_installed_sha") or "")
        short_installed = installed_sha[:10] if installed_sha else "unknown"
        tar_sha_short = str(params.get("_tarball_sha256") or "")[:12]
        ci_passed = int(params.get("_ci_passed") or 0)
        ci_total = int(params.get("_ci_total") or 0)
        commit_title = sanitize_text(params.get("_commit_title", ""), max_len=160)
        commit_author = sanitize_text(params.get("_commit_author", ""), max_len=64)
        reason = sanitize_text(params.get("reason", ""), max_len=200)
        caller_disp = caller.k8s_identity or f"{caller.username} (UID {caller.uid})"

        changed_files = params.get("_changed_files") or []
        files_block = (
            "\n".join(f"• {sanitize_text(fn, max_len=120)}" for fn in changed_files)
            if changed_files
            else "• (merge commit — see PR diff)"
        )
        ci_line = f"✅ {ci_passed}/{ci_total} Checks Passed" if ci_total else "Skipped (config)"

        title = f"🚨 OOB GATE UPDATE [{hostname}] [{verify_code}]"
        message = (
            f"⚠️ TIER-0 SECURITY GATE SELF-UPDATE\n"
            f"Channel: {channel}\n"
            f"Host: {hostname}\n"
            f"Caller: {caller_disp}\n"
            f"Repo: {repo_full} ({branch})\n"
            f"Version: {short_installed} -> {short_target}\n"
            f"CI Suite: {ci_line}\n"
            f"Tarball SHA-256: {tar_sha_short}...\n\n"
            f"Commit ({commit_author}):\n"
            f"{commit_title}\n\n"
            f"Modified Files:\n"
            f"{files_block}\n\n"
            f"Reason: {reason}"
        )
        summary = f"self-update {repo_full}@{short_target}: {commit_title}"
        return NotificationSpec(
            title=title,
            message=message,
            approve_title=f"Update Gate [{short_target}] [{verify_code}]",
            deny_title="Deny Update",
            approved_title=f"✅ OOB Gate Updating [{short_target}]",
            approved_message=f"Applying {repo_full}@{short_target} on {hostname} (auto-rollback armed).",
            denied_title=f"🛑 OOB Gate Update Denied [{verify_code}]",
            denied_message=f"Rejected Tier-0 gate update ({short_target}) from {caller_disp}.",
            timeout_title=f"⏱️ OOB Gate Update Timed Out [{verify_code}]",
            timeout_message=f"Expired without approval ({short_target}).",
            command_summary=summary,
            icon="mdi:shield-sync",
            color="#DC2626",
            channel=channel,
            group=group,
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        ucfg = self._get_update_config(config)
        install_dir = ucfg["install_dir"]
        service_name = ucfg["service_name"]
        stage_id = str(params.get("_stage_id") or uuid.uuid4().hex)
        staged_dir = str(params.get("_staged_dir") or "")
        tarball_path = str(params.get("_tarball_path") or "")
        expected_tar_sha = str(params.get("_tarball_sha256") or "")
        target_sha = str(params.get("_target_sha") or "")
        previous_sha = str(params.get("_installed_sha") or "")

        if not tarball_path or not os.path.isfile(tarball_path):
            return {"status": "error", "message": "Staged update tarball is missing"}

        with open(tarball_path, "rb") as tf:
            actual_sha = sha256_hex(tf.read())
        if not hmac.compare_digest(actual_sha, expected_tar_sha):
            self.cleanup_pending_request(params)
            return {"status": "error", "message": "Security alert: Staged tarball SHA-256 mismatch"}

        extract_dir = os.path.join(staged_dir, "extracted")
        next_install_dir = f"{install_dir}.next.{stage_id[:12]}"
        try:
            _safe_extract_repo_tarball(tarball_path, extract_dir)
            _stage_install_tree(extract_dir, next_install_dir, target_sha)

            # Preflight smoke test (`--help`) against the staged entrypoint
            smoke = subprocess.run(
                [sys.executable, "-I", os.path.join(next_install_dir, "ha_sudo_gate.py"), "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if smoke.returncode != 0:
                shutil.rmtree(next_install_dir, ignore_errors=True)
                self.cleanup_pending_request(params)
                return {
                    "status": "error",
                    "message": f"Staged entrypoint smoke check failed: {smoke.stderr or smoke.stdout}",
                }
        except Exception as e:
            shutil.rmtree(next_install_dir, ignore_errors=True)
            self.cleanup_pending_request(params)
            return {"status": "error", "message": f"Failed staging self-update tree: {e}"}

        # Deterministic in-process swap path for non-root unit tests
        if config.get("_test_inprocess_swap"):
            prev_dir = f"{install_dir}.prev"
            shutil.rmtree(prev_dir, ignore_errors=True)
            if os.path.exists(install_dir):
                os.replace(install_dir, prev_dir)
            os.replace(next_install_dir, install_dir)
            self.cleanup_pending_request(params)
            return {
                "status": "approved",
                "previous_commit": previous_sha,
                "target_commit": target_sha,
                "restarting": False,
            }

        systemd_run_bin = shutil.which("systemd-run")
        if os.geteuid() != 0 or not systemd_run_bin or not os.path.isdir("/run/systemd/system"):
            shutil.rmtree(next_install_dir, ignore_errors=True)
            self.cleanup_pending_request(params)
            return {
                "status": "error",
                "message": "Root systemd environment (systemd-run) is required to perform live daemon self-update",
            }

        socket_path = str(config.get("socket_path", "/run/ha-sudo/daemon.sock"))
        unit_file_dst = f"/etc/systemd/system/{service_name}"
        apply_script_path = os.path.join(os.path.dirname(staged_dir), f"apply_self_update_{stage_id[:12]}.sh")
        unit_name = f"ha-oob-self-update-{req_id.replace('-', '')[:12]}"

        q_install = shlex.quote(install_dir)
        q_prev = shlex.quote(f"{install_dir}.prev")
        q_next = shlex.quote(next_install_dir)
        q_staged = shlex.quote(staged_dir)
        q_script = shlex.quote(apply_script_path)
        q_svc = shlex.quote(service_name)
        q_unit_dst = shlex.quote(unit_file_dst)
        q_sock = shlex.quote(socket_path)
        q_sha = shlex.quote(target_sha)
        q_py = shlex.quote(sys.executable)

        script_body = f"""#!/bin/bash
set -uo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Allow current daemon ~0.6s to flush the Unix socket approval response to caller
sleep 0.6

rm -rf {q_prev}
if [ -d {q_install} ]; then
    mv {q_install} {q_prev}
fi
mv {q_next} {q_install}
chown -R root:root {q_install}

ln -sf {q_install}/ha_sudo_gate.py /usr/local/bin/oob-auth
ln -sf {q_install}/ha_sudo_gate.py /usr/local/bin/ha-oob-gate

if [ -f {q_install}/ha-sudo-gate.service ]; then
    if [ -f {q_unit_dst} ]; then
        cp -f {q_unit_dst} {q_unit_dst}.prev
    fi
    cp -f {q_install}/ha-sudo-gate.service {q_unit_dst}
    chown root:root {q_unit_dst}
    chmod 0644 {q_unit_dst}
fi

if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF {q_install} {q_unit_dst} /usr/local/bin/oob-auth /usr/local/bin/ha-oob-gate 2>/dev/null || true
fi

systemctl daemon-reload
systemctl restart {q_svc}

HEALTHY=0
for _ in $(seq 1 16); do
    sleep 0.5
    if systemctl is-active --quiet {q_svc} && [ -S {q_sock} ]; then
        if {q_py} -I - {q_sock} {q_sha} << 'PYCHECK'
import json, socket, struct, sys
sock_p, exp_sha = sys.argv[1], sys.argv[2]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(2.0)
    s.connect(sock_p)
    s.sendall((json.dumps({{"action": "gate_health"}}) + "\\n").encode("utf-8"))
    data = b""
    while b"\\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
resp = json.loads(data.decode("utf-8").strip())
sys.exit(0 if resp.get("status") == "ok" and resp.get("installed_commit") == exp_sha else 1)
PYCHECK
        then
            HEALTHY=1
            break
        fi
    fi
done

rm -rf {q_staged}

if [ "$HEALTHY" -eq 1 ]; then
    logger -t ha-oob-watchdog "Self-update to {target_sha[:12]} succeeded and passed socket health check." 2>/dev/null || true
    rm -f {q_script}
    exit 0
fi

logger -p authpriv.crit -t ha-oob-watchdog "Self-update to {target_sha[:12]} FAILED health check! Rolling back to .prev..." 2>/dev/null || true
rm -rf {q_install}.failed
mv {q_install} {q_install}.failed 2>/dev/null || true
if [ -d {q_prev} ]; then
    mv {q_prev} {q_install}
fi
if [ -f {q_unit_dst}.prev ]; then
    cp -f {q_unit_dst}.prev {q_unit_dst}
fi
if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF {q_install} {q_unit_dst} 2>/dev/null || true
fi
systemctl daemon-reload
systemctl restart {q_svc}
rm -rf {q_install}.failed {q_script}
exit 1
"""
        sfd = os.open(apply_script_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o500)
        with os.fdopen(sfd, "w", encoding="utf-8") as sf:
            sf.write(script_body)

        launch = subprocess.run(
            [
                systemd_run_bin,
                "--no-block",
                "--collect",
                "--quiet",
                f"--unit={unit_name}",
                "--property=RuntimeMaxSec=60",
                "/bin/bash",
                apply_script_path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if launch.returncode != 0:
            shutil.rmtree(next_install_dir, ignore_errors=True)
            self.cleanup_pending_request(params)
            try:
                os.remove(apply_script_path)
            except OSError:
                pass
            return {
                "status": "error",
                "message": f"Failed to spawn detached systemd self-update unit: {launch.stderr or launch.stdout}",
            }

        return {
            "status": "approved",
            "previous_commit": previous_sha,
            "target_commit": target_sha,
            "restarting": True,
            "channel": ucfg["notification_channel"] or f"OOB GATE UPDATE: {config.get('hostname') or 'host'}",
        }
