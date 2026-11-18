"""
test_self_update.py - Behavioral & adversarial security tests for SelfUpdateModule (`self_update`):
- Dedicated `OOB GATE UPDATE: <hostname>` Android notification channel & `#DC2626` alert styling
- Caller repo/branch/path override rejection
- Mandatory passing GitHub Actions CI check-run enforcement
- Zip-Slip / symlink / syntax-error tarball preflight rejection before mobile notification
- Zero-TOCTOU staged tarball SHA-256 verification, atomic `.prev` backup swap, and `gate_health` IPC
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import tempfile
import unittest
from typing import Any, Dict, Tuple
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate.daemon import GateEngine
from ha_oob_gate.mcp_server import MCP_TOOLS, dispatch_mcp_tool_call
from ha_oob_gate.modules import CallerInfo
from ha_oob_gate.modules.self_update import _safe_extract_repo_tarball, read_installed_commit


def _build_mock_repo_tarball(
    commit_sha: str,
    *,
    extra_py_code: str = "",
    inject_traversal: bool = False,
    inject_symlink: bool = False,
) -> bytes:
    """Create an in-memory `.tar.gz` mimicking GitHub's `Locknes-ha-oob-gate-<sha>/` tarball structure."""
    buf = io.BytesIO()
    prefix = f"Locknes-ha-oob-gate-{commit_sha[:7]}"
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        if inject_traversal:
            ti = tarfile.TarInfo(name=f"{prefix}/../../etc/evil")
            data = b"pwn"
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

        if inject_symlink:
            ti_sym = tarfile.TarInfo(name=f"{prefix}/ha_oob_gate/evil_link.py")
            ti_sym.type = tarfile.SYMTYPE
            ti_sym.linkname = "/etc/shadow"
            tf.addfile(ti_sym)

        # Copy real `ha_sudo_gate.py`, `ha_oob_gate/` package, and `systemd/` so `--help` smoke check runs cleanly
        rel_files = ["ha_sudo_gate.py", "systemd/ha-sudo-gate.service", "systemd/pam_ha_sudo.sh"]
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "ha_oob_gate")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for fn in sorted(files):
                if fn.endswith(".py"):
                    rel_files.append(os.path.relpath(os.path.join(root, fn), REPO_ROOT))

        for rel in rel_files:
            src_p = os.path.join(REPO_ROOT, rel)
            with open(src_p, "rb") as f:
                raw = f.read()
            if rel == "ha_oob_gate/__init__.py" and extra_py_code:
                raw = raw + b"\n" + extra_py_code.encode("utf-8")
            ti = tarfile.TarInfo(name=f"{prefix}/{rel}")
            ti.size = len(raw)
            ti.mode = 0o755 if rel.endswith((".sh", "cli.py", "daemon.py", "ha_sudo_gate.py")) else 0o644
            tf.addfile(ti, io.BytesIO(raw))

    return buf.getvalue()


class TestSelfUpdateModule(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.install_dir = os.path.join(self.tmp_dir.name, "install_root")
        os.makedirs(self.install_dir, mode=0o755, exist_ok=True)
        with open(os.path.join(self.install_dir, ".installed_commit"), "w", encoding="utf-8") as mf:
            mf.write("1" * 40 + "\n")

        self.target_sha = "a" * 40
        self.config: Dict[str, Any] = {
            "hostname": "oob-bastion-01",
            "ha_url": "https://homeassistant.example.com",
            "ha_trusted_ip": "192.0.2.10",
            "ha_approval_token": "approval-tok-xyz",
            "webhook_id": "c" * 32,
            "callback_host": "192.0.2.20",
            "callback_port": 8443,
            "listen_port": 8443,
            "timeout_seconds": 30,
            "hmac_key_path": os.path.join(self.tmp_dir.name, "hmac.key"),
            "ticket_dir": os.path.join(self.tmp_dir.name, "tickets"),
            "socket_path": os.path.join(self.tmp_dir.name, "daemon.sock"),
            "vault_path": os.path.join(self.tmp_dir.name, "vault.json"),
            "_test_inprocess_swap": True,
            "module_config": {
                "self_update": {
                    "enabled": True,
                    "repo": "Locknes/ha-oob-gate",
                    "branch": "main",
                    "require_ci_green": True,
                    "install_dir": self.install_dir,
                }
            },
        }
        self.engine = GateEngine(self.config)
        self.caller = CallerInfo(uid=1001, gid=1001, pid=7001, username="ai-agent", is_root=False)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_caller_cannot_override_repo_branch_or_paths(self) -> None:
        mod = self.engine.modules["self_update"]
        for bad_params in (
            {"repo": "attacker/evil-gate", "reason": "try custom repo"},
            {"branch": "feat/unmerged", "reason": "try unmerged branch"},
            {"tarball_url": "https://evil.example/payload.tgz", "reason": "try custom url"},
            {"install_dir": "/tmp/hijack", "reason": "try custom install_dir"},
            {"source_dir": "/home/ai-agent/ha-oob-gate", "reason": "try local agent dir"},
        ):
            ok, msg = mod.validate(dict(bad_params), self.caller, self.config)
            self.assertFalse(ok, f"Expected override {bad_params} to be rejected")
            self.assertIn("cannot override", msg)

    def test_ci_checks_and_tarball_safety_enforced_before_notification(self) -> None:
        mod = self.engine.modules["self_update"]

        # 1. Failing CI check-run must block before staging or prompting
        def fake_gh_failing_ci(url: str, token: str, method: str = "GET", payload: Any = None) -> Tuple[int, dict]:
            if url.endswith("/commits/main"):
                return 200, {"sha": self.target_sha, "commit": {"message": "feat: test"}}
            if url.endswith(f"/commits/{self.target_sha}/check-runs"):
                return 200, {
                    "check_runs": [
                        {"name": "Python 3.12", "status": "completed", "conclusion": "failure"},
                    ]
                }
            raise AssertionError(f"Unexpected URL {url}")

        with patch("ha_oob_gate.modules.self_update._github_api_request", side_effect=fake_gh_failing_ci):
            ok_fail, msg_fail = mod.validate({"reason": "Deploy broken build"}, self.caller, self.config)
        self.assertFalse(ok_fail)
        self.assertIn("concluded 'failure'", msg_fail)

        # 2. Zip-Slip & symlink tarballs rejected cleanly
        bad_trav = os.path.join(self.tmp_dir.name, "trav.tgz")
        with open(bad_trav, "wb") as f:
            f.write(_build_mock_repo_tarball(self.target_sha, inject_traversal=True))
        with self.assertRaises(RuntimeError):
            _safe_extract_repo_tarball(bad_trav, os.path.join(self.tmp_dir.name, "out_trav"))

        bad_sym = os.path.join(self.tmp_dir.name, "sym.tgz")
        with open(bad_sym, "wb") as f:
            f.write(_build_mock_repo_tarball(self.target_sha, inject_symlink=True))
        with self.assertRaises(RuntimeError):
            _safe_extract_repo_tarball(bad_sym, os.path.join(self.tmp_dir.name, "out_sym"))

        # 3. Syntax error inside tarball caught by `-I -m compileall` before notification
        syntax_tar_bytes = _build_mock_repo_tarball(self.target_sha, extra_py_code="def broken_syntax(:\n")

        def fake_gh_green(url: str, token: str, method: str = "GET", payload: Any = None) -> Tuple[int, dict]:
            if url.endswith("/commits/main"):
                return 200, {"sha": self.target_sha, "commit": {"message": "feat: bad syntax"}}
            if url.endswith(f"/commits/{self.target_sha}/check-runs"):
                return 200, {"check_runs": [{"name": "CI", "status": "completed", "conclusion": "success"}]}
            raise AssertionError(url)

        class _TarResp:
            def __init__(self, b: bytes) -> None:
                self._b = io.BytesIO(b)

            def read(self, n: int = -1) -> bytes:
                return self._b.read(n)

            def __enter__(self) -> "_TarResp":
                return self

            def __exit__(self, *args: object) -> None:
                return None

        with (
            patch("ha_oob_gate.modules.self_update._github_api_request", side_effect=fake_gh_green),
            patch("urllib.request.urlopen", return_value=_TarResp(syntax_tar_bytes)),
        ):
            ok_syn, msg_syn = mod.validate({"reason": "Deploy syntax error"}, self.caller, self.config)
        self.assertFalse(ok_syn)
        self.assertIn("compilation failed", msg_syn)

    def test_dedicated_oob_update_channel_and_end_to_end_atomic_swap(self) -> None:
        good_tar_bytes = _build_mock_repo_tarball(self.target_sha)
        webhooks_sent = []

        def fake_gh_ok(url: str, token: str, method: str = "GET", payload: Any = None) -> Tuple[int, dict]:
            if url.endswith("/commits/main"):
                return 200, {
                    "sha": self.target_sha,
                    "author": {"login": "Locknes"},
                    "commit": {"message": "feat(ha_api): safe log reader\n\nDetails"},
                    "files": [
                        {"filename": "ha_oob_gate/modules/ha_api.py", "additions": 295, "deletions": 1},
                    ],
                }
            if url.endswith(f"/commits/{self.target_sha}/check-runs"):
                return 200, {
                    "check_runs": [
                        {"name": "Python 3.10", "status": "completed", "conclusion": "success"},
                        {"name": "Python 3.11", "status": "completed", "conclusion": "success"},
                        {"name": "Python 3.12", "status": "completed", "conclusion": "success"},
                    ]
                }
            raise AssertionError(url)

        class _TarResp:
            def __init__(self, b: bytes) -> None:
                self._b = io.BytesIO(b)

            def read(self, n: int = -1) -> bytes:
                return self._b.read(n)

            def __enter__(self) -> "_TarResp":
                return self

            def __exit__(self, *args: object) -> None:
                return None

        with (
            patch("ha_oob_gate.modules.self_update._github_api_request", side_effect=fake_gh_ok),
            patch("urllib.request.urlopen", side_effect=lambda req, timeout=20: _TarResp(good_tar_bytes)),
            patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (webhooks_sent.append(p) or True)),
        ):
            pending = self.engine.submit_and_wait(
                "self_update",
                {"reason": "Deploy safe HA log reader"},
                self.caller,
                wait_seconds=0,
            )
            self.assertEqual(pending["status"], "pending")
            self.assertEqual(len(webhooks_sent), 1)
            wp = webhooks_sent[0]

            # Dedicated high-salience OOB GATE UPDATE channel, group, icon, and crimson color!
            self.assertEqual(wp["channel"], "OOB GATE UPDATE: oob-bastion-01")
            self.assertEqual(wp["group"], "oob_gate_update_oob-bastion-01")
            self.assertEqual(wp["icon"], "mdi:shield-sync")
            self.assertEqual(wp["color"], "#DC2626")
            self.assertIn("OOB GATE UPDATE", wp["title"])
            self.assertIn("TIER-0 SECURITY GATE SELF-UPDATE", wp["message"])
            self.assertIn(f"{'1' * 10} -> {self.target_sha[:10]}", wp["message"])
            self.assertIn("3/3 Checks Passed", wp["message"])
            self.assertIn("ha_oob_gate/modules/ha_api.py (+295/-1)", wp["message"])

            # Approve via callback with required X-HA-Approval-Token
            code, _ = self.engine.handle_ha_callback(
                req_id=pending["request_id"],
                nonce=wp["approve_nonce"],
                action="approve",
                client_ip="192.0.2.10",
                approval_token_hdr="approval-tok-xyz",
            )
            self.assertEqual(code, 200)
            resolved = self.engine.wait_for_resolution(pending["request_id"], timeout=10.0)

        self.assertEqual(resolved["status"], "approved")
        self.assertEqual(resolved["target_commit"], self.target_sha)
        self.assertEqual(read_installed_commit(self.install_dir), self.target_sha)
        self.assertEqual(read_installed_commit(f"{self.install_dir}.prev"), "1" * 40)

        # Verify `gate_health` IPC reports the newly installed commit
        health = self.engine.modules["self_update"].handle_ipc_action("gate_health", {}, self.caller, self.config)
        self.assertIsNotNone(health)
        assert health is not None
        self.assertEqual(health["installed_commit"], self.target_sha)

        # Verify MCP tool `oob_self_update` is registered and dispatches cleanly
        tool_names = {t["name"] for t in MCP_TOOLS}
        self.assertIn("oob_self_update", tool_names)
        mcp_res = dispatch_mcp_tool_call(
            "oob_self_update",
            {"reason": "Test MCP self-update"},
            self.config,
            socket_requester=lambda s, p, t: {"status": "approved", "target_commit": self.target_sha, "restarting": False},
        )
        self.assertFalse(mcp_res["isError"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
