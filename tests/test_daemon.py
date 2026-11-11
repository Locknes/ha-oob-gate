"""
test_daemon.py - Behavioral tests for GateEngine, IPC framing, TLS callback server,
resolved-request retention/eviction, K8s/GitHub modules, and audit secret redaction.
"""

from __future__ import annotations

import builtins
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate.audit import emit_audit_event
from ha_oob_gate.cli import _build_broker_ssl_context, send_unix_socket_request
from ha_oob_gate.daemon import (
    MAX_ACTIVE_LEASES,
    MAX_ACTIVE_REQUESTS,
    GateEngine,
    create_tls_context,
    handle_unix_socket_client,
    load_config,
    make_http_handler,
    verify_ha_callback_origin,
    wrap_http_server_tls,
)
from ha_oob_gate.ipc import FrameTooLargeError, recv_json_frame
from ha_oob_gate.modules import BaseGateModule, CallerInfo, NotificationSpec
from ha_oob_gate.modules.github_token import create_github_app_jwt, evaluate_repo_tag_policy
from ha_oob_gate.sanitize import sanitize_text


class TestDaemonEngineAndIPC(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.ticket_dir = os.path.join(self.tmp_dir.name, "tickets")
        self.vault_path = os.path.join(self.tmp_dir.name, "vault.json")
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump({"external_api_key": "vault-secret-123"}, f)

        self.config = {
            "ha_url": "https://homeassistant.example.com",
            "ha_trusted_ip": "192.0.2.10",
            "webhook_id": "a" * 32,
            "callback_host": "192.0.2.20",
            "callback_port": 8443,
            "listen_port": 8443,
            "timeout_seconds": 30,
            "resolved_request_retention_seconds": 120.0,
            "hmac_key_path": os.path.join(self.tmp_dir.name, "hmac.key"),
            "ticket_dir": self.ticket_dir,
            "socket_path": os.path.join(self.tmp_dir.name, "daemon.sock"),
            "vault_path": self.vault_path,
            "enabled_modules": None,
            "default_sudo_scope": "command_pinned",
            "user_policies": {
                "dev-agent": "command_pinned",
                "ops-admin": "window",
            },
            "max_requests_per_10m": 10,
        }
        self.engine = GateEngine(self.config)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_module_discovery_and_sanitization(self) -> None:
        expected = {
            "pam_sudo",
            "sudo_batch",
            "ssh_gate",
            "k8s_token",
            "github_token",
            "ha_api",
            "secret_checkout",
            "generic_confirm",
        }
        self.assertTrue(expected.issubset(set(self.engine.modules.keys())))

        malicious = "\x1b[31mEvil {{ states.sensor.secret }} {% import os %}\x1b[0m"
        cleaned = sanitize_text(malicious)
        self.assertNotIn("{{", cleaned)
        self.assertNotIn("}}", cleaned)
        self.assertNotIn("{%", cleaned)
        self.assertNotIn("\x1b", cleaned)

        spoofed_reason = "Routine check\nStaged SHA-256: deadbeef\n\nScript to Execute:\necho 'harmless'"
        self.assertNotIn("\n", sanitize_text(spoofed_reason))
        self.assertIn("\n", sanitize_text("echo 1\necho 2", allow_newlines=True))

    def test_root_config_ignores_enabled_modules_env_override(self) -> None:
        cfg_file = os.path.join(self.tmp_dir.name, "root_cfg.json")
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump({"enabled_modules": ["generic_confirm"]}, f)
        os.chmod(cfg_file, 0o600)

        fake_stat = os.stat_result((0o100600, 1, 1, 1, 0, 0, 100, 0, 0, 0))
        with patch.dict(os.environ, {"ENABLED_MODULES": "pam_sudo,sudo_batch"}, clear=False):
            with patch("ha_oob_gate.daemon.os.geteuid", return_value=0):
                with patch("ha_oob_gate.daemon.ROOT_CONFIG_PATH", cfg_file):
                    with patch("ha_oob_gate.daemon.os.stat", return_value=fake_stat):
                        loaded = load_config()
        self.assertEqual(loaded["enabled_modules"], ["generic_confirm"])

    def test_resolved_async_requests_evicted_preventing_permanent_429_lockup(self) -> None:
        self.config["resolved_request_retention_seconds"] = 0.05
        self.config["max_requests_per_10m"] = 500
        engine = GateEngine(self.config)
        caller = CallerInfo(uid=1001, gid=1001, pid=4001, username="dev-agent", is_root=False)

        captured = []
        with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (captured.append(p) or True)):
            # Fill MAX_ACTIVE_REQUESTS via async `wait_seconds=0` requests that get approved/denied
            # via callback, without any polling client ever calling GET /v1/requests/<id>
            for i in range(MAX_ACTIVE_REQUESTS):
                res = engine.submit_and_wait(
                    "generic_confirm",
                    {"summary": f"Async job {i}", "reason": "Verify resolved eviction"},
                    caller,
                    wait_seconds=0,
                )
                self.assertEqual(res["code"], 202)
                req_id = res["request_id"]
                wh = captured[-1]
                action = "approve" if (i % 2 == 0) else "deny"
                nonce = wh["approve_nonce"] if action == "approve" else wh["deny_nonce"]
                code, _ = engine.handle_ha_callback(req_id, nonce, action, "192.0.2.10")
                self.assertEqual(code, 200)

            self.assertEqual(len(engine.active_requests), MAX_ACTIVE_REQUESTS)
            time.sleep(0.08)

            # Next submission must automatically evict expired resolved entries instead of locking up with 429!
            next_res = engine.submit_and_wait(
                "generic_confirm",
                {"summary": "Post-retention job", "reason": "Must succeed without 429"},
                caller,
                wait_seconds=0,
            )
            self.assertEqual(next_res["code"], 202, f"Expected 202 after retention window, got {next_res}")
            self.assertEqual(len(engine.active_requests), 1)

    def test_processing_race_never_returns_pending_to_sync_waiter_and_cleans_up(self) -> None:
        slow_grant_started = threading.Event()
        allow_slow_grant_finish = threading.Event()
        revoked_abandoned: list[str] = []

        class SlowModule(BaseGateModule):
            name = "slow_mod"
            default_ttl_seconds = 120
            run_grant_async = True

            def validate(self, params, caller, config):
                return True, "ok"

            def format_notification(self, params, caller, verify_code, hostname, config):
                return NotificationSpec(title="Slow", message="Slow", command_summary="slow")

            def grant(self, req_id, params, caller, ttl_seconds, config):
                slow_grant_started.set()
                allow_slow_grant_finish.wait(timeout=5.0)
                return {"status": "approved", "marker": "slow_done"}

            def revoke(self, req_id, grant_metadata, config):
                revoked_abandoned.append(req_id)
                return True

        self.engine.modules["slow_mod"] = SlowModule()
        caller = CallerInfo(uid=1001, gid=1001, pid=4002, username="dev-agent", is_root=False)
        captured = []
        with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (captured.append(p) or True)):
            pending = self.engine.submit_and_wait("slow_mod", {}, caller, wait_seconds=0)
            req_id = pending["request_id"]
            caller_nonce = pending["caller_nonce"]
            code, _ = self.engine.handle_ha_callback(req_id, captured[-1]["approve_nonce"], "approve", "192.0.2.10")
            self.assertEqual(code, 200)

        self.assertTrue(slow_grant_started.wait(timeout=2.0))

        # Async poll (`cleanup_on_exit=False`) while grant is in-flight returns `"processing"`
        poll_res = self.engine.wait_for_resolution(req_id, timeout=0.01, cleanup_on_exit=False)
        self.assertEqual(poll_res["status"], "processing")
        self.assertEqual(poll_res["request_id"], req_id)
        self.assertTrue(caller_nonce)

        # Synchronous waiter (`cleanup_on_exit=True`) whose grace window expires while still `"processing"`
        # must return `"timeout"` (NEVER `"pending"`), and once `_grant_worker` finishes it must clean up
        # `active_requests` and immediately revoke the abandoned lease!
        orig_cond_cls = self.engine.active_requests[req_id]["condition"]
        with patch.object(orig_cond_cls, "wait", return_value=False):
            sync_res = self.engine.wait_for_resolution(req_id, timeout=0.0, cleanup_on_exit=True)
        self.assertEqual(sync_res["status"], "timeout")

        allow_slow_grant_finish.set()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and req_id in self.engine.active_requests:
            time.sleep(0.02)

        self.assertNotIn(req_id, self.engine.active_requests)
        self.assertNotIn(req_id, self.engine.active_leases)
        self.assertEqual(revoked_abandoned, [req_id])

    def test_fragmented_unix_socket_json_framing_and_oversized_rejection(self) -> None:
        sock_path = self.config["socket_path"]
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(4)

        def serve_two():
            for _ in range(2):
                conn, _ = srv.accept()
                handle_unix_socket_client(conn, self.engine)

        t = threading.Thread(target=serve_two, daemon=True)
        t.start()
        try:
            # 1. Send fragmented byte chunks without closing write half -> daemon parses newline-delimited frame cleanly
            cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cli.settimeout(5.0)
            cli.connect(sock_path)
            raw_frame = (
                json.dumps(
                    {
                        "action": "revoke",
                        "request_id": "00000000-0000-4000-8000-000000000000",
                        "caller_nonce": "a" * 32,
                        "padding": "X" * 5000,
                    }
                ).encode("utf-8")
                + b"\n"
            )
            for idx in range(0, len(raw_frame), 137):
                cli.sendall(raw_frame[idx : idx + 137])
                time.sleep(0.001)
            resp = recv_json_frame(cli, max_bytes=65536)
            cli.close()
            self.assertEqual(resp, {"status": "not_found"})

            # 2. Oversized frame (>16 KiB) rejected cleanly with error response
            cli2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cli2.settimeout(5.0)
            cli2.connect(sock_path)
            cli2.sendall((b'{"action":"revoke","pad":"' + (b"Z" * 20000) + b'"}\n'))
            err_resp = recv_json_frame(cli2, max_bytes=65536)
            cli2.close()
            self.assertEqual(err_resp["status"], "error")
            self.assertIn("exceeds maximum size", err_resp["message"])
        finally:
            srv.close()

        # Unit check on FrameTooLargeError directly
        a, b = socket.socketpair()
        try:
            a.sendall(b"A" * 256)
            with self.assertRaises(FrameTooLargeError):
                recv_json_frame(b, max_bytes=64)
        finally:
            a.close()
            b.close()

    def test_tls_callback_listener_dual_origin_auth_and_urlencoded_polling(self) -> None:
        self.assertFalse(verify_ha_callback_origin({"ha_trusted_ip": "", "ha_approval_token": ""}, "127.0.0.1", "")[0])

        secret_tok = "a1b2c3d4" * 8
        dual_cfg = dict(self.config)
        dual_cfg["ha_trusted_ip"] = "127.0.0.1"
        dual_cfg["ha_approval_token"] = secret_tok

        self.assertFalse(verify_ha_callback_origin(dual_cfg, "127.0.0.1", "")[0])
        self.assertFalse(verify_ha_callback_origin(dual_cfg, "127.0.0.1", "wrong")[0])
        self.assertFalse(verify_ha_callback_origin(dual_cfg, "198.51.100.25", secret_tok)[0])
        self.assertTrue(verify_ha_callback_origin(dual_cfg, "127.0.0.1", secret_tok)[0])

        cert_path = os.path.join(self.tmp_dir.name, "tls.crt")
        key_path = os.path.join(self.tmp_dir.name, "tls.key")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                key_path,
                "-out",
                cert_path,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dual_cfg["tls_enabled"] = True
        dual_cfg["tls_cert_path"] = cert_path
        dual_cfg["tls_key_path"] = key_path

        tls_ctx = create_tls_context(dual_cfg)
        self.assertEqual(tls_ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

        dual_engine = GateEngine(dual_cfg)
        caller = CallerInfo(uid=1001, gid=1001, pid=4005, username="dev-agent", is_root=False)
        captured = []
        with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (captured.append(p) or True)):
            pending = dual_engine.submit_and_wait(
                "generic_confirm",
                {"summary": "TLS callback test", "reason": "Verify HTTPS + dual auth"},
                caller,
                wait_seconds=0,
            )
        req_id = pending["request_id"]
        caller_nonce = pending["caller_nonce"]
        approve_nonce = captured[0]["approve_nonce"]
        deny_nonce = captured[0]["deny_nonce"]
        self.assertNotEqual(approve_nonce, deny_nonce)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_http_handler(dual_engine))
        self.assertTrue(wrap_http_server_tls(srv, dual_cfg))
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            client_ctx = _build_broker_ssl_context(cert_path)

            # Poll GET /v1/requests/<id> with URL-encoded query parameters (`%30` -> `0`)
            poll_req = urllib.request.Request(
                f"https://127.0.0.1:{port}/v1/requests/{req_id}?caller_nonce={caller_nonce}&wait=%30",
                method="GET",
            )
            with urllib.request.urlopen(poll_req, context=client_ctx, timeout=5) as poll_resp:
                pdata = json.loads(poll_resp.read().decode("utf-8"))
                self.assertEqual(pdata["status"], "pending")

            # Missing X-HA-Approval-Token -> 403
            req_no_tok = urllib.request.Request(
                f"https://127.0.0.1:{port}/approve",
                data=json.dumps({"request_id": req_id, "nonce": approve_nonce, "action": "approve"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx_err:
                urllib.request.urlopen(req_no_tok, context=client_ctx, timeout=5)
            self.assertEqual(ctx_err.exception.code, 403)

            # Cross-nonce attempt (deny_nonce on /approve) -> 401
            req_cross = urllib.request.Request(
                f"https://127.0.0.1:{port}/approve",
                data=json.dumps({"request_id": req_id, "nonce": deny_nonce, "action": "approve"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-HA-Approval-Token": secret_tok},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as cross_err:
                urllib.request.urlopen(req_cross, context=client_ctx, timeout=5)
            self.assertEqual(cross_err.exception.code, 401)

            # Valid trusted IP + header token + approve_nonce -> 200
            req_ok = urllib.request.Request(
                f"https://127.0.0.1:{port}/approve",
                data=json.dumps({"request_id": req_id, "nonce": approve_nonce, "action": "approve"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-HA-Approval-Token": secret_tok},
                method="POST",
            )
            with urllib.request.urlopen(req_ok, context=client_ctx, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_abandoned_client_socket_cancels_request_and_cleans_up_staged_file(self) -> None:
        live_sock = os.path.join(self.tmp_dir.name, "live_cancel.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(live_sock)
        srv.listen(4)
        webhooks_sent = []
        done_evt = threading.Event()

        def serve_one():
            conn, _ = srv.accept()
            try:
                handle_unix_socket_client(conn, self.engine)
            finally:
                done_evt.set()

        with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (webhooks_sent.append(p) or True)):
            threading.Thread(target=serve_one, daemon=True).start()
            cli_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cli_sock.connect(live_sock)
            cli_sock.sendall(
                (
                    json.dumps(
                        {
                            "action": "module_request",
                            "module": "sudo_batch",
                            "params": {"script_content": "echo WILL_CANCEL", "reason": "Test Ctrl+C disconnect"},
                        }
                    )
                    + "\n"
                ).encode("utf-8")
            )
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not self.engine.active_requests:
                time.sleep(0.02)
            self.assertEqual(len(self.engine.active_requests), 1)
            pending_entry = next(iter(self.engine.active_requests.values()))
            staged_file = pending_entry["params"]["_staged_path"]
            self.assertTrue(os.path.exists(staged_file))

            cli_sock.close()
            self.assertTrue(done_evt.wait(timeout=3.0))
            self.assertEqual(len(self.engine.active_requests), 0)
            self.assertFalse(os.path.exists(staged_file))
            self.assertTrue(any(w.get("clear") is True for w in webhooks_sent))
        srv.close()

    def test_github_policy_direct_openssl_key_path_and_rate_limit_accounting(self) -> None:
        # 1. Policy evaluation with oob-* tags & custom properties
        self.assertEqual(evaluate_repo_tag_policy(["oob-write", "oob-deny"], {}, "write")[0], "deny")
        self.assertEqual(evaluate_repo_tag_policy(["oob-read"], {}, "read")[0], "auto")
        self.assertEqual(evaluate_repo_tag_policy(["oob-read"], {}, "write")[0], "deny")
        self.assertEqual(evaluate_repo_tag_policy(["oob-oob"], {}, "read")[0], "auto")
        self.assertEqual(evaluate_repo_tag_policy(["oob-oob"], {}, "write")[0], "oob")
        self.assertEqual(evaluate_repo_tag_policy([], {"oob_access": "write"}, "write")[0], "auto")
        self.assertEqual(evaluate_repo_tag_policy([], {}, "read", default_policy="deny")[0], "deny")

        # 2. OpenSSL fallback passes private_key_path directly (zero tempfile write)
        fake_pem_path = os.path.join(self.tmp_dir.name, "gh_app.pem")
        with open(fake_pem_path, "w", encoding="utf-8") as pf:
            pf.write("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")

        real_import = builtins.__import__

        def mock_no_cryptography(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise ImportError("No cryptography")
            return real_import(name, *args, **kwargs)

        recorded_openssl_argv = []

        def fake_openssl_run(cmd, **kwargs):
            recorded_openssl_argv.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout=b"fake-sig", stderr=b"")

        with patch("builtins.__import__", side_effect=mock_no_cryptography):
            with patch("tempfile.NamedTemporaryFile", side_effect=AssertionError("Must not write private key to tempfile!")):
                with patch("subprocess.run", side_effect=fake_openssl_run):
                    jwt_tok = create_github_app_jwt("12345", private_key_path=fake_pem_path)
        self.assertEqual(len(jwt_tok.split(".")), 3)
        self.assertIn(fake_pem_path, recorded_openssl_argv[0])

        # 3. Rate limit accounting on failed vs auto-approved GitHub requests
        caller = CallerInfo(uid=1001, gid=1001, pid=4010, username="dev-agent", is_root=False)
        gh_cfg = dict(self.config, max_requests_per_10m=2)
        gh_cfg["module_config"] = {
            "github_token": {
                "app_id": "12345",
                "installation_id": "999",
                "private_key_path": fake_pem_path,
                "allow_vault_pat_fallback": False,
                "default_repo_policy": "deny",
            }
        }
        gh_engine = GateEngine(gh_cfg)

        def fake_gh_api_deny(url, token, method="GET", payload=None):
            if url.endswith("/access_tokens") and method == "POST":
                return 201, {"token": "ghs_meta_tok", "expires_at": "2026-11-10T18:00:00Z"}
            if url.endswith("/topics"):
                return 200, {"names": ["oob-deny"]}
            if url.endswith("/properties/values"):
                return 200, []
            return 204, {}

        with patch("ha_oob_gate.modules.github_token.create_github_app_jwt", return_value="fake.jwt.sig"):
            with patch("ha_oob_gate.modules.github_token._github_api_request", side_effect=fake_gh_api_deny):
                self.assertEqual(
                    gh_engine.submit_and_wait(
                        "github_token", {"repo": "org/secret", "permission": "read", "reason": "1"}, caller, wait_seconds=0
                    )["code"],
                    403,
                )
                self.assertEqual(
                    gh_engine.submit_and_wait(
                        "github_token", {"repo": "org/secret", "permission": "read", "reason": "2"}, caller, wait_seconds=0
                    )["code"],
                    403,
                )
                self.assertEqual(
                    gh_engine.submit_and_wait(
                        "github_token", {"repo": "org/secret", "permission": "read", "reason": "3"}, caller, wait_seconds=0
                    )["code"],
                    429,
                )

        auto_engine = GateEngine(gh_cfg)

        def fake_gh_api_auto(url, token, method="GET", payload=None):
            if url.endswith("/access_tokens") and method == "POST":
                return 201, {"token": "ghs_read_tok", "expires_at": "2026-11-10T18:00:00Z"}
            if url.endswith("/topics"):
                return 200, {"names": ["oob-read"]}
            if url.endswith("/properties/values"):
                return 200, []
            return 204, {}

        with patch("ha_oob_gate.modules.github_token.create_github_app_jwt", return_value="fake.jwt.sig"):
            with patch("ha_oob_gate.modules.github_token._github_api_request", side_effect=fake_gh_api_auto):
                for i in range(5):
                    ar = auto_engine.submit_and_wait(
                        "github_token", {"repo": "org/open", "permission": "read", "reason": f"fetch {i}"}, caller, wait_seconds=0
                    )
                    self.assertTrue(ar["auto_approved"])

        with patch("ha_oob_gate.daemon.trigger_ha_webhook", return_value=True):
            self.assertEqual(
                auto_engine.submit_and_wait(
                    "generic_confirm", {"summary": "Interactive OOB", "reason": "Unlocked"}, caller, wait_seconds=0
                )["code"],
                202,
            )

    def test_k8s_token_validation_ttl_clamp_and_atomic_rollback(self) -> None:
        caller = CallerInfo(uid=1001, gid=1001, pid=4020, username="dev-agent", is_root=False)
        k8s_mod = self.engine.modules["k8s_token"]

        self.assertFalse(k8s_mod.validate({"role": "view", "namespaces": ["*"], "reason": "wildcard"}, caller, self.config)[0])
        self.assertFalse(k8s_mod.validate({"role": "cluster-admin", "namespaces": ["default"], "reason": "bad role"}, caller, self.config)[0])
        for bad_ns in ("kube-system", "jit-system", "cert-manager"):
            self.assertFalse(
                k8s_mod.validate({"role": "jit-workload-operator", "namespaces": [bad_ns], "reason": "sys"}, caller, self.config)[0]
            )

        with patch("ha_oob_gate.daemon.trigger_ha_webhook", return_value=True):
            high = self.engine.submit_and_wait(
                "k8s_token",
                {"role": "view", "namespaces": ["default"], "reason": "max clamp", "ttl_seconds": 999999},
                caller,
                wait_seconds=0,
            )
            self.assertEqual(high["ttl_seconds"], 1800)
            low = self.engine.submit_and_wait(
                "k8s_token",
                {"role": "view", "namespaces": ["default"], "reason": "min clamp", "ttl_seconds": -10},
                caller,
                wait_seconds=0,
            )
            self.assertEqual(low["ttl_seconds"], 60)

        k8s_calls = []

        def fake_k8s_api(method, path, body=None, config=None, override_token=None):
            k8s_calls.append((method, path))
            if method == "POST" and path.endswith("/token"):
                raise RuntimeError("Simulated TokenRequest failure")
            return {"status": {"token": "unused"}}

        with patch("ha_oob_gate.modules.k8s_token.k8s_api_request", side_effect=fake_k8s_api):
            with self.assertRaises(RuntimeError):
                k8s_mod.grant(
                    req_id="12345678-aaaa-4bbb-8ccc-1234567890ab",
                    params={"role": "jit-storage-operator", "namespaces": ["app-data"], "reason": "rollback"},
                    caller=caller,
                    ttl_seconds=600,
                    config=self.config,
                )

        delete_paths = [p for m, p in k8s_calls if m == "DELETE"]
        self.assertTrue(any("/namespaces/app-data/rolebindings/jit-oob-12345678aaaa" in p for p in delete_paths))
        self.assertTrue(any("/clusterrolebindings/jit-oob-12345678aaaa" in p for p in delete_paths))
        self.assertTrue(any("/serviceaccounts/jit-oob-12345678aaaa" in p for p in delete_paths))

    def test_lease_eviction_and_audit_redaction_of_arbitrary_secret_keys(self) -> None:
        # 1. Lease capacity eviction revokes oldest lease outside engine.lock
        caller = CallerInfo(uid=1001, gid=1001, pid=4030, username="dev-agent", is_root=False)
        revoked_evictions = []
        with patch.object(
            self.engine.modules["generic_confirm"],
            "revoke",
            side_effect=lambda rid, meta, cfg: (revoked_evictions.append((rid, self.engine.lock.locked())) or True),
        ):
            with self.engine.lock:
                self.engine.active_leases.clear()
                for i in range(MAX_ACTIVE_LEASES):
                    self.engine.active_leases[f"evict-{i}"] = {
                        "request_id": f"evict-{i}",
                        "module": "generic_confirm",
                        "grant_metadata": {},
                        "expires_at": float(100 + i),
                    }
            captured = []
            with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (captured.append(p) or True)):
                p_ev = self.engine.submit_and_wait(
                    "generic_confirm", {"summary": "Evict", "reason": "Evict"}, caller, wait_seconds=0
                )
                self.engine.handle_ha_callback(p_ev["request_id"], captured[-1]["approve_nonce"], "approve", "192.0.2.10")
            self.assertEqual(revoked_evictions, [("evict-0", False)])

        # 2. Audit log replaces exact keys AND arbitrary `*_token` / `*_secret` / `*_key` / `*_password` keys with "[REDACTED]"
        audit_file = os.path.join(self.tmp_dir.name, "audit.jsonl")
        cfg = dict(self.config, audit_log_path=audit_file)
        ok = emit_audit_event(
            "test.event",
            cfg,
            request_id="req-999",
            approve_nonce="nonce-secret-val",
            custom_api_token="tok-secret-val",
            webhook_signing_secret="wh-secret-val",
            db_password="pw-secret-val",
            ssh_private_key="pem-secret-val",
            nested={"token": "ghs_secret123", "safe_field": "visible_value"},
        )
        self.assertTrue(ok)
        with open(audit_file, "r", encoding="utf-8") as f:
            raw_line = f.readline().strip()
        for leaked in ("nonce-secret-val", "tok-secret-val", "wh-secret-val", "pw-secret-val", "pem-secret-val", "ghs_secret123"):
            self.assertNotIn(leaked, raw_line)
        parsed = json.loads(raw_line)
        self.assertEqual(parsed["approve_nonce"], "[REDACTED]")
        self.assertEqual(parsed["custom_api_token"], "[REDACTED]")
        self.assertEqual(parsed["webhook_signing_secret"], "[REDACTED]")
        self.assertEqual(parsed["db_password"], "[REDACTED]")
        self.assertEqual(parsed["ssh_private_key"], "[REDACTED]")
        self.assertEqual(parsed["nested"]["token"], "[REDACTED]")
        self.assertEqual(parsed["nested"]["safe_field"], "visible_value")


if __name__ == "__main__":
    unittest.main(verbosity=2)
