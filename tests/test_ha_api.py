"""
test_ha_api.py - Behavioral tests for HaApiModule, single-call `allowed_domains`
enforcement, structured payload inspection (without benign prose false positives),
and generic `GateEngine.dispatch_lease_rpc()` lifecycle.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate.daemon import GateEngine
from ha_oob_gate.modules import CallerInfo
from ha_oob_gate.modules.ha_api import (
    execute_ha_proxy_call,
    redact_ha_log_output,
    validate_ha_proxy_call,
)


class TestHaApiProxyModule(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.vault_path = os.path.join(self.tmp_dir.name, "vault.json")
        with open(self.vault_path, "w", encoding="utf-8") as vf:
            json.dump({"ha_admin_token": "secret-ha-jwt", "backup_key": "ok-secret"}, vf)

        self.config = {
            "ha_url": "https://homeassistant.example.com",
            "ha_trusted_ip": "192.0.2.10",
            "ha_admin_token": "mock-root-ha-token",
            "webhook_id": "d" * 32,
            "callback_host": "192.0.2.20",
            "callback_port": 8443,
            "listen_port": 8443,
            "timeout_seconds": 30,
            "hmac_key_path": os.path.join(self.tmp_dir.name, "hmac.key"),
            "ticket_dir": os.path.join(self.tmp_dir.name, "tickets"),
            "socket_path": os.path.join(self.tmp_dir.name, "daemon.sock"),
            "vault_path": self.vault_path,
        }
        self.engine = GateEngine(self.config)
        self.caller = CallerInfo(uid=1001, gid=1001, pid=6001, username="ai-agent", is_root=False)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_self_approval_and_escalation_endpoints_blocked(self) -> None:
        blocked = [
            ("POST", "/api/events/mobile_app_notification_action", {"action": "APPROVE_OOB_123"}, ["light"]),
            ("POST", "/api/events/%6dobile_app_notification_action", {"action": "APPROVE_OOB_123"}, ["light"]),
            ("POST", "/api/webhook/some_webhook_id", {}, ["light"]),
            ("POST", "/api/HandleWebhook/hook", {}, ["light"]),
            ("POST", "/api/services/rest_command/oob_gate_callback", {"request_id": "123"}, ["rest_command"]),
            ("POST", "/api/services/notify/mobile_app_phone", {"message": "spoof"}, ["notify"]),
            ("POST", "/api/services/shell_command/run_root", {}, ["shell_command"]),
            ("POST", "/api/services/homeassistant/turn_on", {"entity_id": "script.root"}, ["homeassistant"]),
            ("POST", "/api/services/mqtt/publish", {"topic": "cmd"}, ["mqtt"]),
            ("POST", "/api/services/automation/turn_off", {"entity_id": "all"}, ["automation"]),
            ("POST", "/api/auth/long_lived_access_token", {}, ["light"]),
            ("POST", "/api/template", {"template": "{{ states }}"}, ["light"]),
            ("POST", "/api/states/lock.front_door", {"state": "unlocked"}, ["lock"]),
            ("DELETE", "/api/states/binary_sensor.door", None, ["binary_sensor"]),
            ("GET", "/api/../api/webhook/test", None, ["light"]),
        ]
        for method, path, body, doms in blocked:
            ok, _ = validate_ha_proxy_call(method, path, body, scope="admin", allowed_domains=doms)
            self.assertFalse(ok, f"Expected {method} {path} to be blocked")

        # Structured payload inspection blocks OOB entity/action targeting (including JSON-escaped `\u0061pprove_oob_`)
        self.assertFalse(
            validate_ha_proxy_call(
                "POST",
                "/api/services/light/turn_on",
                '{"entity_id": "automation.universal_oob_auth_gate"}',
                scope="admin",
                allowed_domains=["light"],
            )[0]
        )
        self.assertFalse(
            validate_ha_proxy_call(
                "POST",
                "/api/services/light/turn_on",
                '{"action": "\\u0061pprove_oob_123456"}',
                scope="admin",
                allowed_domains=["light"],
            )[0]
        )

        # Benign prose fields (e.g. `todo.add_item` or calendar descriptions mentioning "oob" or "sudo") MUST succeed!
        ok_benign, err_benign = validate_ha_proxy_call(
            "POST",
            "/api/services/todo/add_item",
            {"entity_id": "todo.engineering_tasks", "item": "Rotate ha_oob_gate TLS cert and test sudo gate"},
            scope="admin",
            allowed_domains=["todo"],
        )
        self.assertTrue(ok_benign, f"Benign prose body falsely rejected: {err_benign}")

    def test_single_mode_enforces_allowed_domains_in_validate_and_grant(self) -> None:
        ha_mod = self.engine.modules["ha_api"]

        # `mode='single'` with `domains=['light']` trying to call `/api/services/lock/unlock` MUST fail!
        ok_mismatch, msg_mismatch = ha_mod.validate(
            {
                "mode": "single",
                "scope": "admin",
                "domains": ["light"],
                "method": "POST",
                "path": "/api/services/lock/unlock",
                "body": {"entity_id": "lock.front_door"},
                "reason": "Attempt cross-domain single call",
            },
            self.caller,
            self.config,
        )
        self.assertFalse(ok_mismatch)
        self.assertIn("allowed_domains", msg_mismatch)

        # Even if params are mutated before grant(), grant() re-enforces `allowed_domains=clean_domains`
        with self.assertRaises(PermissionError):
            ha_mod.grant(
                req_id="req-single-mismatch",
                params={
                    "mode": "single",
                    "scope": "admin",
                    "domains": ["light"],
                    "method": "POST",
                    "path": "/api/services/lock/unlock",
                    "body": {"entity_id": "lock.front_door"},
                    "reason": "Mutated path",
                },
                caller=self.caller,
                ttl_seconds=900,
                config=self.config,
            )

        # Unscoped admin without domains fails unless allow_unscoped_ha_admin=True
        ok_no_dom, _ = ha_mod.validate(
            {"mode": "lease", "scope": "admin", "domains": [], "reason": "No domains"},
            self.caller,
            self.config,
        )
        self.assertFalse(ok_no_dom)

    def test_raw_ha_admin_token_blocked_in_secret_checkout_and_lease_rpc_enforces_caller(self) -> None:
        res_sec = self.engine.submit_and_wait(
            "secret_checkout",
            {"key": "ha_admin_token", "reason": "Attempt raw token checkout"},
            self.caller,
            wait_seconds=0,
        )
        self.assertEqual(res_sec["status"], "error")
        self.assertIn("cannot be checked out raw", res_sec["message"])

        captured = []
        with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (captured.append(p) or True)):
            pending = self.engine.submit_and_wait(
                "ha_api",
                {"mode": "lease", "scope": "admin", "domains": ["light"], "reason": "Control office lights"},
                self.caller,
                wait_seconds=0,
            )
            req_id = pending["request_id"]
            caller_nonce = pending["caller_nonce"]
            code, _ = self.engine.handle_ha_callback(
                req_id=req_id,
                nonce=captured[-1]["approve_nonce"],
                action="approve",
                client_ip="192.0.2.10",
            )
            self.assertEqual(code, 200)

        with patch(
            "ha_oob_gate.modules.ha_api.execute_ha_proxy_call",
            return_value={"status": "ok", "http_status": 200, "data": [{"entity_id": "light.office"}]},
        ):
            proxy_ok = self.engine.dispatch_lease_rpc(
                req_id=req_id,
                caller_nonce=caller_nonce,
                action="ha_proxy_call",
                payload={"method": "POST", "path": "/api/services/light/turn_on", "body": {"entity_id": "light.office"}},
                caller=self.caller,
                expected_module="ha_api",
            )
            self.assertEqual(proxy_ok["status"], "ok")

            # Different UID rejected even with stolen caller_nonce
            other_caller = CallerInfo(uid=1002, gid=1002, pid=6099, username="other-user", is_root=False)
            wrong_caller = self.engine.dispatch_lease_rpc(
                req_id=req_id,
                caller_nonce=caller_nonce,
                action="ha_proxy_call",
                payload={"method": "GET", "path": "/api/states"},
                caller=other_caller,
                expected_module="ha_api",
            )
            self.assertEqual(wrong_caller["code"], 403)
            self.assertIn("Caller identity mismatch", wrong_caller["message"])

            # Domain outside lease (`lock`) rejected
            wrong_domain = self.engine.dispatch_lease_rpc(
                req_id=req_id,
                caller_nonce=caller_nonce,
                action="ha_proxy_call",
                payload={"method": "POST", "path": "/api/services/lock/unlock", "body": {"entity_id": "lock.front"}},
                caller=self.caller,
                expected_module="ha_api",
            )
            self.assertEqual(wrong_domain["code"], 403)

            # Revoke lease and verify subsequent RPC returns 404
            self.assertTrue(self.engine.revoke_lease(req_id, caller_nonce))
            after_rev = self.engine.dispatch_lease_rpc(
                req_id=req_id,
                caller_nonce=caller_nonce,
                action="ha_proxy_call",
                payload={"method": "GET", "path": "/api/states"},
                caller=self.caller,
                expected_module="ha_api",
            )
            self.assertEqual(after_rev["code"], 404)

    def test_safe_log_endpoints_allowed_while_supervisor_and_websocket_remain_blocked(self) -> None:
        allowed_reads = [
            "/api/error_log",
            "/api/error_log?lines=500",
            "/api/hassio/core/logs",
            "/api/hassio/core/logs?lines=250",
            "/api/hassio/supervisor/logs",
            "/api/hassio/host/logs",
            "/api/hassio/dns/logs",
            "/api/hassio/addons/a0d7b954_nginxproxymanager/logs?lines=200",
            "/api/hassio/addons/core_matter_server/logs",
        ]
        for path in allowed_reads:
            ok, msg = validate_ha_proxy_call("GET", path, None, scope="read")
            self.assertTrue(ok, f"Expected read-only log path '{path}' to succeed, got: {msg}")

        blocked_bypass_attempts = [
            ("POST", "/api/hassio/core/logs", {}),
            ("DELETE", "/api/hassio/core/logs", None),
            ("GET", "/api/hassio/core/logs", {"unexpected": 1}),
            ("GET", "/api/hassio/core/logs/follow", None),
            ("GET", "/api/hassio/addons/headscale/info", None),
            ("GET", "/api/hassio/addons/headscale/options", None),
            ("POST", "/api/hassio/addons/headscale/restart", {}),
            ("GET", "/api/hassio/backups", None),
            ("GET", "/api/hassio/ingress/panels", None),
            ("GET", "/api/HASSIO/core/logs", None),
            ("GET", "/api/websocket", None),
            ("POST", "/api/websocket", {}),
            ("GET", "/api/error_log?follow=1", None),
            ("GET", "/api/error_log?lines=0", None),
            ("GET", "/api/error_log?lines=9999", None),
            ("GET", "/api/error_log?lines=abc", None),
            ("GET", "/api/hassio/core/logs?lines=100&boot=-1", None),
        ]
        for method, path, body in blocked_bypass_attempts:
            ok, _ = validate_ha_proxy_call(method, path, body, scope="admin", allowed_domains=["light"])
            self.assertFalse(ok, f"Expected {method} {path} to be blocked")

    def test_log_redaction_scrubs_oob_nonces_webhooks_and_tokens_without_hiding_auth_culprit(self) -> None:
        cfg = {
            **self.config,
            "ha_approval_token": "super-secret-callback-approval-999",
            "webhook_id": "wh_secret_id_abcdef123456",
        }
        raw_log = (
            "\x1b[33m2026-11-17 15:02:11 WARNING (MainThread) [homeassistant.components.http.ban] "
            "Login attempt or request with invalid authentication from core-matter-server (172.30.32.1). "
            "Requested URL: '/auth/token'. (Home Assistant/2026.11.2-io.homeassistant.companion.android)\x1b[0m\n"
            "2026-11-17 15:03:00 DEBUG [webhook] POST /api/webhook/wh_secret_id_abcdef123456 "
            'payload={"approve_nonce": "0123456789abcdef0123456789abcdef", "deny_nonce": "fedcba9876543210", '
            '"action": "APPROVE_OOB_0123456789abcdef", "X-HA-Approval-Token": "super-secret-callback-approval-999"}\n'
            "2026-11-17 15:03:05 DEBUG [http] Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJpc3MiOiJoYSJ9.sig_part_1234567890 gh_pat=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 {{ states }}\n"
        )
        scrubbed = redact_ha_log_output(raw_log, config=cfg, token="mock-root-ha-token")

        # Diagnostic details needed to debug `172.30.32.1` remain intact
        self.assertIn("core-matter-server (172.30.32.1)", scrubbed)
        self.assertIn("Requested URL: '/auth/token'", scrubbed)
        self.assertIn("io.homeassistant.companion.android", scrubbed)

        # Every OOB secret, nonce, webhook ID, JWT, PAT, ANSI escape, and Jinja2 tag is scrubbed
        self.assertNotIn("\x1b[", scrubbed)
        self.assertNotIn("wh_secret_id_abcdef123456", scrubbed)
        self.assertNotIn("0123456789abcdef", scrubbed)
        self.assertNotIn("fedcba9876543210", scrubbed)
        self.assertNotIn("super-secret-callback-approval-999", scrubbed)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", scrubbed)
        self.assertNotIn("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", scrubbed)
        self.assertNotIn("{{", scrubbed)

    def test_error_log_supervisor_and_oneshot_websocket_fallbacks(self) -> None:
        seen_requests = []

        class _FakeResp:
            def __init__(self, body_bytes: bytes, status: int = 200) -> None:
                self._buf = io.BytesIO(body_bytes)
                self.status = status

            def read(self, n: int = -1) -> bytes:
                return self._buf.read(n)

            def __enter__(self) -> "_FakeResp":
                return self

            def __exit__(self, *args: object) -> None:
                return None

        # 1. HA 2025.10+ fallback: `/api/error_log` -> 404, `/api/hassio/core/logs` -> 200 with Range header
        def fake_urlopen_supervisor(req, timeout=15):
            seen_requests.append((req.full_url, dict(req.header_items())))
            if req.full_url.endswith("/api/error_log"):
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b"404: Not Found"))
            if req.full_url.endswith("/api/hassio/core/logs"):
                return _FakeResp(
                    b"2026-11-17 15:00:00 WARNING [http.ban] invalid auth from 172.30.32.1 token=mock-root-ha-token\n"
                )
            raise AssertionError(f"Unexpected URL {req.full_url}")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen_supervisor):
            res_sup = execute_ha_proxy_call("GET", "/api/error_log?lines=250", None, self.config)
        self.assertEqual(res_sup["status"], "ok")
        self.assertIn("invalid auth from 172.30.32.1", res_sup["data"])
        self.assertNotIn("mock-root-ha-token", res_sup["data"])
        sup_headers = {k.lower(): v for k, v in seen_requests[-1][1].items()}
        self.assertEqual(sup_headers.get("range"), "entries=:-250:")

        # 2. HA Container/Core fallback: both `/api/error_log` and `/api/hassio/core/logs` -> 404 -> one-shot WebSocket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        ws_commands_received = []

        def _ws_send_unmasked_text(conn: socket.socket, obj: dict) -> None:
            raw = json.dumps(obj).encode("utf-8")
            hdr = bytearray([0x81])
            if len(raw) < 126:
                hdr.append(len(raw))
            else:
                hdr.append(126)
                hdr.extend(struct.pack("!H", len(raw)))
            conn.sendall(bytes(hdr) + raw)

        def _ws_recv_masked_json(conn: socket.socket) -> dict:
            b1, b2 = conn.recv(2)
            assert b1 & 0x0F == 0x1 and (b2 & 0x80)
            ln = b2 & 0x7F
            if ln == 126:
                (ln,) = struct.unpack("!H", conn.recv(2))
            mkey = conn.recv(4)
            enc = conn.recv(ln)
            dec = bytes(b ^ mkey[i % 4] for i, b in enumerate(enc))
            return json.loads(dec.decode("utf-8"))

        def _ws_server() -> None:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(5.0)
                req_raw = b""
                while b"\r\n\r\n" not in req_raw:
                    req_raw += conn.recv(4096)
                ws_key = ""
                for ln in req_raw.decode("latin1").split("\r\n"):
                    if ln.lower().startswith("sec-websocket-key:"):
                        ws_key = ln.split(":", 1)[1].strip()
                accept = base64.b64encode(
                    hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
                ).decode("ascii")
                conn.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    ).encode("ascii")
                )
                _ws_send_unmasked_text(conn, {"type": "auth_required"})
                auth_msg = _ws_recv_masked_json(conn)
                assert auth_msg.get("access_token") == "mock-root-ha-token"
                _ws_send_unmasked_text(conn, {"type": "auth_ok"})
                cmd_msg = _ws_recv_masked_json(conn)
                ws_commands_received.append(cmd_msg)
                _ws_send_unmasked_text(
                    conn,
                    {
                        "id": cmd_msg["id"],
                        "type": "result",
                        "success": True,
                        "result": [
                            {
                                "timestamp": 1763391731.0,
                                "level": "WARNING",
                                "name": "homeassistant.components.http.ban",
                                "source": ["components/http/ban.py", 136],
                                "message": [
                                    "Login attempt from core-matter-server (172.30.32.1). "
                                    "approve_nonce=abcdef1234567890"
                                ],
                                "count": 2,
                            }
                        ],
                    },
                )

        t = threading.Thread(target=_ws_server, daemon=True)
        t.start()
        try:
            def fake_urlopen_all_404(req, timeout=15):
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b"404: Not Found"))

            ws_cfg = {**self.config, "ha_url": f"http://127.0.0.1:{port}"}
            with patch("urllib.request.urlopen", side_effect=fake_urlopen_all_404):
                res_ws = execute_ha_proxy_call("GET", "/api/error_log?lines=50", None, ws_cfg)
            t.join(timeout=3.0)
        finally:
            srv.close()

        self.assertEqual(res_ws["status"], "ok")
        self.assertEqual(ws_commands_received, [{"id": 1, "type": "system_log/list"}])
        self.assertIn("core-matter-server (172.30.32.1)", res_ws["data"])
        self.assertIn("[x2]", res_ws["data"])
        self.assertNotIn("abcdef1234567890", res_ws["data"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
