"""
test_ha_api.py - Behavioral tests for HaApiModule, single-call `allowed_domains`
enforcement, structured payload inspection (without benign prose false positives),
and generic `GateEngine.dispatch_lease_rpc()` lifecycle.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate.daemon import GateEngine
from ha_oob_gate.modules import CallerInfo
from ha_oob_gate.modules.ha_api import validate_ha_proxy_call


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
