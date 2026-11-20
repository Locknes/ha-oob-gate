"""
test_github_repo_tier.py - Security, adversarial, and end-to-end tests
for the `github_repo_tier` module (`oob-auth github-set-tier` & `oob_github_set_tier`).
"""

from __future__ import annotations

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


class TestGitHubRepoTierModule(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pem_path = os.path.join(self.tmp_dir.name, "github_app.pem")
        self.oauth_path = os.path.join(self.tmp_dir.name, "github_user_oauth.json")
        self.admin_pat_path = os.path.join(self.tmp_dir.name, "github_repo_admin_pat")
        with open(self.pem_path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")

        self.config = {
            "ha_url": "https://homeassistant.example.com",
            "ha_trusted_ip": "192.0.2.10",
            "ha_approval_token": "secret-approval-token",
            "webhook_id": "w" * 32,
            "callback_host": "192.0.2.20",
            "callback_port": 8443,
            "listen_port": 8443,
            "timeout_seconds": 30,
            "ticket_dir": os.path.join(self.tmp_dir.name, "tickets"),
            "socket_path": os.path.join(self.tmp_dir.name, "daemon.sock"),
            "hmac_key_path": os.path.join(self.tmp_dir.name, "hmac.key"),
            "vault_path": os.path.join(self.tmp_dir.name, "vault.json"),
            "audit_stdout": False,
            "module_config": {
                "github_token": {
                    "app_id": "5795593",
                    "private_key_path": self.pem_path,
                    "vault_pat_path": os.path.join(self.tmp_dir.name, "nonexistent_vault_pat"),
                },
                "github_repo_create": {
                    "user_oauth_path": self.oauth_path,
                    "repo_admin_pat_path": self.admin_pat_path,
                },
                "github_repo_tier": {
                    "protected_repos": ["locklabs/k8s-gitops"],
                },
                "self_update": {
                    "repo": "Locknes/ha-oob-gate",
                },
            },
        }
        self.caller = CallerInfo(uid=1001, gid=1001, pid=4242, username="ai-agent", is_root=False)
        self.engine = GateEngine(self.config)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_protected_tier0_repos_cannot_promote_to_write_but_can_tighten_to_oob(self) -> None:
        mod = self.engine.modules["github_repo_tier"]
        self.assertFalse(mod.can_auto_approve({"repo": "locklabs/k8s-apps-gitops", "oob_tier": "write"}, self.caller, self.config))

        for protected in ("Locknes/ha-oob-gate", "locklabs/k8s-gitops"):
            ok_w, err_w = mod.validate(
                {"repo": protected, "oob_tier": "write", "reason": "Try promoting Tier-0 repo"},
                self.caller,
                self.config,
            )
            self.assertFalse(ok_w)
            self.assertIn("protected Tier-0 repository", err_w)

        def fake_gh(url, token, method="GET", payload=None):
            if url.endswith("/app/installations"):
                return 200, [{"id": 102, "repository_selection": "all", "account": {"login": "locklabs", "type": "Organization"}}]
            if url.endswith("/app/installations/102/access_tokens"):
                return 201, {"token": "ghs_temp_admin"}
            if url.endswith("/installation/token") and method == "DELETE":
                return 204, {}
            if url.endswith("/repos/locklabs/k8s-gitops") and method == "GET":
                return 200, {"full_name": "locklabs/k8s-gitops"}
            if url.endswith("/repos/locklabs/k8s-gitops/topics") and method == "GET":
                return 200, {"names": ["oob-read", "k3s"]}
            if url.endswith("/repos/locklabs/k8s-gitops/properties/values"):
                return 200, []
            return 500, {}

        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_tier.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh), \
             patch("ha_oob_gate.modules.github_repo_tier._github_api_request", side_effect=fake_gh):
            ok_tighten, msg = mod.validate(
                {"repo": "locklabs/k8s-gitops", "oob_tier": "oob", "reason": "Require phone tap"},
                self.caller,
                self.config,
            )
        self.assertTrue(ok_tighten, msg)

    def test_rejects_nonexistent_repo_and_org_custom_property_override(self) -> None:
        mod = self.engine.modules["github_repo_tier"]

        def fake_gh(url, token, method="GET", payload=None):
            if url.endswith("/app/installations"):
                return 200, [{"id": 102, "repository_selection": "all", "account": {"login": "locklabs", "type": "Organization"}}]
            if url.endswith("/app/installations/102/access_tokens"):
                return 201, {"token": "ghs_temp_admin"}
            if url.endswith("/installation/token") and method == "DELETE":
                return 204, {}
            if url.endswith("/repos/locklabs/missing"):
                return 404, {"message": "Not Found"}
            if url.endswith("/repos/locklabs/prop-governed") and method == "GET":
                return 200, {"full_name": "locklabs/prop-governed"}
            if url.endswith("/repos/locklabs/prop-governed/topics"):
                return 200, {"names": ["oob-oob"]}
            if url.endswith("/repos/locklabs/prop-governed/properties/values"):
                return 200, [{"property_name": "oob_access", "value": "oob"}]
            return 500, {}

        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_tier.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh), \
             patch("ha_oob_gate.modules.github_repo_tier._github_api_request", side_effect=fake_gh):
            ok_404, err_404 = mod.validate(
                {"repo": "locklabs/missing", "oob_tier": "write", "reason": "Check 404"},
                self.caller,
                self.config,
            )
            self.assertFalse(ok_404)
            self.assertIn("does not exist", err_404)

            ok_prop, err_prop = mod.validate(
                {"repo": "locklabs/prop-governed", "oob_tier": "write", "reason": "Check custom prop"},
                self.caller,
                self.config,
            )
            self.assertFalse(ok_prop)
            self.assertIn("oob_access='oob'", err_prop)

    def test_end_to_end_replaces_oob_topics_preserves_other_topics_and_revokes_admin_token(self) -> None:
        calls = []

        def fake_gh(url, token, method="GET", payload=None):
            calls.append((method, url, payload))
            if url.endswith("/app/installations"):
                return 200, [{"id": 102, "repository_selection": "all", "account": {"login": "locklabs", "type": "Organization"}}]
            if url.endswith("/app/installations/102/access_tokens"):
                return 201, {"token": "ghs_temp_org_admin"}
            if url.endswith("/installation/token") and method == "DELETE":
                return 204, {}
            if url.endswith("/repos/locklabs/k8s-apps-gitops") and method == "GET":
                return 200, {"full_name": "locklabs/k8s-apps-gitops"}
            if url.endswith("/repos/locklabs/k8s-apps-gitops/topics") and method == "GET":
                return 200, {"names": ["oob-oob", "agy-read", "gitops", "fleet"]}
            if url.endswith("/repos/locklabs/k8s-apps-gitops/properties/values"):
                return 404, {}
            if url.endswith("/repos/locklabs/k8s-apps-gitops/topics") and method == "PUT":
                return 200, {"names": payload["names"]}
            return 500, {}

        mod = self.engine.modules["github_repo_tier"]
        params = {"repo": "locklabs/k8s-apps-gitops", "oob_tier": "write", "reason": "Promote fleet repo"}
        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_tier.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh), \
             patch("ha_oob_gate.modules.github_repo_tier._github_api_request", side_effect=fake_gh):
            ok, msg = mod.validate(params, self.caller, self.config)
            self.assertTrue(ok, msg)
            notif = mod.format_notification(params, self.caller, "ABCD1234", "rh-agy-bas01", self.config)
            self.assertIn("SILENT FUTURE PUSHES", notif.message)
            self.assertIn("oob-oob, agy-read -> oob-write", notif.message)
            granted = mod.grant("req-1", params, self.caller, 600, self.config)

        self.assertEqual(granted["topic"], "oob-write")
        self.assertEqual(granted["previous_oob_topics"], ["oob-oob", "agy-read"])
        self.assertEqual(granted["topics"], ["oob-write", "gitops", "fleet"])
        del_calls = [c for c in calls if c[0] == "DELETE" and c[1].endswith("/installation/token")]
        self.assertEqual(len(del_calls), 2, "Expected temporary org admin tokens revoked after both validate and grant")


if __name__ == "__main__":
    unittest.main(verbosity=2)
