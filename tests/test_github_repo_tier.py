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
from ha_oob_gate.modules import CallerInfo, discover_modules


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

    def test_discover_modules_co_enables_github_repo_tier_with_github_repo_create(self) -> None:
        mods_with_create = discover_modules(["github_repo_create"])
        self.assertIn("github_repo_create", mods_with_create)
        self.assertIn("github_repo_tier", mods_with_create)

        mods_confirm_only = discover_modules(["generic_confirm"])
        self.assertIn("generic_confirm", mods_confirm_only)
        self.assertNotIn("github_repo_tier", mods_confirm_only)

    def test_oob_deny_lockout_and_live_topic_merge_toctou_protection(self) -> None:
        mod = self.engine.modules["github_repo_tier"]
        topic_seq = [
            ["oob-deny", "sensitive"],
            ["agy-deny", "sensitive"],
            ["oob-oob", "alpha"],
            ["oob-deny", "alpha", "beta"],
            ["oob-oob", "alpha"],
            ["oob-oob", "alpha", "beta"],
        ]

        def fake_gh(url, token, method="GET", payload=None):
            if url.endswith("/app/installations"):
                return 200, [{"id": 102, "repository_selection": "all", "account": {"login": "locklabs", "type": "Organization"}}]
            if url.endswith("/app/installations/102/access_tokens"):
                return 201, {"token": "ghs_temp_org_admin"}
            if url.endswith("/installation/token") and method == "DELETE":
                return 204, {}
            if url.endswith("/repos/locklabs/locked-repo") and method == "GET":
                return 200, {"id": 901, "full_name": "locklabs/locked-repo"}
            if url.endswith("/repos/locklabs/locked-repo/topics") and method == "GET":
                return 200, {"names": topic_seq.pop(0)}
            if url.endswith("/repos/locklabs/locked-repo/properties/values"):
                return 404, {}
            if url.endswith("/repos/locklabs/locked-repo/topics") and method == "PUT":
                return 200, {"names": payload["names"]}
            return 500, {}

        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_tier.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh), \
             patch("ha_oob_gate.modules.github_repo_tier._github_api_request", side_effect=fake_gh):
            for lock_tag in ("oob-deny", "agy-deny"):
                ok_d, err_d = mod.validate(
                    {"repo": "locklabs/locked-repo", "oob_tier": "write", "reason": "Try unlock"},
                    self.caller,
                    self.config,
                )
                self.assertFalse(ok_d)
                self.assertIn(lock_tag, err_d)

            # Concurrent lock between validate() and grant() aborts before PUT
            p_toctou = {"repo": "locklabs/locked-repo", "oob_tier": "write", "reason": "TOCTOU test"}
            ok_v, msg_v = mod.validate(p_toctou, self.caller, self.config)
            self.assertTrue(ok_v, msg_v)
            with self.assertRaises(RuntimeError) as cm_err:
                mod.grant("req-toctou", p_toctou, self.caller, 600, self.config)
            self.assertIn("deny topic", str(cm_err.exception))

            # Concurrent non-policy topic (`beta`) added between validate and grant is preserved
            p_merge = {"repo": "locklabs/locked-repo", "oob_tier": "write", "reason": "Live topic merge"}
            ok_m, msg_m = mod.validate(p_merge, self.caller, self.config)
            self.assertTrue(ok_m, msg_m)
            res = mod.grant("req-merge", p_merge, self.caller, 600, self.config)
            self.assertEqual(res["topics"], ["oob-write", "alpha", "beta"])

    def test_selected_repo_creator_private_repo_fallback_and_attach_on_grant(self) -> None:
        import json

        with open(self.oauth_path, "w", encoding="utf-8") as f:
            json.dump({"client_id": "Iv123", "access_token": "ghu_root_user_oauth"}, f)

        calls = []

        def fake_gh(url, token, method="GET", payload=None):
            calls.append((method, url, token, payload))
            if url.endswith("/app/installations"):
                return 200, [
                    {"id": 201, "repository_selection": "selected", "account": {"login": "Locknes", "type": "User"}}
                ]
            if url.endswith("/app/installations/201/access_tokens"):
                return 201, {"token": "ghs_meta_fallback"}
            if url.endswith("/installation/token") and method == "DELETE":
                return 204, {}
            if url.endswith("/repos/Locknes/lock-rip-site") and method == "GET":
                if token == "ghu_root_user_oauth":
                    return 404, {"message": "Not Found"}
                return 200, {"id": 88801, "full_name": "Locknes/lock-rip-site"}
            if url.endswith("/repos/Locknes/lock-rip-site/topics") and method == "GET":
                return 200, {"names": ["oob-oob", "cloudflare-pages", "static-site"]}
            if url.endswith("/repos/Locknes/lock-rip-site/properties/values"):
                return 404, {}
            if url.endswith("/user/installations/201/repositories/88801") and method == "PUT":
                return 204, {}
            if url.endswith("/repos/Locknes/lock-rip-site/topics") and method == "PUT":
                return 200, {"names": payload["names"]}
            return 500, {}

        mod = self.engine.modules["github_repo_tier"]
        params = {"repo": "Locknes/lock-rip-site", "tier": "write", "reason": "Enable auto-pushes"}
        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_tier.create_github_app_jwt", return_value="fake.jwt"), \
             patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh), \
             patch("ha_oob_gate.modules.github_repo_tier._github_api_request", side_effect=fake_gh):
            ok, msg = mod.validate(params, self.caller, self.config)
            self.assertTrue(ok, msg)
            self.assertEqual(params["_attach_creator_inst_id"], "201")
            res = mod.grant("req-priv", params, self.caller, 600, self.config)

        self.assertEqual(res["topics"], ["oob-write", "cloudflare-pages", "static-site"])
        self.assertIn(
            ("PUT", "https://api.github.com/user/installations/201/repositories/88801", "ghu_root_user_oauth", None),
            calls,
        )
        self.assertIn(("DELETE", "https://api.github.com/installation/token", "ghs_meta_fallback", None), calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
