"""
test_github_repo_create.py - Security, adversarial, and end-to-end behavioral tests
for the `github_repo_create` module (`oob-auth github-create-repo` & `oob_github_create_repo`).
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate.daemon import GateEngine
from ha_oob_gate.modules import CallerInfo


class TestGitHubRepoCreateModule(unittest.TestCase):
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
            },
        }
        self.caller = CallerInfo(uid=1001, gid=1001, pid=4242, username="ai-agent", is_root=False)
        self.engine = GateEngine(self.config)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_adversarial_guardrails_block_write_tier_reserved_topics_and_foreign_owners(self) -> None:
        mod = self.engine.modules["github_repo_create"]
        self.assertFalse(mod.can_auto_approve({}, self.caller, self.config))

        # 1. Pre-tagging a newly created repo as `oob-write` is blocked by default
        ok_w, err_w = mod.validate(
            {"repo": "locklabs/new-repo", "oob_tier": "write", "reason": "Try silent future pushes"},
            self.caller,
            self.config,
        )
        self.assertFalse(ok_w)
        self.assertIn("oob-write", err_w)

        # 2. Smuggling `oob-write` or `agy-write` via `--topics` is blocked
        for sneaky_topic in ("oob-write", "agy-write", "oob-oob", "oob"):
            ok_t, err_t = mod.validate(
                {
                    "repo": "locklabs/new-repo",
                    "oob_tier": "oob",
                    "topics": ["home-assistant", sneaky_topic],
                    "reason": "Smuggle topic",
                },
                self.caller,
                self.config,
            )
            self.assertFalse(ok_t, f"Expected topic {sneaky_topic!r} to be rejected")
            self.assertIn("reserved policy topic", err_t)

        # 3. Creating a repo under a foreign/uninstalled org (`attacker-org/exfil`) is blocked
        def fake_gh_installations(url, token, method="GET", payload=None):
            if url.endswith("/app/installations"):
                return 200, [
                    {"id": 101, "repository_selection": "all", "account": {"login": "Locknes", "type": "User"}},
                    {"id": 102, "repository_selection": "all", "account": {"login": "locklabs", "type": "Organization"}},
                ]
            return 404, {}

        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt.sig"):
            with patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh_installations):
                ok_f, err_f = mod.validate(
                    {"repo": "attacker-org/exfil", "visibility": "public", "reason": "Exfil"},
                    self.caller,
                    self.config,
                )
                self.assertFalse(ok_f)
                self.assertIn("attacker-org", err_f)

    def test_existing_repo_rejected_before_prompt_and_never_retagged(self) -> None:
        calls = []

        def fake_gh_existing(url, token, method="GET", payload=None):
            calls.append((method, url))
            if url.endswith("/app/installations"):
                return 200, [
                    {"id": 102, "repository_selection": "all", "account": {"login": "locklabs", "type": "Organization"}}
                ]
            if url.endswith("/app/installations/102/access_tokens"):
                return 201, {"token": "ghs_temp_org_admin"}
            if url.endswith("/installation/token") and method == "DELETE":
                return 204, {}
            if url.endswith("/repos/locklabs/existing-secret") and method == "GET":
                return 200, {"id": 999, "full_name": "locklabs/existing-secret"}
            return 500, {}

        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt.sig"):
            with patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh_existing):
                resp = self.engine.submit_and_wait(
                    "github_repo_create",
                    {"repo": "locklabs/existing-secret", "oob_tier": "oob", "reason": "Attempt clobber"},
                    self.caller,
                    wait_seconds=0,
                )
        self.assertEqual(resp["status"], "error")
        self.assertIn("already exists", resp["message"])
        # Verify temporary preflight token was immediately revoked
        self.assertIn(("DELETE", "https://api.github.com/installation/token"), calls)

    def test_end_to_end_org_repo_creation_via_github_app_and_single_repo_token_mint(self) -> None:
        calls = []
        webhooks = []

        def fake_gh_org(url, token, method="GET", payload=None):
            calls.append((method, url, token, payload))
            if url.endswith("/app/installations"):
                return 200, [
                    {"id": 102, "repository_selection": "all", "account": {"login": "locklabs", "type": "Organization"}}
                ]
            if url.endswith("/app/installations/102/access_tokens"):
                if payload and payload.get("permissions", {}).get("administration") == "write":
                    return 201, {"token": "ghs_temp_org_admin_NEVER_RETURN"}
                return 201, {"token": "ghs_downscoped_single_repo_push", "expires_at": "2026-11-18T20:00:00Z"}
            if url.endswith("/installation/token") and method == "DELETE":
                return 204, {}
            if url.endswith("/repos/locklabs/ha-blueprints") and method == "GET":
                return 404, {"message": "Not Found"}
            if url.endswith("/orgs/locklabs/repos") and method == "POST":
                return 201, {
                    "id": 55501,
                    "full_name": "locklabs/ha-blueprints",
                    "private": False,
                    "html_url": "https://github.com/locklabs/ha-blueprints",
                    "clone_url": "https://github.com/locklabs/ha-blueprints.git",
                    "ssh_url": "git@github.com:locklabs/ha-blueprints.git",
                }
            if url.endswith("/repos/locklabs/ha-blueprints/topics") and method == "PUT":
                return 200, {"names": payload["names"]}
            return 500, {}

        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt.sig"):
            with patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh_org):
                with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda cfg, p: (webhooks.append(p) or True)):
                    pending = self.engine.submit_and_wait(
                        "github_repo_create",
                        {
                            "repo": "locklabs/ha-blueprints",
                            "visibility": "public",
                            "description": "Clean Home Assistant blueprints",
                            "oob_tier": "oob",
                            "topics": ["home-assistant", "frigate"],
                            "mint_token": True,
                            "reason": "Publish Frigate review blueprint",
                        },
                        self.caller,
                        wait_seconds=0,
                    )
                    self.assertEqual(pending["status"], "pending")
                    req_id = pending["request_id"]
                    approve_nonce = webhooks[0]["approve_nonce"]
                    # Verify high-salience PUBLIC warning on mobile notification
                    self.assertIn("PUBLIC", webhooks[0]["title"])
                    self.assertEqual(webhooks[0]["color"], "#F59E0B")

                    code_cb, _ = self.engine.handle_ha_callback(
                        req_id, approve_nonce, "approve", "192.0.2.10", "secret-approval-token"
                    )
                    self.assertEqual(code_cb, 200)
                    resolved = self.engine.wait_for_resolution(req_id, timeout=5.0)

        self.assertEqual(resolved["status"], "approved")
        self.assertEqual(resolved["repo"], "locklabs/ha-blueprints")
        self.assertEqual(resolved["visibility"], "public")
        self.assertEqual(resolved["topics"], ["oob-oob", "home-assistant", "frigate"])
        # Returned token MUST be the downscoped single-repo token, NEVER the org-admin token
        self.assertEqual(resolved["token"], "ghs_downscoped_single_repo_push")
        self.assertNotIn("ghs_temp_org_admin_NEVER_RETURN", json.dumps(resolved))
        # Both preflight and grant org-admin tokens must have been revoked
        revoke_tokens = [tok for (m, u, tok, _) in calls if m == "DELETE" and u.endswith("/installation/token")]
        self.assertEqual(revoke_tokens, ["ghs_temp_org_admin_NEVER_RETURN", "ghs_temp_org_admin_NEVER_RETURN"])

    def test_personal_user_repo_attaches_selected_app_installation_without_leaking_user_token(self) -> None:
        with open(self.oauth_path, "w", encoding="utf-8") as f:
            json.dump({"client_id": "Iv123", "access_token": "ghu_SECRET_USER_TOKEN_DO_NOT_LEAK"}, f)

        calls = []

        def fake_gh_user(url, token, method="GET", payload=None):
            calls.append((method, url, token, payload))
            if url.endswith("/app/installations"):
                return 200, [
                    {"id": 101, "repository_selection": "selected", "account": {"login": "Locknes", "type": "User"}}
                ]
            if url.endswith("/user") and method == "GET":
                return 200, {"login": "Locknes"}
            if url.endswith("/repos/Locknes/ha-blueprints") and method == "GET":
                return 404, {"message": "Not Found"}
            if url.endswith("/user/repos") and method == "POST":
                return 201, {
                    "id": 77701,
                    "full_name": "Locknes/ha-blueprints",
                    "private": False,
                    "html_url": "https://github.com/Locknes/ha-blueprints",
                    "clone_url": "https://github.com/Locknes/ha-blueprints.git",
                }
            if url.endswith("/repos/Locknes/ha-blueprints/topics") and method == "PUT":
                return 200, {"names": payload["names"]}
            if url.endswith("/user/installations/101/repositories/77701") and method == "PUT":
                return 204, {}
            if url.endswith("/app/installations/101/access_tokens") and method == "POST":
                return 201, {"token": "ghs_single_repo_locknes_push", "expires_at": "2026-11-18T20:00:00Z"}
            return 500, {}

        webhooks = []
        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt.sig"):
            with patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh_user):
                with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda cfg, p: (webhooks.append(p) or True)):
                    pending = self.engine.submit_and_wait(
                        "github_repo_create",
                        {
                            "repo": "Locknes/ha-blueprints",
                            "visibility": "public",
                            "mint_token": True,
                            "reason": "Create personal blueprints repo",
                        },
                        self.caller,
                        wait_seconds=0,
                    )
                    self.assertEqual(pending["status"], "pending")
                    req_id = pending["request_id"]
                    self.engine.handle_ha_callback(
                        req_id, webhooks[0]["approve_nonce"], "approve", "192.0.2.10", "secret-approval-token"
                    )
                    resolved = self.engine.wait_for_resolution(req_id, timeout=5.0)

        self.assertEqual(resolved["status"], "approved")
        self.assertTrue(resolved["app_installed"])
        self.assertEqual(resolved["token"], "ghs_single_repo_locknes_push")
        self.assertNotIn("ghu_SECRET_USER_TOKEN_DO_NOT_LEAK", json.dumps(resolved))
        self.assertTrue(
            any(m == "PUT" and u.endswith("/user/installations/101/repositories/77701") for (m, u, _, _) in calls)
        )

    def test_cli_github_create_repo_stdout_contract(self) -> None:
        import ha_oob_gate.cli as cli_mod

        open(self.config["socket_path"], "w", encoding="utf-8").close()
        out_url, err_url = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.tmp_dir.name}, clear=False):
            with patch("ha_oob_gate.cli.load_config", return_value=self.config):
                with patch(
                    "ha_oob_gate.cli.send_unix_socket_request",
                    return_value={
                        "status": "approved",
                        "html_url": "https://github.com/Locknes/ha-blueprints",
                        "visibility": "public",
                        "topics": ["oob-oob"],
                    },
                ):
                    with redirect_stdout(out_url), redirect_stderr(err_url):
                        with self.assertRaises(SystemExit) as cm:
                            cli_mod.main(
                                [
                                    "github-create-repo",
                                    "--repo",
                                    "Locknes/ha-blueprints",
                                    "--visibility",
                                    "public",
                                    "--reason",
                                    "Create blueprints repo",
                                ]
                            )
                        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(out_url.getvalue(), "https://github.com/Locknes/ha-blueprints\n")
        self.assertIn("[oob-auth]", err_url.getvalue())

    def test_two_app_split_isolates_creator_from_token_broker(self) -> None:
        from pathlib import Path
        from ha_oob_gate.setup_github_app import build_app_manifest, update_github_repo_creator_config

        creator_manifest = build_app_manifest(role="repo-creator")
        self.assertEqual(creator_manifest["name"], "locklab-repo-creator")
        self.assertEqual(
            creator_manifest["default_permissions"],
            {"administration": "write", "metadata": "read"},
        )
        self.assertNotIn("contents", creator_manifest["default_permissions"])

        cfg_file = Path(self.tmp_dir.name) / "config.json"
        serializable_cfg = {k: v for k, v in self.config.items() if not k.startswith("_")}
        cfg_file.write_text(json.dumps(serializable_cfg), encoding="utf-8")
        creator_pem = Path(self.tmp_dir.name) / "github_repo_creator.pem"
        creator_pem.write_text("-----BEGIN RSA PRIVATE KEY-----\ncreator\n-----END RSA PRIVATE KEY-----\n", encoding="utf-8")

        updated_cfg = update_github_repo_creator_config(
            config_path=cfg_file,
            app_id="999002",
            private_key_path=creator_pem,
            user_oauth_path=Path(self.oauth_path),
        )
        # Existing `github_token` App #1 (`5795593`) must remain completely untouched
        self.assertEqual(updated_cfg["module_config"]["github_token"]["app_id"], "5795593")
        self.assertEqual(updated_cfg["module_config"]["github_repo_create"]["app_id"], "999002")

        with open(self.oauth_path, "w", encoding="utf-8") as f:
            json.dump({"client_id": "IvCreator", "access_token": "ghu_creator_oauth"}, f)

        split_engine = GateEngine(updated_cfg)
        jwt_calls = []
        api_calls = []

        def fake_jwt(app_id, private_key_path="", private_key_pem="", now=None):
            jwt_calls.append((str(app_id), str(private_key_path)))
            return f"jwt_for_{app_id}"

        def fake_gh(url, token, method="GET", payload=None):
            api_calls.append((method, url, token, payload))
            if url.endswith("/app/installations"):
                if token == "jwt_for_999002":
                    # App #2 (`locklab-repo-creator`): selected-repos only
                    return 200, [{"id": 202, "repository_selection": "selected", "account": {"login": "Locknes", "type": "User"}}]
                if token == "jwt_for_5795593":
                    # App #1 (`locklab-oob-gate`): token broker
                    return 200, [{"id": 101, "repository_selection": "selected", "account": {"login": "Locknes", "type": "User"}}]
            if url.endswith("/user") and method == "GET":
                return 200, {"login": "Locknes"}
            if url.endswith("/repos/Locknes/ha-blueprints") and method == "GET":
                return 404, {}
            if url.endswith("/user/repos") and method == "POST":
                return 201, {"id": 88801, "full_name": "Locknes/ha-blueprints", "private": False}
            if url.endswith("/user/installations/202/repositories/88801") and method == "PUT":
                return 204, {}
            if url.endswith("/repos/Locknes/ha-blueprints/topics") and method == "PUT":
                return 200, {"names": payload["names"]}
            if url.endswith("/user/installations/101/repositories/88801") and method == "PUT":
                return 204, {}
            if url.endswith("/app/installations/101/access_tokens") and method == "POST":
                self.assertEqual(token, "jwt_for_5795593")
                return 201, {"token": "ghs_minted_by_token_broker_app1", "expires_at": "2026-11-18T21:00:00Z"}
            return 500, {}

        webhooks = []
        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", side_effect=fake_jwt):
            with patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh):
                with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda cfg, p: (webhooks.append(p) or True)):
                    pending = split_engine.submit_and_wait(
                        "github_repo_create",
                        {"repo": "Locknes/ha-blueprints", "visibility": "public", "mint_token": True, "reason": "2-app split"},
                        self.caller,
                        wait_seconds=0,
                    )
                    self.assertEqual(pending["status"], "pending")
                    req_id = pending["request_id"]
                    split_engine.handle_ha_callback(
                        req_id, webhooks[0]["approve_nonce"], "approve", "192.0.2.10", "secret-approval-token"
                    )
                    resolved = split_engine.wait_for_resolution(req_id, timeout=5.0)

        self.assertEqual(resolved["status"], "approved")
        self.assertEqual(resolved["token"], "ghs_minted_by_token_broker_app1")
        # Creator App (202) was attached BEFORE topics PUT, and Token Broker App (101) was also attached
        method_urls = [(m, u.split("api.github.com")[-1]) for (m, u, _, _) in api_calls]
        idx_attach_creator = method_urls.index(("PUT", "/user/installations/202/repositories/88801"))
        idx_topics = method_urls.index(("PUT", "/repos/Locknes/ha-blueprints/topics"))
        idx_attach_broker = method_urls.index(("PUT", "/user/installations/101/repositories/88801"))
        self.assertLess(idx_attach_creator, idx_topics)
        self.assertLess(idx_topics, idx_attach_broker)

    def test_mint_token_workflows_validation_and_permission_scope(self) -> None:
        # 1. `workflows=True` without `mint_token=True` fails validation cleanly
        bad = self.engine.submit_and_wait(
            "github_repo_create",
            {"repo": "Locknes/ci-demo", "mint_token": False, "workflows": True, "reason": "bad"},
            self.caller,
            wait_seconds=0,
        )
        self.assertEqual(bad["code"], 403)

        # 2. `workflows=True` + `mint_token=True` requests `workflows: write` after approval
        with open(self.oauth_path, "w", encoding="utf-8") as f:
            json.dump({"client_id": "IvDemo", "access_token": "ghu_demo_oauth"}, f)

        mint_calls = []

        def fake_gh(url, token, method="GET", payload=None):
            if url.endswith("/app/installations"):
                return 200, [{"id": 101, "repository_selection": "all", "account": {"login": "Locknes", "type": "User"}}]
            if url.endswith("/user") and method == "GET":
                return 200, {"login": "Locknes"}
            if url.endswith("/repos/Locknes/ci-demo") and method == "GET":
                return 404, {}
            if url.endswith("/user/repos") and method == "POST":
                return 201, {"id": 99901, "full_name": "Locknes/ci-demo", "private": False}
            if url.endswith("/repos/Locknes/ci-demo/topics") and method == "PUT":
                return 200, {"names": payload["names"]}
            if url.endswith("/app/installations/101/access_tokens") and method == "POST":
                mint_calls.append(payload)
                return 201, {"token": "ghs_repo_create_wf", "expires_at": "2026-11-19T08:00:00Z"}
            return 500, {}

        webhooks = []
        with patch("ha_oob_gate.modules.github_repo_create.create_github_app_jwt", return_value="fake.jwt.sig"):
            with patch("ha_oob_gate.modules.github_repo_create._github_api_request", side_effect=fake_gh):
                with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda cfg, p: (webhooks.append(p) or True)):
                    pending = self.engine.submit_and_wait(
                        "github_repo_create",
                        {
                            "repo": "Locknes/ci-demo",
                            "visibility": "public",
                            "mint_token": True,
                            "workflows": True,
                            "reason": "create with workflow CI",
                        },
                        self.caller,
                        wait_seconds=0,
                    )
                    self.assertEqual(pending["status"], "pending")
                    req_id = pending["request_id"]
                    self.engine.handle_ha_callback(
                        req_id, webhooks[0]["approve_nonce"], "approve", "192.0.2.10", "secret-approval-token"
                    )
                    resolved = self.engine.wait_for_resolution(req_id, timeout=5.0)

        self.assertEqual(resolved["status"], "approved")
        self.assertTrue(resolved["workflows"])
        self.assertEqual(
            mint_calls[-1]["permissions"],
            {"metadata": "read", "contents": "write", "pull_requests": "write", "workflows": "write"},
        )


if __name__ == "__main__":
    unittest.main()
