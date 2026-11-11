"""
test_pam_and_batch.py - Behavioral tests for PamSudoModule, SudoBatchModule,
no-lockout PAM daemon failure handling, `pam_ha_sudo.sh` break-glass execution,
and `install.sh --configure-pam-file` across Debian/Ubuntu and RHEL/Fedora PAM stacks.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate.cli import EXIT_HA_UNREACHABLE, run_pam_gate
from ha_oob_gate.daemon import GateEngine
from ha_oob_gate.modules import CallerInfo
from ha_oob_gate.modules.pam_sudo import (
    create_signed_ticket,
    normalize_sudo_command,
    verify_and_consume_ticket,
)


class TestPamAndBatchModules(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.ticket_dir = os.path.join(self.tmp_dir.name, "tickets")
        self.config = {
            "ha_url": "https://homeassistant.example.com",
            "ha_trusted_ip": "192.0.2.10",
            "webhook_id": "b" * 32,
            "callback_host": "192.0.2.20",
            "callback_port": 8443,
            "listen_port": 8443,
            "timeout_seconds": 30,
            "hmac_key_path": os.path.join(self.tmp_dir.name, "hmac.key"),
            "ticket_dir": self.ticket_dir,
            "socket_path": os.path.join(self.tmp_dir.name, "daemon.sock"),
            "default_sudo_scope": "command_pinned",
            "agent_users": ["ai-agent"],
            "user_policies": {
                "pinned-admin": "command_pinned",
                "window-admin": "window",
                "ai-agent": "deny_pam_sudo",
            },
            "max_requests_per_10m": 20,
        }
        self.engine = GateEngine(self.config)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_unprivileged_caller_blocked_from_pam_sudo(self) -> None:
        unpriv = CallerInfo(uid=1000, gid=1000, pid=1234, username="pinned-admin", is_root=False)
        res = self.engine.submit_and_wait(
            "pam_sudo",
            {"user": "pinned-admin", "command": "sudo systemctl status nginx"},
            unpriv,
            wait_seconds=0,
        )
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["code"], 403)
        self.assertIn("requires root caller", res["message"])

    def test_single_use_command_pinned_tickets_and_concurrent_isolation(self) -> None:
        hmac_key = self.engine.hmac_key
        t1 = create_signed_ticket(
            ticket_dir=self.ticket_dir,
            username="pinned-admin",
            req_id="11111111-2222-3333-4444-555555555555",
            command="/usr/bin/sudo systemctl status nginx",
            scope_mode="command_pinned",
            timeout_seconds=60,
            hmac_key=hmac_key,
        )
        t2 = create_signed_ticket(
            ticket_dir=self.ticket_dir,
            username="pinned-admin",
            req_id="66666666-7777-8888-9999-000000000000",
            command="/usr/bin/sudo systemctl status sshd",
            scope_mode="command_pinned",
            timeout_seconds=60,
            hmac_key=hmac_key,
        )
        self.assertNotEqual(t1, t2)
        self.assertEqual(os.stat(os.path.dirname(t1)).st_mode & 0o777, 0o700)

        # Bait-and-switch fails
        self.assertFalse(verify_and_consume_ticket(self.ticket_dir, "pinned-admin", "sudo bash", hmac_key))
        self.assertFalse(verify_and_consume_ticket(self.ticket_dir, "pinned-admin", "sudo chmod +s /bin/bash", hmac_key))

        # Exact commands succeed once each and are consumed
        self.assertTrue(verify_and_consume_ticket(self.ticket_dir, "pinned-admin", "sudo systemctl status nginx", hmac_key))
        self.assertFalse(verify_and_consume_ticket(self.ticket_dir, "pinned-admin", "sudo systemctl status nginx", hmac_key))
        self.assertTrue(verify_and_consume_ticket(self.ticket_dir, "pinned-admin", "sudo systemctl status sshd", hmac_key))

        self.assertNotEqual(normalize_sudo_command("sudo -l"), normalize_sudo_command("sudo -i"))
        self.assertNotEqual(normalize_sudo_command("sudo -u postgres psql"), normalize_sudo_command("sudo psql"))
        self.assertNotEqual(normalize_sudo_command("sudo /bin/echo 'a b'"), normalize_sudo_command("sudo /bin/echo a b"))

    def test_pam_command_pinned_allowlist_blocks_versioned_interpreters_and_allows_conf_args(self) -> None:
        root_caller = CallerInfo(uid=0, gid=0, pid=2001, username="root", is_root=True)
        pam_mod = self.engine.modules["pam_sudo"]

        # Agent user with deny_pam_sudo is rejected
        ok_agent, msg_agent = pam_mod.validate(
            {"user": "ai-agent", "command": "sudo systemctl status nginx"}, root_caller, self.config
        )
        self.assertFalse(ok_agent)
        self.assertIn("disabled for account", msg_agent)

        # Shells, versioned interpreters (python3.12, perl5.38), GTFOBins, and interactive flags are rejected
        for bad_cmd in (
            "sudo -i",
            "sudo -s",
            "sudo -ni",
            "sudo -u postgres psql",
            "sudo /bin/bash",
            "sudo python3.12 -c 'import os'",
            "sudo perl5.38 -e 'exec \"/bin/sh\"'",
            "sudo vim /etc/hosts",
            "sudo tar -cf /tmp/x.tar /etc",
            "sudo /tmp/myscript.sh",
            "sudo systemctl status " + ("B" * 500),
        ):
            with patch("ha_oob_gate.command_policy.shutil.which", side_effect=lambda b, **kw: f"/usr/bin/{os.path.basename(b)}"):
                with patch("ha_oob_gate.command_policy.os.path.realpath", side_effect=lambda p: p):
                    with patch("ha_oob_gate.command_policy.os.stat", return_value=os.stat_result((0o100755, 1, 1, 1, 0, 0, 100, 0, 0, 0))):
                        ok, _ = pam_mod.validate({"user": "pinned-admin", "command": bad_cmd}, root_caller, self.config)
                        self.assertFalse(ok, f"Expected PAM command_pinned to reject {bad_cmd!r}")

        # Benign `.conf` / `.yaml` / `.json` arguments on allowlisted commands MUST succeed (no extension false positives!)
        with patch("ha_oob_gate.command_policy.shutil.which", side_effect=lambda b, **kw: f"/usr/bin/{os.path.basename(b)}"):
            with patch("ha_oob_gate.command_policy.os.path.realpath", side_effect=lambda p: p):
                with patch("ha_oob_gate.command_policy.os.stat", return_value=os.stat_result((0o100755, 1, 1, 1, 0, 0, 100, 0, 0, 0))):
                    for good_cmd in (
                        "sudo nginx -t -c /etc/nginx/nginx.conf",
                        "sudo systemctl status sshd.service",
                        "sudo systemctl show -p FragmentPath /etc/app/settings.yaml",
                        "sudo stat /etc/app/manifest.json",
                    ):
                        ok, msg = pam_mod.validate({"user": "pinned-admin", "command": good_cmd}, root_caller, self.config)
                        self.assertTrue(ok, f"Expected {good_cmd!r} to succeed, got: {msg}")

    def test_run_pam_gate_exits_75_without_inprocess_http_server_when_daemon_down(self) -> None:
        # Bind a dummy socket to listen_port to prove `run_pam_gate` NEVER attempts to bind 0.0.0.0:listen_port
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        occupied_port = blocker.getsockname()[1]

        try:
            missing_sock = os.path.join(self.tmp_dir.name, "missing.sock")
            stale_sock = os.path.join(self.tmp_dir.name, "stale.sock")
            s_stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s_stale.bind(stale_sock)
            s_stale.close()

            for sock_p in (missing_sock, stale_sock):
                pam_cfg = dict(self.config, socket_path=sock_p, listen_port=occupied_port)
                with patch("ha_oob_gate.cli.os.geteuid", return_value=0):
                    with patch("ha_oob_gate.cli.inspect_proc_command", return_value=("sudo systemctl status sshd", "/")):
                        with self.assertRaises(SystemExit) as cm:
                            run_pam_gate(pam_cfg, "window-admin", "sudo systemctl status sshd")
                        self.assertEqual(
                            cm.exception.code,
                            EXIT_HA_UNREACHABLE,
                            f"Expected EXIT_HA_UNREACHABLE (75) for {sock_p}, got {cm.exception.code}",
                        )
        finally:
            blocker.close()

    def test_pam_ha_sudo_sh_breakglass_end_to_end_when_daemon_socket_missing(self) -> None:
        pam_sh = os.path.join(REPO_ROOT, "systemd/pam_ha_sudo.sh")
        real_gate = os.path.join(REPO_ROOT, "ha_sudo_gate.py")
        fake_group = os.path.join(self.tmp_dir.name, "group")
        fake_passwd = os.path.join(self.tmp_dir.name, "passwd")
        pam_cfg_file = os.path.join(self.tmp_dir.name, "pam_test_config.json")

        with open(pam_cfg_file, "w", encoding="utf-8") as cf:
            json.dump(
                {
                    "socket_path": os.path.join(self.tmp_dir.name, "nonexistent_daemon.sock"),
                    "ticket_dir": self.ticket_dir,
                    "hmac_key_path": os.path.join(self.tmp_dir.name, "hmac.key"),
                    "timeout_seconds": 5,
                },
                cf,
            )
        with open(fake_group, "w", encoding="utf-8") as grp:
            grp.write("wheel:x:10:ops-admin\nha-breakglass:x:991:console-admin,serial-admin\n")
        with open(fake_passwd, "w", encoding="utf-8") as pw:
            pw.write(
                "console-admin:x:1005:1005::/home/console-admin:/bin/bash\n"
                "ops-admin:x:1006:1006::/home/ops-admin:/bin/bash\n"
            )

        def invoke_pam_helper(user: str, tty: str, gate_bin: str = real_gate) -> int:
            env = {
                "PATH": "/usr/bin:/bin",
                "PAM_RUSER": user,
                "PAM_TTY": tty,
                "HA_SUDO_TEST_GATE_BIN": gate_bin,
                "HA_SUDO_TEST_PYTHON_BIN": sys.executable,
                "HA_SUDO_TEST_GROUP_FILE": fake_group,
                "HA_SUDO_TEST_PASSWD_FILE": fake_passwd,
                "HA_SUDO_TEST_CONFIG": pam_cfg_file,
            }
            return subprocess.run(
                ["/bin/bash", pam_sh], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ).returncode

        # Real ha_sudo_gate.py --pam sees missing daemon.sock -> exits 75 -> pam_ha_sudo.sh allows breakglass on tty1 & ttyS0!
        self.assertEqual(invoke_pam_helper("console-admin", "/dev/tty1"), 0)
        self.assertEqual(invoke_pam_helper("serial-admin", "ttyS0"), 0)
        # Missing gate binary also triggers exit 75 -> allows breakglass on local console
        self.assertEqual(invoke_pam_helper("console-admin", "/dev/tty2", gate_bin="/nonexistent/gate.py"), 0)
        # Blocked over SSH pseudo-terminal (`pts/0`) or for non-breakglass user
        self.assertEqual(invoke_pam_helper("console-admin", "pts/0"), 1)
        self.assertEqual(invoke_pam_helper("ops-admin", "/dev/tty1"), 1)

    def test_install_sh_configure_pam_file_debian_ubuntu_and_rhel_idempotent(self) -> None:
        install_sh = os.path.join(REPO_ROOT, "install.sh")

        # 1. Debian / Ubuntu `/etc/pam.d/sudo` with `@include common-auth`
        debian_pam = os.path.join(self.tmp_dir.name, "pam_sudo_debian")
        with open(debian_pam, "w", encoding="utf-8") as f:
            f.write(
                "#%PAM-1.0\n"
                "session    required   pam_env.so readenv=1 user_readenv=0\n"
                "@include common-auth\n"
                "@include common-account\n"
                "@include common-session-noninteractive\n"
            )
        for _ in range(2):  # Run twice to verify idempotency
            subprocess.run(["/bin/bash", install_sh, "--configure-pam-file", debian_pam], check=True)

        with open(debian_pam, "r", encoding="utf-8") as f:
            deb_lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
        self.assertIn("@include common-auth", deb_lines)
        # Must NOT prepend a duplicate `pam_unix.so` when `@include common-auth` is present!
        self.assertFalse(any("pam_unix.so" in ln for ln in deb_lines), f"Unexpected duplicate pam_unix.so in {deb_lines}")
        self.assertEqual(sum(1 for ln in deb_lines if "pam_ha_sudo.sh" in ln), 1)
        idx_inc = deb_lines.index("@include common-auth")
        self.assertIn("pam_ha_sudo.sh", deb_lines[idx_inc + 1])

        # 2. RHEL / Fedora `/etc/pam.d/sudo` with `auth include system-auth`
        rhel_pam = os.path.join(self.tmp_dir.name, "pam_sudo_rhel")
        with open(rhel_pam, "w", encoding="utf-8") as f:
            f.write(
                "#%PAM-1.0\n"
                "auth       include      system-auth\n"
                "account    include      system-auth\n"
                "session    include      system-auth\n"
            )
        for _ in range(2):
            subprocess.run(["/bin/bash", install_sh, "--configure-pam-file", rhel_pam], check=True)

        with open(rhel_pam, "r", encoding="utf-8") as f:
            rhel_lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
        self.assertFalse(any("pam_unix.so" in ln for ln in rhel_lines))
        self.assertTrue(any(ln.startswith("auth") and "substack" in ln and "system-auth" in ln for ln in rhel_lines))
        self.assertEqual(sum(1 for ln in rhel_lines if "pam_ha_sudo.sh" in ln), 1)

    def test_sudo_batch_shebang_guardrails_toctou_and_root_mount_isolation(self) -> None:
        caller = CallerInfo(uid=1001, gid=1001, pid=2050, username="ai-agent", is_root=False)
        batch_mod = self.engine.modules["sudo_batch"]

        # 1. Non-bash shebangs (`#!/usr/bin/env python3`, `#!/usr/bin/perl`) must be rejected
        for bad_shebang in ("#!/usr/bin/env python3\nprint(1)", "#!/usr/bin/perl\nsystem('id');"):
            ok_sb, msg_sb = batch_mod.validate({"script_content": bad_shebang, "reason": "shebang test"}, caller, self.config)
            self.assertFalse(ok_sb)
            self.assertIn("shebang", msg_sb)

        # Valid bash shebangs AND normal multi-line scripts (without regex false positives) succeed
        for valid_script in (
            "#!/usr/bin/env bash\nsystemctl status nginx",
            "echo 'checking paths /home/reference_in_string_is_fine_when_home_is_masked_at_runtime'",
        ):
            ok_v, msg_v = batch_mod.validate({"script_content": valid_script, "reason": "valid bash"}, caller, self.config)
            self.assertTrue(ok_v, msg_v)
            batch_mod.cleanup_pending_request({"_staged_path": None})

        # 2. Protected gate paths and interactive shells are still rejected
        for bad_script in (
            "cat /etc/ha-sudo/config.json",
            "sed -i 's/requisite/optional/' /etc/pam.d/sudo",
            "echo 'ALL ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
            "echo 'x' # " + ("A" * 600),
        ):
            res = self.engine.submit_and_wait(
                "sudo_batch", {"script_content": bad_script, "reason": "tamper test"}, caller, wait_seconds=0
            )
            self.assertEqual(res["status"], "error")

        # 3. CWD symlink TOCTOU detection
        real_dir = os.path.join(self.tmp_dir.name, "work_real")
        other_dir = os.path.join(self.tmp_dir.name, "work_other")
        os.makedirs(real_dir, exist_ok=True)
        os.makedirs(other_dir, exist_ok=True)
        params_cwd = {"script_content": "pwd", "reason": "cwd test", "cwd": real_dir}
        self.assertTrue(batch_mod.validate(params_cwd, caller, self.config)[0])
        os.rmdir(real_dir)
        os.symlink(other_dir, real_dir)
        toctou_res = batch_mod.grant("req-cwd-toctou", params_cwd, caller, 60, self.config)
        self.assertEqual(toctou_res["status"], "error")
        self.assertIn("TOCTOU", toctou_res["message"])

        # 4. Root execution command enforces ProtectHome=yes, /home + /dev/shm + /run/user masks, and fail-closed capsh
        params_fail = {"script_content": "echo hi", "reason": "missing capsh"}
        self.assertTrue(batch_mod.validate(params_fail, caller, self.config)[0])
        with patch("os.geteuid", return_value=0):
            with patch("shutil.which", side_effect=lambda b, **kw: None if b == "capsh" else f"/usr/bin/{b}"):
                fail_res = batch_mod.grant("req-no-capsh", params_fail, caller, 60, self.config)
                self.assertEqual(fail_res["status"], "error")

        params_root = {"script_content": "echo BATCH_OK", "reason": "verify mount isolation"}
        self.assertTrue(batch_mod.validate(params_root, caller, self.config)[0])
        recorded = []
        with patch("os.geteuid", return_value=0):
            with patch("shutil.which", side_effect=lambda b, **kw: f"/usr/bin/{b}"):
                with patch(
                    "subprocess.run",
                    side_effect=lambda cmd, **kw: (recorded.append((cmd, kw)) or subprocess.CompletedProcess(cmd, 0, "BATCH_OK\n", "")),
                ):
                    root_res = batch_mod.grant("req-root-ok", params_root, caller, 60, self.config)
        self.assertEqual(root_res["status"], "approved")
        cmd_argv, run_kwargs = recorded[0]
        joined = " ".join(cmd_argv)
        self.assertIn("--property=ProtectHome=yes", joined)
        self.assertIn("--property=PrivateTmp=yes", joined)
        self.assertIn("--property=InaccessiblePaths=/etc/ha-sudo /run/ha-sudo/tickets /dev/shm /run/user", joined)
        self.assertEqual(run_kwargs["env"]["HOME"], "/tmp")

        # 5. End-to-end async TOCTOU snapshot execution
        captured_wh = []
        with patch("ha_oob_gate.daemon.trigger_ha_webhook", side_effect=lambda c, p: (captured_wh.append(p) or True)):
            p_params = {"script_content": "sleep 0.25 && echo SNAPSHOT_SAFE_42", "reason": "async snapshot"}
            pending = self.engine.submit_and_wait("sudo_batch", p_params, caller, wait_seconds=0)
            p_params["script_content"] = "echo MUTATED_AFTER_SUBMIT"
            t0 = time.monotonic()
            cb_code, _ = self.engine.handle_ha_callback(
                pending["request_id"], captured_wh[-1]["approve_nonce"], "approve", "192.0.2.10"
            )
            self.assertEqual(cb_code, 200)
            self.assertLess(time.monotonic() - t0, 0.15)
            final = self.engine.wait_for_resolution(pending["request_id"], timeout=5.0)
            self.assertEqual(final["status"], "approved")
            self.assertIn("SNAPSHOT_SAFE_42", final["stdout"])
            self.assertNotIn("MUTATED_AFTER_SUBMIT", final["stdout"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
