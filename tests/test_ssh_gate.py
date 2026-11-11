"""
test_ssh_gate.py - Behavioral tests for SshGateModule allowlist enforcement,
versioned interpreter & GTFOBins rejection, `run_ssh_enforce` execution, and
orphaned background child termination in `SshGateModule.revoke()`.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate.cli import run_ssh_enforce
from ha_oob_gate.daemon import GateEngine
from ha_oob_gate.modules import CallerInfo


class TestSshGateModule(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config = {
            "ha_url": "https://homeassistant.example.com",
            "ha_trusted_ip": "192.0.2.10",
            "webhook_id": "c" * 32,
            "callback_host": "192.0.2.20",
            "callback_port": 8443,
            "listen_port": 8443,
            "timeout_seconds": 30,
            "hmac_key_path": os.path.join(self.tmp_dir.name, "hmac.key"),
            "ticket_dir": os.path.join(self.tmp_dir.name, "tickets"),
            "socket_path": os.path.join(self.tmp_dir.name, "daemon.sock"),
        }
        self.engine = GateEngine(self.config)
        self.ssh_mod = self.engine.modules["ssh_gate"]
        self.caller = CallerInfo(uid=1001, gid=1001, pid=5001, username="ops-user", is_root=False)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_allowlist_blocks_shells_metacharacters_versioned_interpreters_and_gtfobins(self) -> None:
        fake_root_stat = os.stat_result((0o100755, 1, 1, 1, 0, 0, 100, 0, 0, 0))
        with patch("ha_oob_gate.command_policy.shutil.which", side_effect=lambda b, **kw: f"/usr/bin/{os.path.basename(b)}"):
            with patch("ha_oob_gate.command_policy.os.path.realpath", side_effect=lambda p: p):
                with patch("ha_oob_gate.command_policy.os.stat", return_value=fake_root_stat):
                    for bad_cmd in (
                        "",
                        "bash",
                        "bash -i",
                        "uptime; id",
                        "uptime && /bin/sh",
                        "uptime | cat",
                        "echo $(id)",
                        "python3.12 -c 'import pty; pty.spawn(\"/bin/sh\")'",
                        "perl5.38 -e 'exec \"/bin/sh\"'",
                        "ruby3.2 -e 'exec \"/bin/sh\"'",
                        "node20 -e 'require(\"child_process\").spawn(\"/bin/sh\")'",
                        "vim /etc/hosts",
                        "git status",
                        "systemctl restart nginx",  # only status/is-active/is-failed/list-units/show allowed by default!
                        "cp /etc/hosts /tmp/h",
                        "curl https://example.com",
                        "echo " + ("X" * 510),
                    ):
                        ok, _ = self.ssh_mod.validate({"command": bad_cmd}, self.caller, self.config)
                        self.assertFalse(ok, f"Expected SSH gate to block {bad_cmd!r}")

                    # Default allowlisted read-only diagnostics succeed
                    for good_cmd in (
                        "systemctl status nginx",
                        "systemctl is-active sshd",
                        "journalctl -u ha-sudo-gate.service -n 50",
                        "df -h",
                        "uptime",
                    ):
                        ok, msg = self.ssh_mod.validate({"command": good_cmd}, self.caller, self.config)
                        self.assertTrue(ok, f"Expected {good_cmd!r} to be allowed, got: {msg}")

        # Symlink in user directory pointing to /bin/bash is rejected
        sym_bash = os.path.join(self.tmp_dir.name, "uptime")
        os.symlink("/bin/bash", sym_bash)
        self.assertFalse(self.ssh_mod.validate({"command": sym_bash}, self.caller, self.config)[0])

        # Non-root-owned binary in /usr/bin is rejected
        nonroot_stat = os.stat_result((0o100755, 1, 1, 1, 1001, 1001, 100, 0, 0, 0))
        with patch("ha_oob_gate.command_policy.shutil.which", return_value="/usr/bin/uptime"):
            with patch("ha_oob_gate.command_policy.os.path.realpath", return_value="/usr/bin/uptime"):
                with patch("ha_oob_gate.command_policy.os.stat", return_value=nonroot_stat):
                    self.assertFalse(self.ssh_mod.validate({"command": "uptime"}, self.caller, self.config)[0])

    def test_run_ssh_enforce_sets_non_interactive_pagers_and_unit_name(self) -> None:
        exec_user = []
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "systemctl status sshd", "SSH_CLIENT": "192.0.2.50 1234 22"}):
            with patch(
                "ha_oob_gate.cli.send_unix_socket_request",
                return_value={"status": "approved", "max_runtime_seconds": 90, "unit_name": "ha-oob-ssh-testunit"},
            ):
                with patch("ha_oob_gate.cli.os.geteuid", return_value=1001):
                    with patch("ha_oob_gate.cli._can_run_systemd_user_scope", return_value=True):
                        with patch("os.execvp", side_effect=lambda p, a: exec_user.append((p, a, os.environ.get("SYSTEMD_PAGER")))):
                            run_ssh_enforce(self.config)

        prog, argv, pager_env = exec_user[0]
        self.assertEqual(prog, "systemd-run")
        self.assertIn("--user", argv)
        self.assertIn("--unit=ha-oob-ssh-testunit", argv)
        self.assertEqual(pager_env, "cat")
        self.assertEqual(argv[-3:], ["systemctl", "status", "sshd"])

        exec_timeout = []
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "uptime", "SSH_CLIENT": "192.0.2.50 1234 22"}):
            with patch("ha_oob_gate.cli.send_unix_socket_request", return_value={"status": "approved", "max_runtime_seconds": 60}):
                with patch("ha_oob_gate.cli.os.geteuid", return_value=1001):
                    with patch("ha_oob_gate.cli._can_run_systemd_user_scope", return_value=False):
                        with patch("os.execvp", side_effect=lambda p, a: exec_timeout.append((p, a))):
                            run_ssh_enforce(self.config)
        self.assertEqual(exec_timeout[0][0], "timeout")
        self.assertNotIn("--foreground", exec_timeout[0][1])

    def test_pid_spoofing_blocked_and_orphaned_background_child_killed_on_revoke(self) -> None:
        # 1. Spoofed PID 1 / UID 0 is rejected
        spoof_caller = CallerInfo(uid=1001, gid=1001, pid=999999, username="ops-user", is_root=False)
        g_spoof = self.ssh_mod.grant("req-spoof", {"command": "uptime", "pid": 1}, spoof_caller, 60, self.config)
        self.assertEqual(g_spoof["lease_metadata"]["pid"], 0)
        self.assertFalse(self.ssh_mod.revoke("req-spoof", {"pid": 1, "pgid": 1, "uid": 0}, self.config))
        self.assertFalse(self.ssh_mod.revoke("req-spoof", {"pid": 1, "pgid": 1, "uid": 1001}, self.config))

        # 2. Spawn a session/process-group leader that forks an orphaned background `sleep 30` child
        #    and then EXITS immediately (so the original leader PID no longer exists in `/proc/<pid>`!).
        orphan_pid_file = os.path.join(self.tmp_dir.name, "orphan.pid")
        leader = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import os, subprocess, time\n"
                    "child = subprocess.Popen(['sleep', '30'])\n"
                    f"open({orphan_pid_file!r}, 'w').write(str(child.pid))\n"
                    "time.sleep(0.15)\n"
                ),
            ],
            start_new_session=True,
        )
        orphan_pid = 0
        try:
            # Grant while leader is alive so `pgid` and `sid` are recorded
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not os.path.exists(orphan_pid_file):
                time.sleep(0.02)
            with open(orphan_pid_file, "r", encoding="utf-8") as f:
                orphan_pid = int(f.read().strip())

            real_caller = CallerInfo(uid=os.getuid(), gid=os.getgid(), pid=leader.pid, username="ops-user", is_root=False)
            g_res = self.ssh_mod.grant("req-orphan-kill", {"command": "uptime"}, real_caller, 60, self.config)
            self.assertEqual(g_res["lease_metadata"]["pgid"], leader.pid)

            # Wait for the PGID leader to exit so `/proc/<leader.pid>` is completely gone!
            leader.wait(timeout=3.0)
            os.kill(orphan_pid, 0)  # Prove orphaned child is still alive after leader exited

            # Revoke must scan `/proc` for matching `(pgid, sid, uid)` and kill the orphaned child!
            self.assertTrue(self.ssh_mod.revoke("req-orphan-kill", g_res["lease_metadata"], self.config))

            wait_dead = time.monotonic() + 3.0
            alive = True
            while time.monotonic() < wait_dead:
                try:
                    os.kill(orphan_pid, 0)
                    time.sleep(0.03)
                except ProcessLookupError:
                    alive = False
                    break
            self.assertFalse(alive, f"Orphaned child PID {orphan_pid} survived SshGateModule.revoke()!")
        finally:
            if leader.poll() is None:
                leader.kill()
                leader.wait()
            if orphan_pid:
                try:
                    os.kill(orphan_pid, 9)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
