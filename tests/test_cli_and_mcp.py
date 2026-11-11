"""
test_cli_and_mcp.py - Behavioral tests for CLI stdout/stderr contracts, lazy import
side-effect freedom, MCP JSON-RPC 2.0 server (`oob_ha_api` lease + `oob_ha_api_call` +
`oob_revoke`), and `MinimalWebSocket` / atomic secret rotation in `rotate_ha_service_token.py`.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ha_oob_gate import __version__
from ha_oob_gate.mcp_server import handle_mcp_jsonrpc_message
from ha_oob_gate.rotate_ha_service_token import MinimalWebSocket, write_secret_file_atomic


class TestCliMcpAndTokenRotation(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.runtime_dir = os.path.join(self.tmp_dir.name, "runtime")
        os.makedirs(self.runtime_dir, mode=0o700, exist_ok=True)
        self.config = {
            "ha_url": "https://homeassistant.example.com",
            "ha_trusted_ip": "192.0.2.10",
            "webhook_id": "e" * 32,
            "callback_host": "192.0.2.20",
            "callback_port": 8443,
            "listen_port": 8443,
            "timeout_seconds": 30,
            "socket_path": os.path.join(self.tmp_dir.name, "daemon.sock"),
        }
        # Create dummy socket file so `os.path.exists(config["socket_path"])` is True for local CLI path
        open(self.config["socket_path"], "w", encoding="utf-8").close()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_importing_cli_has_zero_filesystem_mutation_side_effects(self) -> None:
        import ha_oob_gate.cli as cli_mod

        with patch("os.makedirs", side_effect=AssertionError("Import must not call os.makedirs!")):
            with patch("os.chmod", side_effect=AssertionError("Import must not call os.chmod!")):
                importlib.reload(cli_mod)

    def test_cli_subcommands_emit_machine_clean_stdout_and_banners_on_stderr(self) -> None:
        import ha_oob_gate.cli as cli_mod

        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.runtime_dir}, clear=False):
            with patch("ha_oob_gate.cli.load_config", return_value=self.config):
                # 1. `oob-auth k8s-token` -> stdout is `export K8S_JIT_TOKEN=...`, banners on stderr
                out_k8s, err_k8s = io.StringIO(), io.StringIO()
                with patch(
                    "ha_oob_gate.cli.send_unix_socket_request",
                    return_value={
                        "status": "approved",
                        "request_id": "req-k8s-1",
                        "caller_nonce": "nonce-k8s-1",
                        "token": "eyJhbGciOiJSUzI1NiJ9.fake.k8sjwt",
                        "service_account": "jit-system/jit-oob-123",
                        "expires_at": "2026-11-11T20:00:00Z",
                    },
                ):
                    with redirect_stdout(out_k8s), redirect_stderr(err_k8s):
                        cli_mod.main(["k8s-token", "--namespaces", "default", "--reason", "Deploy app"])
                self.assertEqual(out_k8s.getvalue(), "export K8S_JIT_TOKEN=eyJhbGciOiJSUzI1NiJ9.fake.k8sjwt\n")
                self.assertIn("[oob-auth]", err_k8s.getvalue())

                # 2. `oob-auth secret-checkout` (without `--stdout`) -> stdout is ONLY the 0600 file path!
                out_sec, err_sec = io.StringIO(), io.StringIO()
                with patch(
                    "ha_oob_gate.cli.send_unix_socket_request",
                    return_value={"status": "approved", "value": "top-secret-api-token"},
                ):
                    with redirect_stdout(out_sec), redirect_stderr(err_sec):
                        with self.assertRaises(SystemExit) as cm_sec:
                            cli_mod.main(["secret-checkout", "--key", "ext_api", "--reason", "Backup"])
                        self.assertEqual(cm_sec.exception.code, 0)
                sec_path = out_sec.getvalue().strip()
                self.assertTrue(os.path.isfile(sec_path), f"Expected file path on stdout, got: {sec_path!r}")
                self.assertEqual(os.stat(sec_path).st_mode & 0o777, 0o600)
                with open(sec_path, "r", encoding="utf-8") as sf:
                    self.assertEqual(sf.read(), "top-secret-api-token")
                self.assertIn("[oob-auth]", err_sec.getvalue())

    def test_mcp_server_version_and_ha_api_lease_workflow(self) -> None:
        init_resp = handle_mcp_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, self.config)
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "ha-oob-gate")
        self.assertEqual(init_resp["result"]["serverInfo"]["version"], __version__)
        self.assertEqual(__version__, "5.0.0")

        list_resp = handle_mcp_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, self.config)
        tool_names = {t["name"] for t in list_resp["result"]["tools"]}
        self.assertEqual(
            tool_names,
            {
                "oob_sudo_batch",
                "oob_k8s_token",
                "oob_github_token",
                "oob_ha_api",
                "oob_ha_api_call",
                "oob_secret_checkout",
                "oob_confirm",
                "oob_revoke",
            },
        )

        # 1. `oob_ha_api` in `mode="single"` without `path` returns validation error
        err_single = handle_mcp_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "oob_ha_api", "arguments": {"mode": "single", "reason": "Missing path"}},
            },
            self.config,
            socket_requester=lambda s, p, t: {"status": "approved"},
        )
        self.assertTrue(err_single["result"]["isError"])

        # 2. `oob_ha_api` in `mode="lease"` WITHOUT `path` succeeds, followed by `oob_ha_api_call` and `oob_revoke`
        recorded_ipc = []

        def fake_ipc(sock_path, payload, timeout):
            recorded_ipc.append(payload)
            if payload["action"] == "module_request" and payload["module"] == "ha_api":
                return {"status": "approved", "request_id": "lease-123", "caller_nonce": "cnonce-456", "mode": "lease"}
            if payload["action"] == "ha_proxy_call":
                return {"status": "ok", "http_status": 200, "data": [{"entity_id": "sensor.temp", "state": "21.5"}]}
            if payload["action"] == "revoke":
                return {"status": "revoked", "request_id": payload["request_id"]}
            return {"status": "error"}

        lease_resp = handle_mcp_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "oob_ha_api", "arguments": {"mode": "lease", "scope": "read", "reason": "Read sensors"}},
            },
            self.config,
            socket_requester=fake_ipc,
        )
        self.assertFalse(lease_resp["result"]["isError"])

        call_resp = handle_mcp_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "oob_ha_api_call",
                    "arguments": {
                        "request_id": "lease-123",
                        "caller_nonce": "cnonce-456",
                        "method": "GET",
                        "path": "/api/states",
                    },
                },
            },
            self.config,
            socket_requester=fake_ipc,
        )
        self.assertFalse(call_resp["result"]["isError"])
        self.assertIn("sensor.temp", call_resp["result"]["content"][0]["text"])

        rev_resp = handle_mcp_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "oob_revoke",
                    "arguments": {"request_id": "lease-123", "caller_nonce": "cnonce-456"},
                },
            },
            self.config,
            socket_requester=fake_ipc,
        )
        self.assertFalse(rev_resp["result"]["isError"])
        self.assertEqual([p["action"] for p in recorded_ipc], ["module_request", "ha_proxy_call", "revoke"])

    def test_rotate_ha_service_token_atomic_0600_write_and_websocket_framing(self) -> None:
        # 1. Atomic 0600 secret file write (never world-readable at creation)
        tok_path = Path(self.tmp_dir.name) / "secrets" / "ha_admin_token"
        write_secret_file_atomic(tok_path, "new-long-lived-token-xyz")
        self.assertEqual(tok_path.read_text(encoding="utf-8"), "new-long-lived-token-xyz\n")
        self.assertEqual(tok_path.stat().st_mode & 0o777, 0o600)

        # 2. MinimalWebSocket buffered HTTP upgrade (coalesced with first WS frame + ping/pong!)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        server_seen_pong = threading.Event()

        def make_server_frame(opcode: int, payload: bytes) -> bytes:
            hdr = bytearray([0x80 | opcode])
            n = len(payload)
            if n < 126:
                hdr.append(n)
            elif n < 65536:
                hdr.append(126)
                hdr.extend(struct.pack("!H", n))
            else:
                hdr.append(127)
                hdr.extend(struct.pack("!Q", n))
            return bytes(hdr) + payload

        def read_masked_client_frame(conn: socket.socket) -> tuple[int, bytes]:
            b1, b2 = conn.recv(2)
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", conn.recv(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", conn.recv(8))
            mask_key = conn.recv(4) if masked else b""
            data = bytearray()
            while len(data) < length:
                data.extend(conn.recv(length - len(data)))
            if masked:
                return opcode, bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
            return opcode, bytes(data)

        def ws_server():
            conn, _ = srv.accept()
            try:
                req = b""
                while b"\r\n\r\n" not in req:
                    req += conn.recv(4096)
                ws_key = ""
                for line in req.decode("latin1").split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        ws_key = line.split(":", 1)[1].strip()
                accept = base64.b64encode(
                    hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
                ).decode("ascii")

                # Coalesce 101 Switching Protocols + Ping frame + auth_required JSON frame in ONE sendall()!
                greeting = make_server_frame(0x1, json.dumps({"type": "auth_required"}).encode("utf-8"))
                ping_frame = make_server_frame(0x9, b"ping-check")
                conn.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    ).encode("ascii")
                    + ping_frame
                    + greeting
                )

                # Expect masked Pong (`0xA`), then masked auth JSON (`0x1`)
                op1, data1 = read_masked_client_frame(conn)
                if op1 == 0xA and data1 == b"ping-check":
                    server_seen_pong.set()
                op2, data2 = read_masked_client_frame(conn)
                auth_msg = json.loads(data2.decode("utf-8"))
                if op2 == 0x1 and auth_msg.get("access_token") == "test-tok":
                    conn.sendall(make_server_frame(0x1, json.dumps({"type": "auth_ok"}).encode("utf-8")))
            finally:
                conn.close()
                srv.close()

        t = threading.Thread(target=ws_server, daemon=True)
        t.start()
        with MinimalWebSocket(f"ws://127.0.0.1:{port}/api/websocket", verify_ssl=False, timeout=5.0) as ws:
            ws.authenticate("test-tok")
        self.assertTrue(server_seen_pong.wait(timeout=2.0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
