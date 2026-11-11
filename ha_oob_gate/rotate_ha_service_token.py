#!/usr/bin/env python3
"""Provision or rotate a dedicated Home Assistant service-account token for ha-oob-gate.

100% Python standard library implementation (no third-party packages required).
Uses a temporary bootstrap admin token in `/etc/ha-sudo/secrets/ha_admin_token` to:
1. Find or create a dedicated Home Assistant admin service user (defaults to `<HOSTNAME>`).
2. Ensure local `homeassistant` auth provider credentials exist for that user.
3. Complete a local login flow as that service user to obtain a user-scoped session.
4. Mint a 10-year Long-Lived Access Token owned by that service user.
5. Verify the new token and atomically replace `/etc/ha-sudo/secrets/ha_admin_token` (`0600`).
6. Revoke the temporary bootstrap token so any terminal-pasted token is invalidated.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/ha-sudo/config.json")
DEFAULT_TOKEN_PATH = Path("/etc/ha-sudo/secrets/ha_admin_token")
TOKEN_LIFESPAN_DAYS = 3650
MAX_HANDSHAKE_HEADER_BYTES = 16384


def _ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    if verify_ssl:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def write_secret_file_atomic(target_path: Path, secret_value: str) -> None:
    """Atomically write `secret_value` to `target_path` using an `0600` temp file with `O_NOFOLLOW`."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_name(f".{target_path.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(secret_value.strip() + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp_path), str(target_path))
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise


class MinimalWebSocket:
    """Minimal RFC 6455 WebSocket client using only the Python standard library."""

    def __init__(self, url: str, verify_ssl: bool = True, timeout: float = 15.0) -> None:
        parsed = urllib.parse.urlparse(url)
        self.scheme = parsed.scheme.lower()
        self.host = parsed.hostname or "localhost"
        self.port = parsed.port or (443 if self.scheme in ("wss", "https") else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.sock: socket.socket | ssl.SSLSocket | None = None
        self._rx_buf = bytearray()
        self._msg_id = 0

    def __enter__(self) -> "MinimalWebSocket":
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.scheme in ("wss", "https"):
            ctx = _ssl_context(self.verify_ssl)
            self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        host_hdr = f"{self.host}:{self.port}" if self.port not in (80, 443) else self.host
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        self.sock.sendall(req.encode("ascii"))

        header_buf = bytearray()
        while b"\r\n\r\n" not in header_buf:
            if len(header_buf) >= MAX_HANDSHAKE_HEADER_BYTES:
                raise RuntimeError("WebSocket handshake headers exceeded 16 KiB limit")
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed during WebSocket handshake")
            header_buf.extend(chunk)

        sep_idx = header_buf.index(b"\r\n\r\n") + 4
        if sep_idx < len(header_buf):
            self._rx_buf.extend(header_buf[sep_idx:])
        raw_headers = bytes(header_buf[:sep_idx])
        status_line = raw_headers.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        if " 101 " not in status_line:
            raise RuntimeError(f"WebSocket handshake failed: {status_line}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.sock is not None:
            try:
                self._send_frame(0x8, b"")
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _recv_exact(self, n: int) -> bytes:
        assert self.sock is not None
        out = bytearray()
        if self._rx_buf:
            take = min(n, len(self._rx_buf))
            out.extend(self._rx_buf[:take])
            del self._rx_buf[:take]
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise RuntimeError("WebSocket connection closed unexpectedly")
            out.extend(chunk)
        return bytes(out)

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        """Encode and send a client-masked RFC 6455 WebSocket frame (`<126`, `16-bit`, or `64-bit` length)."""
        assert self.sock is not None
        mask_key = os.urandom(4)
        header = bytearray([0x80 | (opcode & 0x0F)])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def send_json(self, obj: dict) -> None:
        payload = json.dumps(obj).encode("utf-8")
        self._send_frame(0x1, payload)

    def recv_json(self) -> dict:
        assert self.sock is not None
        fragments: list[bytes] = []
        while True:
            b1, b2 = self._recv_exact(2)
            fin = bool(b1 & 0x80)
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", self._recv_exact(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", self._recv_exact(8))
            mask_key = self._recv_exact(4) if masked else b""
            data = self._recv_exact(length)
            if masked:
                data = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))

            if opcode == 0x8:
                raise RuntimeError("WebSocket closed by server")
            if opcode == 0x9:
                # RFC 6455 control frames must have payload <= 125 bytes
                self._send_frame(0xA, data[:125])
                continue
            if opcode in (0x0, 0x1, 0x2):
                fragments.append(data)
                if fin:
                    raw = b"".join(fragments).decode("utf-8")
                    return json.loads(raw)

    def authenticate(self, token: str) -> None:
        first = self.recv_json()
        if first.get("type") != "auth_required":
            raise RuntimeError(f"Unexpected WebSocket greeting: {first}")
        self.send_json({"type": "auth", "access_token": token})
        resp = self.recv_json()
        if resp.get("type") != "auth_ok":
            raise RuntimeError(f"WebSocket authentication failed: {resp}")

    def call_cmd(self, payload: dict) -> dict:
        self._msg_id += 1
        req_id = self._msg_id
        self.send_json({"id": req_id, **payload})
        while True:
            resp = self.recv_json()
            if resp.get("id") == req_id:
                return resp


def _http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    form_body: dict[str, str] | None = None,
    verify_ssl: bool = True,
) -> dict:
    req_headers = dict(headers or {})
    data: bytes | None = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    ctx = _ssl_context(verify_ssl) if url.lower().startswith("https://") else None
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ensure_user_and_credentials(
    ws_url: str,
    admin_token: str,
    verify_ssl: bool,
    target_user_name: str,
    target_username: str,
) -> tuple[str, str, str]:
    with MinimalWebSocket(ws_url, verify_ssl=verify_ssl) as ws:
        ws.authenticate(admin_token)
        resp = ws.call_cmd({"type": "config/auth/list"})
        if not resp.get("success"):
            raise RuntimeError(f"Failed to list users: {resp}")

        users = resp.get("result", [])
        target_user = None
        for u in users:
            if (u.get("name") or "").strip().lower() == target_user_name.lower():
                target_user = u
                break
            for cred in u.get("credentials", []):
                if (cred.get("username") or "").strip().lower() == target_username.lower():
                    target_user = u
                    break
            if target_user:
                break

        if target_user is None:
            print(f"[*] Creating Home Assistant admin service user '{target_user_name}'...")
            create_resp = ws.call_cmd(
                {
                    "type": "config/auth/create",
                    "name": target_user_name,
                    "group_ids": ["system-admin"],
                    "local_only": False,
                }
            )
            if not create_resp.get("success"):
                raise RuntimeError(f"Failed to create user {target_user_name}: {create_resp}")
            target_user = create_resp["result"]["user"]
        else:
            print(f"[*] Found existing Home Assistant user '{target_user.get('name')}' (id={target_user.get('id')})")

        user_id = target_user["id"]
        temp_password = secrets.token_urlsafe(24)

        ha_cred = None
        for cred in target_user.get("credentials", []):
            if cred.get("type") == "homeassistant":
                ha_cred = cred
                break

        if ha_cred is None:
            username = target_username
            print(f"[*] Attaching local 'homeassistant' credentials for username '{username}'...")
            cred_resp = ws.call_cmd(
                {
                    "type": "config/auth_provider/homeassistant/create",
                    "user_id": user_id,
                    "username": username,
                    "password": temp_password,
                }
            )
            if not cred_resp.get("success"):
                raise RuntimeError(f"Failed to create local credentials: {cred_resp}")
        else:
            username = ha_cred.get("username") or target_username
            print(f"[*] Setting temporary password on existing username '{username}'...")
            pw_resp = ws.call_cmd(
                {
                    "type": "config/auth_provider/homeassistant/admin_change_password",
                    "user_id": user_id,
                    "password": temp_password,
                }
            )
            if not pw_resp.get("success"):
                raise RuntimeError(f"Failed to set password on '{username}': {pw_resp}")

        return user_id, username, temp_password


def _login_as_user(ha_url: str, username: str, password: str, verify_ssl: bool) -> str:
    client_id = f"{ha_url}/"
    redirect_uri = f"{ha_url}/?auth_callback=1"

    flow = _http_json(
        f"{ha_url}/auth/login_flow",
        method="POST",
        json_body={
            "client_id": client_id,
            "handler": ["homeassistant", None],
            "redirect_uri": redirect_uri,
        },
        verify_ssl=verify_ssl,
    )
    flow_id = flow.get("flow_id")
    if not flow_id:
        raise RuntimeError(f"Failed to start login flow: {flow}")

    step = _http_json(
        f"{ha_url}/auth/login_flow/{flow_id}",
        method="POST",
        json_body={
            "client_id": client_id,
            "username": username,
            "password": password,
        },
        verify_ssl=verify_ssl,
    )
    if step.get("type") != "create_entry" or not step.get("result"):
        raise RuntimeError(f"Login flow failed for '{username}': {step}")

    code = step["result"]
    token_resp = _http_json(
        f"{ha_url}/auth/token",
        method="POST",
        form_body={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
        },
        verify_ssl=verify_ssl,
    )
    access_token = token_resp.get("access_token")
    if not access_token:
        raise RuntimeError(f"Failed to exchange auth code for access token: {token_resp}")
    return access_token


def _mint_llat(ws_url: str, user_access_token: str, verify_ssl: bool, client_name: str) -> str:
    with MinimalWebSocket(ws_url, verify_ssl=verify_ssl) as ws:
        ws.authenticate(user_access_token)
        tokens_resp = ws.call_cmd({"type": "auth/refresh_tokens"})
        if tokens_resp.get("success"):
            for rt in tokens_resp.get("result", []):
                if rt.get("type") == "long_lived_access_token" and rt.get("client_name") == client_name:
                    ws.call_cmd({"type": "auth/delete_refresh_token", "refresh_token_id": rt["id"]})

        resp = ws.call_cmd(
            {
                "type": "auth/long_lived_access_token",
                "client_name": client_name,
                "lifespan": TOKEN_LIFESPAN_DAYS,
            }
        )
        if not resp.get("success") or not resp.get("result"):
            raise RuntimeError(f"Failed to mint long-lived access token: {resp}")
        return resp["result"]


def _extract_jwt_iss(token: str) -> str | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        return payload.get("iss")
    except Exception:
        return None


def _revoke_bootstrap_token(ws_url: str, bootstrap_token: str, verify_ssl: bool, target_user_name: str) -> None:
    iss = _extract_jwt_iss(bootstrap_token)
    if not iss:
        return
    try:
        with MinimalWebSocket(ws_url, verify_ssl=verify_ssl) as ws:
            ws.authenticate(bootstrap_token)
            me = ws.call_cmd({"type": "auth/current_user"})
            if me.get("success") and (me.get("result", {}).get("name") or "").strip().lower() == target_user_name.lower():
                return
            del_resp = ws.call_cmd({"type": "auth/delete_refresh_token", "refresh_token_id": iss})
            if del_resp.get("success"):
                print(f"[*] Revoked temporary bootstrap token (refresh_token_id={iss}) in Home Assistant.")
    except Exception as exc:
        print(f"[!] Note: Could not auto-revoke bootstrap token ({exc}); you can delete it in HA Profile -> Security.")


def main(argv: list[str] | None = None) -> int:
    default_host = socket.gethostname().split(".")[0] or "oob-gate"
    parser = argparse.ArgumentParser(description="Provision/rotate dedicated Home Assistant service token for ha-oob-gate")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to ha-oob-gate config.json")
    parser.add_argument("--token-path", default=str(DEFAULT_TOKEN_PATH), help="Path to ha_admin_token secret file")
    parser.add_argument("--service-user", default=default_host.upper(), help="Display name of HA service user")
    parser.add_argument("--username", default=default_host.lower(), help="Login username of HA service user")
    parser.add_argument("--client-name", default=f"{default_host.lower()}-oob-gate", help="LLAT client_name")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print(
            "ERROR: Please run this script with sudo so it can read/write /etc/ha-sudo/secrets/ha_admin_token.",
            file=sys.stderr,
        )
        return 1

    config_path = Path(args.config)
    token_path = Path(args.token_path)

    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    ha_url = cfg["ha_url"].rstrip("/")
    verify_ssl = bool(cfg.get("verify_ssl", True))
    ws_url = ha_url.replace("https://", "wss://").replace("http://", "ws://") + "/api/websocket"

    bootstrap_token = token_path.read_text(encoding="utf-8").strip()
    if not bootstrap_token:
        print(f"ERROR: {token_path} is empty.", file=sys.stderr)
        return 1

    user_id, username, temp_password = _ensure_user_and_credentials(
        ws_url, bootstrap_token, verify_ssl, args.service_user, args.username
    )
    print(f"[*] Logging in as '{username}' (user_id={user_id})...")
    user_session_token = _login_as_user(ha_url, username, temp_password, verify_ssl)

    print(
        f"[*] Minting {TOKEN_LIFESPAN_DAYS}-day Long-Lived Access Token '{args.client_name}' under '{args.service_user}'..."
    )
    new_llat = _mint_llat(ws_url, user_session_token, verify_ssl, args.client_name)

    check = _http_json(
        f"{ha_url}/api/",
        headers={"Authorization": f"Bearer {new_llat}"},
        verify_ssl=verify_ssl,
    )
    print(f"[*] Verified new token against {ha_url}/api/: {check.get('message')}")

    write_secret_file_atomic(token_path, new_llat)
    print(f"[+] Successfully updated {token_path} with token owned by '{args.service_user}' (user_id={user_id})!")

    _revoke_bootstrap_token(ws_url, bootstrap_token, verify_ssl, args.service_user)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
