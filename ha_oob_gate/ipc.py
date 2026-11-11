"""
ipc.py - Newline-delimited JSON (NDJSON) framing over Unix domain sockets.

Keeps the client write half open (no `shutdown(SHUT_WR)`) so the server can
reliably distinguish an active waiting caller from a `Ctrl+C` / EOF disconnect
via `select` + `MSG_PEEK | MSG_DONTWAIT`.
"""

from __future__ import annotations

import json
import socket
from typing import Any, Dict, Optional

DEFAULT_MAX_FRAME_BYTES = 131072


class FrameTooLargeError(ValueError):
    """Raised when an incoming NDJSON frame exceeds `max_bytes`."""


def encode_json_frame(payload: Dict[str, Any]) -> bytes:
    """Encode a dictionary as a single newline-delimited UTF-8 JSON frame."""
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def send_json_frame(sock: socket.socket, payload: Dict[str, Any]) -> None:
    """Send a single newline-delimited JSON frame over `sock`."""
    sock.sendall(encode_json_frame(payload))


def recv_json_frame(
    sock: socket.socket,
    max_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> Optional[Dict[str, Any]]:
    """
    Read a single newline-delimited JSON frame from `sock`.
    Returns `None` on clean EOF with zero bytes read.
    Also tolerates legacy EOF-terminated frames that omit a trailing newline.
    """
    buf = bytearray()
    while True:
        remaining = max_bytes - len(buf) + 1
        chunk = sock.recv(min(4096, max(1, remaining)))
        if not chunk:
            break
        nl_idx = chunk.find(b"\n")
        if nl_idx != -1:
            buf.extend(chunk[:nl_idx])
            if len(buf) > max_bytes:
                raise FrameTooLargeError("Payload exceeds maximum size")
            raw = bytes(buf).strip()
            if not raw:
                return None
            obj = json.loads(raw.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("IPC frame must be a JSON object")
            return obj
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise FrameTooLargeError("Payload exceeds maximum size")

    raw = bytes(buf).strip()
    if not raw:
        return None
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("IPC frame must be a JSON object")
    return obj
