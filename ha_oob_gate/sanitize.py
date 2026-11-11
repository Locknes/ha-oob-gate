"""
Sanitization, cryptographic helpers, and format validators for ha_oob_gate.
Prevents ANSI terminal escape injection and Home Assistant Jinja2 template injection.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX64_REGEX = re.compile(r"^[0-9a-f]{64}$")
ANSI_ESCAPE_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def sanitize_text(val: Any, max_len: int = 1024, allow_newlines: bool = False) -> str:
    """
    Strip ANSI escape sequences, non-printable control characters, neutralize
    Jinja2 template delimiters ({{, }}, {%, %}, {#), and truncate safely.
    By default (`allow_newlines=False`), newlines/carriage returns are collapsed to
    spaces to prevent multiline visual spoofing in single-line metadata fields.
    """
    if val is None:
        return ""
    if not isinstance(val, str):
        val = str(val)

    # 1. Strip ANSI CSI/OSC sequences
    val = ANSI_ESCAPE_REGEX.sub("", val)

    # 2. Strip non-printable control characters (collapse newlines unless allow_newlines=True)
    if allow_newlines:
        cleaned = "".join(ch for ch in val if ch.isprintable() or ch in " \t\n")
    else:
        val = val.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        cleaned = "".join(ch for ch in val if ch.isprintable() or ch == " ")

    # 3. Neutralize Home Assistant Jinja2 delimiters to prevent SSTI
    cleaned = (
        cleaned.replace("{{", "{ {")
        .replace("}}", "} }")
        .replace("{%", "{ %")
        .replace("%}", "% }")
        .replace("{#", "{ #")
        .replace("#}", "# }")
    )

    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "... [truncated]"
    return cleaned.strip()


def sha256_hex(data: str | bytes) -> str:
    """Return hex-encoded SHA-256 digest of string or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
