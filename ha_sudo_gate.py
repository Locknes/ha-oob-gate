#!/usr/bin/env python3
"""
ha_sudo_gate.py - Unified Entrypoint for Modular Home Assistant OOB Gate (v5.0.0).

Delegates to the `ha_oob_gate` package, supporting:
- Persistent root daemon (`--daemon`) with kernel `SO_PEERCRED` Unix socket verification
- Linux PAM sudo helper (`--pam`) with single-use command pinning & break-glass recovery
- OpenSSH ForceCommand helper (`--ssh-enforce`) with allowlisted commands & RuntimeMaxSec enforcement
- Native MCP stdio server (`--mcp-stdio`)
- Modular CLI subcommands (`sudo-batch`, `k8s-token`, `github-token`, `ha-api`, `confirm`, `secret-checkout`, `revoke`)
"""

from __future__ import annotations

import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from ha_oob_gate import __version__
from ha_oob_gate.cli import main
from ha_oob_gate.daemon import (
    GateEngine,
    get_or_create_hmac_key,
    load_config,
    run_daemon,
    trigger_ha_webhook,
)
from ha_oob_gate.modules.pam_sudo import (
    compute_ticket_signature,
    create_signed_ticket,
    verify_and_consume_ticket,
)
from ha_oob_gate.sanitize import sanitize_text

__all__ = [
    "__version__",
    "main",
    "load_config",
    "run_daemon",
    "get_or_create_hmac_key",
    "trigger_ha_webhook",
    "GateEngine",
    "sanitize_text",
    "compute_ticket_signature",
    "verify_and_consume_ticket",
    "create_signed_ticket",
]

if __name__ == "__main__":
    main()
