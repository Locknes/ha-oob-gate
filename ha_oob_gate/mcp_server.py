"""
mcp_server.py - Native Zero-Dependency JSON-RPC 2.0 MCP Server (stdio) for ha_oob_gate.

Allows any MCP-compatible AI coding assistant (Claude Code, Cursor, Windsurf,
Cline, Roo Code, OpenCode, Codex, Antigravity) to invoke Out-of-Band (OOB)
elevation tools (`oob_sudo_batch`, `oob_k8s_token`, `oob_github_token`,
`oob_ha_api`, `oob_ha_api_call`, `oob_secret_checkout`, `oob_confirm`,
`oob_revoke`) natively over stdio without parsing CLI flags.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .daemon import load_config


MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "oob_sudo_batch",
        "description": (
            "Execute a SHA-256-pinned bash script snapshot as root (UID 0) after human mobile approval, "
            "with mount-namespace and systemd self-tamper / mutable-path guardrails."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "Multi-line bash script commands to execute as root"},
                "reason": {"type": "string", "description": "Human-readable reason displayed on mobile notification"},
                "cwd": {"type": "string", "description": "Optional working directory (defaults to current working directory)"},
            },
            "required": ["script", "reason"],
        },
    },
    {
        "name": "oob_k8s_token",
        "description": "Request a 30-minute namespace-scoped Kubernetes JWT gated by Home Assistant mobile approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "enum": ["view", "jit-workload-operator", "jit-storage-operator"],
                    "default": "jit-workload-operator",
                },
                "namespaces": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["default"],
                    "description": "Target Kubernetes namespaces (e.g. ['default'])",
                },
                "reason": {"type": "string", "description": "Reason for Kubernetes elevation"},
            },
            "required": ["namespaces", "reason"],
        },
    },
    {
        "name": "oob_github_token",
        "description": "Request a tag-evaluated single-repo GitHub App token (`read` or `write`) or root vault PAT.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Target repository in 'owner/repo' format"},
                "permission": {"type": "string", "enum": ["read", "write"], "default": "write"},
                "reason": {"type": "string", "description": "Reason for GitHub repository access"},
            },
            "required": ["repo", "reason"],
        },
    },
    {
        "name": "oob_ha_api",
        "description": (
            "Request a filtered Home Assistant REST API proxy call (`mode='single'`) or 15-minute proxy lease "
            "(`mode='lease'`, followed by `oob_ha_api_call`) with zero raw token exposure."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {"type": "string", "enum": ["lease", "single"], "default": "single"},
                "scope": {"type": "string", "enum": ["read", "admin"], "default": "read"},
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed service domains when scope='admin' (e.g. ['light', 'switch'])",
                },
                "method": {"type": "string", "enum": ["GET", "POST", "DELETE"], "default": "GET"},
                "path": {
                    "type": "string",
                    "description": "Home Assistant API path (required when mode='single', optional when mode='lease')",
                },
                "body": {"type": "object", "description": "Optional JSON request body for POST/DELETE calls"},
                "reason": {"type": "string", "description": "Reason for Home Assistant API access"},
            },
            "required": ["reason"],
        },
    },
    {
        "name": "oob_ha_api_call",
        "description": (
            "Execute a subsequent filtered Home Assistant REST API call against an active `oob_ha_api` lease "
            "(`mode='lease'`) without sending another mobile approval prompt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Active `oob_ha_api` lease request_id"},
                "caller_nonce": {"type": "string", "description": "Caller nonce returned when the lease was granted"},
                "method": {"type": "string", "enum": ["GET", "POST", "DELETE"], "default": "GET"},
                "path": {"type": "string", "description": "Home Assistant API path (e.g. '/api/states')"},
                "body": {"type": "object", "description": "Optional JSON request body for POST/DELETE calls"},
            },
            "required": ["request_id", "caller_nonce", "path"],
        },
    },
    {
        "name": "oob_secret_checkout",
        "description": "Request one-time checkout of a named secret from the root vault (`/etc/ha-sudo/vault.json`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Secret key name in vault"},
                "reason": {"type": "string", "description": "Reason for checking out this secret"},
            },
            "required": ["key", "reason"],
        },
    },
    {
        "name": "oob_confirm",
        "description": "Request a generic Yes/No human-in-the-loop mobile approval receipt before a high-impact action.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Action summary displayed on the phone"},
                "reason": {"type": "string", "description": "Why this action is needed"},
            },
            "required": ["summary", "reason"],
        },
    },
    {
        "name": "oob_revoke",
        "description": "Immediately revoke an active lease by `request_id` and `caller_nonce`.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Active lease request_id"},
                "caller_nonce": {"type": "string", "description": "Caller nonce returned when the lease was granted"},
            },
            "required": ["request_id", "caller_nonce"],
        },
    },
]


def dispatch_mcp_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    config: Dict[str, Any],
    socket_requester: Optional[Callable[[str, Dict[str, Any], float], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Dispatch an MCP `tools/call` invocation over the local `ha-oob-gate` Unix socket."""
    if socket_requester is None:
        from .cli import send_unix_socket_request

        socket_requester = send_unix_socket_request

    sock_path = config.get("socket_path", "/run/ha-sudo/daemon.sock")
    timeout = float(config.get("timeout_seconds", 900)) + 30.0

    if tool_name == "oob_revoke":
        resp = socket_requester(
            sock_path,
            {
                "action": "revoke",
                "request_id": str(arguments.get("request_id", "")),
                "caller_nonce": str(arguments.get("caller_nonce", "")),
            },
            15.0,
        )
        is_err = resp.get("status") not in ("revoked", "ok")
        return {
            "content": [{"type": "text", "text": json.dumps(resp, indent=2)}],
            "isError": is_err,
        }

    if tool_name == "oob_ha_api_call":
        path = str(arguments.get("path", "")).strip()
        if not path:
            return {
                "content": [{"type": "text", "text": "Parameter 'path' is required for oob_ha_api_call"}],
                "isError": True,
            }
        resp = socket_requester(
            sock_path,
            {
                "action": "ha_proxy_call",
                "request_id": str(arguments.get("request_id", "")),
                "caller_nonce": str(arguments.get("caller_nonce", "")),
                "method": str(arguments.get("method", "GET")),
                "path": path,
                "body": arguments.get("body"),
            },
            30.0,
        )
        is_err = resp.get("status") != "ok"
        return {
            "content": [{"type": "text", "text": json.dumps(resp, indent=2)}],
            "isError": is_err,
        }

    if tool_name == "oob_ha_api":
        mode = str(arguments.get("mode", "single")).lower()
        path = str(arguments.get("path", "")).strip()
        if mode == "single" and not path:
            return {
                "content": [{"type": "text", "text": "Parameter 'path' is required when mode='single'"}],
                "isError": True,
            }

    module_map = {
        "oob_sudo_batch": (
            "sudo_batch",
            {
                "script_content": arguments.get("script", ""),
                "reason": arguments.get("reason", ""),
                "cwd": arguments.get("cwd") or os.getcwd(),
            },
        ),
        "oob_k8s_token": (
            "k8s_token",
            {
                "role": arguments.get("role", "jit-workload-operator"),
                "namespaces": arguments.get("namespaces", ["default"]),
                "reason": arguments.get("reason", ""),
            },
        ),
        "oob_github_token": (
            "github_token",
            {
                "repo": arguments.get("repo", ""),
                "permission": arguments.get("permission", "write"),
                "reason": arguments.get("reason", ""),
            },
        ),
        "oob_ha_api": (
            "ha_api",
            {
                "mode": arguments.get("mode", "single"),
                "scope": arguments.get("scope", "read"),
                "domains": arguments.get("domains", []),
                "method": arguments.get("method", "GET"),
                "path": arguments.get("path", ""),
                "body": arguments.get("body"),
                "reason": arguments.get("reason", ""),
            },
        ),
        "oob_secret_checkout": (
            "secret_checkout",
            {
                "key": arguments.get("key", ""),
                "reason": arguments.get("reason", ""),
            },
        ),
        "oob_confirm": (
            "generic_confirm",
            {
                "summary": arguments.get("summary", ""),
                "reason": arguments.get("reason", ""),
            },
        ),
    }

    if tool_name not in module_map:
        return {
            "content": [{"type": "text", "text": f"Unknown tool '{tool_name}'"}],
            "isError": True,
        }

    mod_name, params = module_map[tool_name]
    resp = socket_requester(
        sock_path,
        {
            "action": "module_request",
            "module": mod_name,
            "params": params,
        },
        timeout,
    )
    is_err = resp.get("status") != "approved"
    return {
        "content": [{"type": "text", "text": json.dumps(resp, indent=2)}],
        "isError": is_err,
    }


def handle_mcp_jsonrpc_message(
    msg: Dict[str, Any],
    config: Dict[str, Any],
    socket_requester: Optional[Callable[[str, Dict[str, Any], float], Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC 2.0 MCP message and return the response dict (or None for notifications)."""
    method = msg.get("method", "")
    msg_id = msg.get("id")

    if msg_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ha-oob-gate", "version": __version__},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": MCP_TOOLS},
        }

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        try:
            call_res = dispatch_mcp_tool_call(tool_name, arguments, config, socket_requester=socket_requester)
            return {"jsonrpc": "2.0", "id": msg_id, "result": call_res}
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error communicating with ha-oob-gate daemon: {e}"}],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


handle_mcp_request = handle_mcp_jsonrpc_message


def run_mcp_stdio_server(config: Optional[Dict[str, Any]] = None) -> None:
    """Run the line-delimited JSON-RPC 2.0 MCP stdio server."""
    cfg = config or load_config()
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_mcp_jsonrpc_message(msg, cfg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
