"""
ha_api.py - Filtered Root Proxy & Scoped Lease Module for Home Assistant REST API.

Security Architecture:
1. Zero Raw Token Exposure:
   The Home Assistant Long-Lived Access Token resides exclusively in root-only storage
   (`/etc/ha-sudo/secrets/ha_admin_token` or `/etc/ha-sudo/vault.json` mode `0600 root:root`).
   Unprivileged callers never receive the raw bearer token.
2. Dual Execution Modes:
   - `lease` (default 15m TTL): Mints an opaque proxy lease (`request_id` + `caller_nonce`)
     scoped to `read` or `admin` (and required `domains` allowlist). Subsequent calls via
     `oob-auth ha-api` or `oob_ha_api_call` are proxied through `handle_lease_rpc()` and
     revocable via `oob-auth revoke` / `oob_revoke`.
   - `single`: Displays the exact HTTP method, path, and JSON body on the mobile phone
     (capped at 500 chars to prevent truncation) and executes that single call upon approval.
3. Structured Anti-Self-Approval & Escalation Enforcement:
   Instead of brittle substring scanning over free-form JSON text, `validate_ha_proxy_call()`
   enforces canonical URL path rules, service-domain allowlists, and recursive structured
   inspection of `entity_id` / `entity_ids`, `event_type`, and `action` fields.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..sanitize import sanitize_text
from . import BaseGateModule, CallerInfo, NotificationSpec

DEFAULT_HA_TOKEN_SECRET_PATH = "/etc/ha-sudo/secrets/ha_admin_token"
MAX_SINGLE_BODY_LEN = 500
MAX_PROXY_BODY_LEN = 8192
MAX_PROXY_RESPONSE_BYTES = 524288  # 512 KiB cap on proxied responses

ALLOWED_METHODS_READ = frozenset({"GET"})
ALLOWED_METHODS_ADMIN = frozenset({"GET", "POST", "DELETE"})
DOMAIN_NAME_REGEX = re.compile(r"^[a-z0-9_]{1,64}$")
ENTITY_ID_REGEX = re.compile(r"^([a-z0-9_]{1,64})\.[a-z0-9_]+$")

FORBIDDEN_SERVICE_DOMAINS: Set[str] = {
    "rest_command",
    "notify",
    "shell_command",
    "python_script",
    "hassio",
    "supervisor",
    "automation",
    "script",
    "mqtt",
    "persistent_notification",
    "system_log",
}

FORBIDDEN_PATH_PREFIXES = (
    "/api/webhook",
    "/api/HandleWebhook",
    "/api/websocket",
    "/api/template",
    "/api/intent",
    "/api/conversation",
    "/api/services/rest_command",
    "/api/services/notify",
    "/api/services/shell_command",
    "/api/services/python_script",
    "/api/services/hassio",
    "/api/services/supervisor",
    "/api/services/automation",
    "/api/services/script",
    "/api/services/mqtt",
    "/api/services/persistent_notification",
    "/api/services/system_log",
    "/api/config/automation",
    "/api/config/script",
    "/api/config/rest_command",
    "/api/config/shell_command",
    "/api/config/config_entries",
    "/api/config/core",
    "/api/hassio",
    "/api/supervisor",
    "/api/auth",
    "/api/config/auth",
    "/api/onboarding",
    "/api/services/homeassistant/stop",
    "/api/services/homeassistant/turn_off",
    "/api/services/homeassistant/turn_on",
    "/api/services/homeassistant/toggle",
    "/api/services/homeassistant/restart",
    "/api/services/homeassistant/check_config",
    "/api/services/homeassistant/reload_all",
    "/api/services/homeassistant/reload_core_config",
)

FORBIDDEN_EVENT_TYPES = frozenset(
    {
        "mobile_app_notification_action",
        "mobile_app_notification_cleared",
        "oob_request_cancelled",
        "call_service",
        "state_changed",
    }
)

FORBIDDEN_ACTION_PREFIXES = (
    "approve_oob",
    "deny_oob",
)

READ_ALLOWED_EXACT_PATHS = frozenset(
    {
        "/api",
        "/api/",
        "/api/config",
        "/api/states",
        "/api/services",
        "/api/events",
        "/api/error_log",
        "/api/calendars",
    }
)

READ_ALLOWED_PREFIXES = (
    "/api/states/",
    "/api/history/period",
    "/api/logbook",
    "/api/calendars/",
)


def _canonicalize_and_validate_path(raw_path: str) -> Tuple[bool, str, str, str]:
    """
    Validate and canonicalize `raw_path`, rejecting multi-level URL encoding, fragments,
    path traversal (`..` / `.`), backslashes, and duplicate slashes.
    Returns `(ok, canonical_path_with_query, decoded_path, decoded_query_or_err)`.
    """
    raw_path_s = str(raw_path or "").strip()
    if not raw_path_s:
        return False, "", "", "Missing Home Assistant API path"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw_path_s):
        return False, "", "", "API path contains control characters"

    parsed = urllib.parse.urlsplit(raw_path_s)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False, "", "", "API path must be a relative path starting with /api without scheme, host, or fragment"

    decoded_path = urllib.parse.unquote(parsed.path)
    if urllib.parse.unquote(decoded_path) != decoded_path or "%" in decoded_path:
        return False, "", "", "Nested or residual percent-encoding rejected in API path"

    decoded_query = urllib.parse.unquote(parsed.query)
    if urllib.parse.unquote(decoded_query) != decoded_query:
        return False, "", "", "Nested percent-encoding rejected in API query string"

    if (
        "\\" in decoded_path
        or ".." in decoded_path
        or "//" in decoded_path
        or "/./" in decoded_path
        or decoded_path.endswith("/.")
    ):
        return False, "", "", "Path traversal or ambiguous slashes rejected in API path"

    norm_posix = posixpath.normpath(decoded_path)
    expected_no_slash = decoded_path.rstrip("/") if decoded_path != "/" else "/"
    if norm_posix != expected_no_slash:
        return False, "", "", "Non-canonical API path rejected"

    canonical_full = f"{decoded_path}?{parsed.query}" if parsed.query else decoded_path
    return True, canonical_full, decoded_path, decoded_query


def _parse_and_normalize_json_body(body: Any) -> Tuple[bool, Any, Optional[str], str]:
    """
    Parse and re-serialize JSON body so Unicode escapes (e.g. `\\u0041PPROVE_OOB`) are
    fully decoded into native Python strings before structured field inspection.
    Returns `(ok, parsed_obj, canonical_json_str_or_None, error_msg)`.
    """
    if body is None or body == "":
        return True, None, None, "ok"
    if isinstance(body, (dict, list)):
        # Round-trip via JSON to guarantee pure JSON types and normalized strings
        canonical = json.dumps(body, ensure_ascii=False)
        parsed = json.loads(canonical)
    elif isinstance(body, str):
        try:
            parsed = json.loads(body)
        except Exception as e:
            return False, None, None, f"Request body must be valid JSON: {e}"
        if not isinstance(parsed, (dict, list)):
            return False, None, None, "Request JSON body must be a JSON object or array"
        canonical = json.dumps(parsed, ensure_ascii=False)
    else:
        return False, None, None, "Request body must be a JSON object, array, or string"

    if len(canonical.encode("utf-8")) > MAX_PROXY_BODY_LEN:
        return False, None, None, f"Request body exceeds maximum size ({MAX_PROXY_BODY_LEN} bytes)"
    return True, parsed, canonical, "ok"


def _inspect_entity_value(
    raw_entity: Any,
    allowed_domains_set: Optional[Set[str]],
) -> Tuple[bool, str]:
    """Validate an `entity_id` / `entity_ids` value (string or list of strings) against domain policies."""
    if isinstance(raw_entity, list):
        for item in raw_entity:
            ok, err = _inspect_entity_value(item, allowed_domains_set)
            if not ok:
                return False, err
        return True, "ok"

    if not isinstance(raw_entity, str):
        return False, "entity_id must be a string or list of strings"

    for token in (part.strip().lower() for part in raw_entity.split(",") if part.strip()):
        if token in ("all", "*"):
            return False, "Wildcard entity_id ('all' / '*') is forbidden"
        m = ENTITY_ID_REGEX.match(token)
        if not m:
            return False, f"Malformed entity_id '{token}' (expected '<domain>.<object_id>')"
        ent_domain = m.group(1)
        if ent_domain in FORBIDDEN_SERVICE_DOMAINS:
            return False, f"Security policy: targeting protected entity domain '{ent_domain}' is forbidden"
        if allowed_domains_set is not None and ent_domain not in allowed_domains_set:
            return (
                False,
                f"Entity '{token}' domain '{ent_domain}' is outside allowed_domains ({sorted(allowed_domains_set)})",
            )
    return True, "ok"


def _inspect_structured_payload(
    obj: Any,
    allowed_domains_set: Optional[Set[str]],
) -> Tuple[bool, str]:
    """
    Recursively inspect structured JSON keys (`entity_id`, `entity_ids`, `event_type`, `action`)
    without false-positiving on free-form string values like friendly names or descriptions.
    """
    if isinstance(obj, list):
        for item in obj:
            ok, err = _inspect_structured_payload(item, allowed_domains_set)
            if not ok:
                return False, err
        return True, "ok"

    if isinstance(obj, dict):
        for raw_k, val in obj.items():
            key = str(raw_k).strip().lower()
            if key in ("entity_id", "entity_ids"):
                ok, err = _inspect_entity_value(val, allowed_domains_set)
                if not ok:
                    return False, err
            elif key == "event_type" and isinstance(val, str):
                ev_low = val.strip().lower()
                if ev_low in FORBIDDEN_EVENT_TYPES or ev_low.startswith("oob_"):
                    return False, f"Security policy: event_type '{val}' is forbidden"
            elif key == "action" and isinstance(val, str):
                act_low = val.strip().lower()
                if act_low.startswith(FORBIDDEN_ACTION_PREFIXES):
                    return False, f"Security policy: OOB approval action '{val}' is forbidden"
                # Block embedded service-call actions targeting forbidden domains (e.g. `"notify.mobile_app"`)
                if "." in act_low:
                    act_domain = act_low.split(".", 1)[0]
                    if act_domain in FORBIDDEN_SERVICE_DOMAINS:
                        return False, f"Security policy: service action domain '{act_domain}' is forbidden"
                    if allowed_domains_set is not None and act_domain not in allowed_domains_set:
                        return False, f"Action domain '{act_domain}' is outside allowed_domains"

            ok_child, err_child = _inspect_structured_payload(val, allowed_domains_set)
            if not ok_child:
                return False, err_child

    return True, "ok"


def validate_ha_proxy_call(
    method: str,
    raw_path: str,
    body: Any = None,
    scope: str = "read",
    allowed_domains: Optional[Sequence[str]] = None,
) -> Tuple[bool, str]:
    """
    Validate an incoming Home Assistant REST API request against scope (`read` vs `admin`),
    optional service domain restrictions, and structured OOB anti-self-approval rules.
    """
    method_u = str(method or "GET").upper().strip()
    scope_l = str(scope or "read").lower().strip()
    if scope_l not in ("read", "admin"):
        return False, f"Invalid HA scope '{scope_l}' (must be 'read' or 'admin')"

    allowed_methods = ALLOWED_METHODS_READ if scope_l == "read" else ALLOWED_METHODS_ADMIN
    if method_u not in allowed_methods:
        return False, f"HTTP method '{method_u}' is not permitted under '{scope_l}' scope"

    path_ok, _, decoded_path, query_or_err = _canonicalize_and_validate_path(raw_path)
    if not path_ok:
        return False, query_or_err

    norm_path = decoded_path.rstrip("/") if decoded_path != "/api/" else "/api"
    norm_lower = norm_path.lower()

    if norm_lower != "/api" and not norm_lower.startswith("/api/"):
        return False, "Home Assistant API path must start with /api"

    # 1. Hard endpoint denylist: block webhooks, event firing, templates, intents, supervisor, auth, and protected services
    for prefix in FORBIDDEN_PATH_PREFIXES:
        p_low = prefix.lower()
        if norm_lower == p_low or norm_lower.startswith(p_low + "/"):
            return False, f"Security policy: Home Assistant endpoint '{prefix}' is permanently blocked"

    if norm_lower == "/api/events" or norm_lower.startswith("/api/events/"):
        if method_u != "GET" or norm_lower != "/api/events":
            return False, "Security policy: firing or modifying Home Assistant event bus events (/api/events/*) is blocked"

    if norm_lower == "/api/states" or norm_lower.startswith("/api/states/"):
        if method_u != "GET":
            return (
                False,
                "Security policy: direct state-bus mutation (POST/DELETE on /api/states/*) is blocked; use /api/services/<domain>/<service>",
            )
        # Under read/admin GET `/api/states/<entity_id>`, validate entity syntax if specified
        if norm_lower.startswith("/api/states/"):
            state_entity = norm_lower[len("/api/states/") :]
            if "/" in state_entity or not ENTITY_ID_REGEX.match(state_entity):
                return False, f"Invalid entity_id in /api/states path: '{state_entity}'"

    # 2. Structured `/api/services/<domain>/<service>` validation
    allowed_set: Optional[Set[str]] = None
    if allowed_domains is not None:
        cleaned = {str(d).lower().strip() for d in allowed_domains if str(d).strip()}
        if cleaned:
            allowed_set = cleaned

    if norm_lower.startswith("/api/services/"):
        svc_parts = [p for p in norm_lower.split("/") if p]
        if len(svc_parts) != 4:
            return False, "Service endpoint must match /api/services/<domain>/<service>"
        svc_domain, svc_name = svc_parts[2], svc_parts[3]
        if not DOMAIN_NAME_REGEX.match(svc_domain) or not DOMAIN_NAME_REGEX.match(svc_name):
            return False, f"Invalid service domain or name in '{decoded_path}'"
        if svc_domain in FORBIDDEN_SERVICE_DOMAINS:
            return False, f"Security policy: service domain '{svc_domain}' is permanently blocked"

    # 3. Parse JSON body and run structured entity/event/action validation
    body_ok, parsed_body, canonical_body, body_err = _parse_and_normalize_json_body(body)
    if not body_ok:
        return False, body_err
    if method_u == "GET" and canonical_body is not None:
        return False, "GET requests may not include a request body"

    if parsed_body is not None:
        struct_ok, struct_err = _inspect_structured_payload(parsed_body, allowed_set)
        if not struct_ok:
            return False, struct_err

    # 4. Scope-specific endpoint rules
    is_read_endpoint = decoded_path in READ_ALLOWED_EXACT_PATHS or any(
        decoded_path.startswith(p) for p in READ_ALLOWED_PREFIXES
    )
    if scope_l == "read":
        if not is_read_endpoint:
            return False, f"Endpoint '{decoded_path}' is not permitted under 'read' scope"
    else:
        if allowed_set is not None:
            if method_u == "GET" and is_read_endpoint:
                return True, "ok"
            if not norm_lower.startswith("/api/services/"):
                return (
                    False,
                    f"Domain-scoped admin lease ({sorted(allowed_set)}) only permits /api/services/<domain>/<service> mutations and read-only GETs",
                )
            svc_parts = [p for p in norm_lower.split("/") if p]
            if len(svc_parts) != 4 or svc_parts[2] not in allowed_set:
                return (
                    False,
                    f"Endpoint '{decoded_path}' is not in this lease's allowed_domains ({sorted(allowed_set)})",
                )

    return True, "ok"


def _load_ha_admin_token(config: Dict[str, Any]) -> str:
    secret_path = config.get("ha_admin_token_path", DEFAULT_HA_TOKEN_SECRET_PATH)
    if os.path.isfile(secret_path):
        try:
            with open(secret_path, "r", encoding="utf-8") as f:
                tok = f.read().strip()
                if tok:
                    return tok
        except Exception:
            pass

    if config.get("ha_admin_token"):
        return str(config["ha_admin_token"]).strip()

    vault_path = config.get("vault_path", "/etc/ha-sudo/vault.json")
    if os.path.isfile(vault_path):
        try:
            with open(vault_path, "r", encoding="utf-8") as f:
                vdata = json.load(f)
                if vdata.get("ha_admin_token"):
                    return str(vdata["ha_admin_token"]).strip()
        except Exception:
            pass

    raise RuntimeError(
        f"Home Assistant token not found at {secret_path} (or key 'ha_admin_token' in vault.json). "
        "Store a Home Assistant Long-Lived Access Token in /etc/ha-sudo/secrets/ha_admin_token (0600 root:root)."
    )


def execute_ha_proxy_call(
    method: str,
    raw_path: str,
    body: Any,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute a pre-validated HTTP call against Home Assistant using the canonicalized path and JSON body."""
    ha_url = str(config.get("ha_url", "")).rstrip("/")
    if not ha_url:
        raise RuntimeError("Missing ha_url in /etc/ha-sudo/config.json")

    path_ok, canonical_path, _, path_err = _canonicalize_and_validate_path(raw_path)
    if not path_ok:
        raise ValueError(path_err)

    body_ok, _, canonical_body, body_err = _parse_and_normalize_json_body(body)
    if not body_ok:
        raise ValueError(body_err)

    token = _load_ha_admin_token(config)
    method_u = method.upper().strip()
    url = f"{ha_url}{canonical_path}"

    req_bytes: Optional[bytes] = None
    if canonical_body is not None and method_u in ("POST", "DELETE"):
        req_bytes = canonical_body.encode("utf-8")

    req = urllib.request.Request(url, data=req_bytes, method=method_u)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_resp = resp.read(MAX_PROXY_RESPONSE_BYTES + 1)
            truncated = len(raw_resp) > MAX_PROXY_RESPONSE_BYTES
            text_resp = raw_resp[:MAX_PROXY_RESPONSE_BYTES].decode("utf-8", errors="replace")
            try:
                parsed_resp = json.loads(text_resp) if text_resp and not truncated else text_resp
            except Exception:
                parsed_resp = text_resp
            return {
                "status": "ok",
                "http_status": resp.status,
                "truncated": truncated,
                "data": parsed_resp,
            }
    except urllib.error.HTTPError as e:
        err_text = e.read(8192).decode("utf-8", errors="replace")
        return {
            "status": "http_error",
            "http_status": e.code,
            "message": f"Home Assistant HTTP {e.code}",
            "data": err_text,
        }


class HaApiModule(BaseGateModule):
    name = "ha_api"
    description = "Filtered root proxy & short-lived lease for Home Assistant REST API"
    default_ttl_seconds = 900
    requires_root_caller = False

    def validate(self, params: Dict[str, Any], caller: CallerInfo, config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = str(params.get("mode", "lease")).lower().strip()
        scope = str(params.get("scope", "read")).lower().strip()
        reason = str(params.get("reason", "")).strip()
        domains = params.get("domains") or []

        if mode not in ("lease", "single"):
            return False, "mode must be 'lease' or 'single'"
        if scope not in ("read", "admin"):
            return False, "scope must be 'read' or 'admin'"
        if not reason:
            return False, "A human-readable --reason is required for Home Assistant API access"
        if len(reason) > 200:
            return False, "reason exceeds maximum displayable length (200 chars)"

        if not isinstance(domains, list) or len(domains) > 20:
            return False, "domains must be a list of up to 20 Home Assistant service domains"
        clean_domains = [str(d).lower().strip() for d in domains if str(d).strip()]
        if scope == "admin" and not clean_domains and not config.get("allow_unscoped_ha_admin", False):
            return (
                False,
                "Security policy: admin scope requires a non-empty 'domains' allowlist (unless allow_unscoped_ha_admin is enabled)",
            )
        for d_str in clean_domains:
            if not DOMAIN_NAME_REGEX.match(d_str):
                return False, f"Invalid Home Assistant domain name '{d_str}'"
            if d_str in FORBIDDEN_SERVICE_DOMAINS:
                return False, f"Security policy: domain '{d_str}' cannot be granted via ha_api"
        params["domains"] = clean_domains

        if mode == "single":
            method = str(params.get("method", "GET")).upper().strip()
            path = str(params.get("path", "")).strip()
            body = params.get("body")
            body_ok, _, canonical_body, body_err = _parse_and_normalize_json_body(body)
            if not body_ok:
                return False, body_err
            if canonical_body and len(canonical_body) > MAX_SINGLE_BODY_LEN:
                return (
                    False,
                    f"Single-call body exceeds maximum displayable length ({MAX_SINGLE_BODY_LEN} chars) to prevent notification truncation",
                )
            ok, err = validate_ha_proxy_call(method, path, body, scope=scope, allowed_domains=clean_domains)
            if not ok:
                return False, err

        return True, "ok"

    def handle_lease_rpc(
        self,
        action: str,
        payload: Dict[str, Any],
        lease: Dict[str, Any],
        caller: Optional[CallerInfo],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        if action != "ha_proxy_call":
            return {"status": "error", "code": 400, "message": f"Unsupported ha_api lease action '{action}'"}

        meta = lease.get("grant_metadata", {})
        if meta.get("mode") != "lease":
            return {"status": "error", "code": 403, "message": "Single-use ha_api grant cannot be reused as a lease"}

        scope = str(meta.get("scope", "read"))
        domains = list(meta.get("domains") or [])
        method = str(payload.get("method", "GET"))
        path = str(payload.get("path", ""))
        body = payload.get("body")

        ok, err = validate_ha_proxy_call(method, path, body, scope=scope, allowed_domains=domains)
        if not ok:
            return {"status": "error", "code": 403, "message": err}

        try:
            return execute_ha_proxy_call(method, path, body, config)
        except Exception as e:
            return {"status": "error", "code": 502, "message": str(e)}

    def format_notification(
        self,
        params: Dict[str, Any],
        caller: CallerInfo,
        verify_code: str,
        hostname: str,
        config: Dict[str, Any],
    ) -> NotificationSpec:
        mode = str(params.get("mode", "lease")).lower().strip()
        scope = str(params.get("scope", "read")).lower().strip()
        reason = sanitize_text(params.get("reason", ""), max_len=200)
        domains = params.get("domains") or []
        domains_str = ", ".join(sanitize_text(d, max_len=32) for d in domains) if domains else "ALL (except OOB denylist)"
        caller_disp = caller.k8s_identity or f"{caller.username} (UID {caller.uid})"

        is_admin = scope == "admin"
        badge = "🚨 ELEVATED (HA ADMIN WRITE)" if is_admin else "🔍 READ-ONLY"
        max_ttl = int(config.get("ha_api_ttl_seconds", self.default_ttl_seconds))
        eff_ttl = max(60, min(int(params.get("ttl_seconds") or max_ttl), max_ttl))
        ttl_min = max(1, eff_ttl // 60)

        if mode == "single":
            method = sanitize_text(str(params.get("method", "GET")).upper(), max_len=10)
            path = sanitize_text(str(params.get("path", "")), max_len=200)
            _, _, canonical_body, _ = _parse_and_normalize_json_body(params.get("body"))
            body_preview = sanitize_text(canonical_body or "{}", max_len=MAX_SINGLE_BODY_LEN)
            title = f"🏠 HA API Call ({scope.upper()}) [{verify_code}]"
            message = (
                f"{badge}\n"
                f"Host: {hostname}\n"
                f"Caller: {caller_disp}\n"
                f"Reason: {reason}\n\n"
                f"Request: {method} {path}\n"
                f"Payload: {body_preview}"
            )
            summary = f"HA {method} {path}: {reason}"
            approve_btn = f"Execute Call [{verify_code}]"
        else:
            title = f"🏠 HA API Lease ({scope.upper()}) [{verify_code}]"
            message = (
                f"{badge}\n"
                f"Host: {hostname}\n"
                f"Caller: {caller_disp}\n"
                f"Scope: {scope.upper()}\n"
                f"Allowed Domains: {domains_str}\n"
                f"Lease TTL: {ttl_min} minutes\n\n"
                f"Reason:\n{reason}"
            )
            summary = f"HA {scope} lease ({ttl_min}m): {reason}"
            approve_btn = f"Grant {ttl_min}m [{verify_code}]"

        return NotificationSpec(
            title=title,
            message=message,
            approve_title=approve_btn,
            deny_title="Deny",
            approved_title=f"✅ HA API Approved [{verify_code}]",
            approved_message=f"Granted {summary}",
            denied_title=f"❌ HA API Denied [{verify_code}]",
            denied_message=f"Rejected HA API ({scope}) for {caller_disp}",
            timeout_title=f"⏱️ HA API Timed Out [{verify_code}]",
            timeout_message=f"Expired without response for {caller_disp}",
            command_summary=summary,
            color="red" if is_admin else "blue",
        )

    def grant(
        self,
        req_id: str,
        params: Dict[str, Any],
        caller: CallerInfo,
        ttl_seconds: int,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        mode = str(params.get("mode", "lease")).lower().strip()
        scope = str(params.get("scope", "read")).lower().strip()
        clean_domains = [str(d).lower().strip() for d in (params.get("domains") or []) if str(d).strip()]

        # Verify token exists before granting
        _load_ha_admin_token(config)

        if mode == "single":
            method = str(params.get("method", "GET")).upper().strip()
            path = str(params.get("path", "")).strip()
            body = params.get("body")
            ok, err = validate_ha_proxy_call(method, path, body, scope=scope, allowed_domains=clean_domains)
            if not ok:
                raise PermissionError(err)
            res = execute_ha_proxy_call(method, path, body, config)
            return {
                "status": "approved",
                "mode": "single",
                "scope": scope,
                "proxy_response": res,
            }

        max_ttl = int(config.get("ha_api_ttl_seconds", self.default_ttl_seconds))
        effective_ttl = max(60, min(int(ttl_seconds or max_ttl), max_ttl))
        return {
            "status": "approved",
            "mode": "lease",
            "scope": scope,
            "domains": clean_domains,
            "ttl_seconds": effective_ttl,
        }

    def revoke(self, req_id: str, grant_metadata: Dict[str, Any], config: Dict[str, Any]) -> bool:
        return True
