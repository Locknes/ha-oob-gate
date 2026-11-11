# Agent Operating Instructions for `ha-oob-gate`

This repository provides **Out-of-Band (OOB) Authorization (`ha-oob-gate`)** for AI coding agents and Linux/Kubernetes infrastructure.

## How Agents Should Request Privileged Elevation

1. **Prefer MCP Tools When Connected (`oob-auth --mcp-stdio`):**
   - `oob_sudo_batch(script, reason, cwd?)` — Execute a SHA-256-pinned bash script snapshot as `root` (`UID 0`) after human mobile approval, with mount-namespace/systemd self-tamper and mutable-path guardrails.
   - `oob_k8s_token(namespaces, reason, role?)` — Acquire a 30-minute namespace-scoped Kubernetes JWT.
   - `oob_github_token(repo, reason, permission?)` — Acquire a 1-hour single-repo GitHub token.
   - `oob_ha_api(reason, mode?, scope?, domains?, method?, path?, body?)` — Request a single filtered Home Assistant REST API proxy call (`mode="single"`) or a 15-minute proxy lease (`mode="lease"`).
   - `oob_ha_api_call(request_id, caller_nonce, path, method?, body?)` — Execute subsequent filtered Home Assistant API calls against an active `oob_ha_api` lease (`mode="lease"`) without re-prompting.
   - `oob_secret_checkout(key, reason)` — Check out a named secret from `/etc/ha-sudo/vault.json`.
   - `oob_confirm(summary, reason)` — Request a signed Yes/No human confirmation receipt.
   - `oob_revoke(request_id, caller_nonce)` — Immediately revoke an active lease when finished.

2. **CLI Fallback (`oob-auth`):**
   - See [`skills/oob-auth/SKILL.md`](skills/oob-auth/SKILL.md) for exact CLI invocations and clean `stdout` / `stderr` contracts.
   - Never run interactive `sudo` from an agent user (`deny_pam_sudo`); always use `oob-auth sudo-batch`.

## Development & Verification

Run the behavioral unit and regression test suite before submitting changes:

```bash
python3 -m unittest discover -s tests -v
```
