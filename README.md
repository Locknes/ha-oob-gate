# ha-oob-gate — Out-of-Band Authorization & MCP Gateway for Home Assistant

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](pyproject.toml)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(stdlib%20only)-success.svg)](ha_oob_gate)
[![MCP Compatible](https://img.shields.io/badge/MCP-JSON--RPC%202.0%20stdio-purple.svg)](ha_oob_gate/mcp_server.py)

**`ha-oob-gate`** is a zero-dependency Out-of-Band (OOB) authorization gateway (`v5.0.0`, Python 3.10+) that turns **Home Assistant Companion App actionable push notifications** into a cryptographic human-in-the-loop approval boundary for **AI coding agents** (Claude Code, Cursor, Windsurf, Cline, Roo Code, OpenCode, Codex) and **Linux/Kubernetes infrastructure**.

Instead of granting autonomous agents standing `NOPASSWD: ALL` sudo privileges, cluster-admin kubeconfigs, broad GitHub Personal Access Tokens, or raw Home Assistant long-lived tokens, `ha-oob-gate` enforces **Just-Enough-Administration (JEA)** and **Just-In-Time (JIT)** leases with a single tap on your phone or smartwatch.

---

## Architecture & Security Model

```
┌────────────────────────────────────────────────────────────────────────────┐
│ AI Agent / CLI / PAM / SSH Caller (Unprivileged UID)                       │
│   • CLI: `oob-auth sudo-batch | k8s-token | github-token | ha-api | ...`   │
│   • MCP: `oob-auth --mcp-stdio` (Claude Code, Cursor, Windsurf, Cline...)  │
│   • PAM: `sudo <cmd>` -> `pam_unix.so` (1st factor) + `pam_ha_sudo.sh`     │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │ Unix Domain Socket (/run/ha-sudo/daemon.sock)
                                │ Kernel SO_PEERCRED + Newline-Delimited JSON
                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ ha-oob-gate Root Daemon (`ha-sudo-gate.service`)                           │
│   1. Validates command allowlists & snapshots immutable batch script       │
│      to `/run/ha-sudo/staged/<id>.sh` (0500 root:root, SHA-256 pinned)     │
│   2. Generates separate 256-bit `approve_nonce` & `deny_nonce`             │
│   3. Dispatches webhook to Home Assistant & polls client socket for Ctrl+C │
└───────────────┬───────────────────────────────────────────▲────────────────┘
                │ HTTPS Webhook                             │ HTTPS Callback (:8443 TLSv1.2+)
                ▼                                           │ + X-HA-Approval-Token (HMAC)
┌───────────────────────────────────────────┐               │ + Trusted IP Allowlist
│ Home Assistant (`universal_oob_auth`)     │───────────────┘
│   • Pushes actionable notification to     │
│     iOS / Android / Apple Watch / Wear OS │
│   • Verifies `context.user_id` of approver│
└───────────────────────────────────────────┘
```

### Key Security Controls & Honest Trust Boundaries
1. **TLSv1.2+ Callback Server & Dual Origin Verification:** The callback listener (`:8443`) uses `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` with auto-generated `0400` root-owned SAN certificates and requires **both** `client_ip in allowed_ips` **and** a constant-time `hmac.compare_digest` verification of `X-HA-Approval-Token` plus a request-specific 256-bit `approve_nonce`.
2. **Human-Approved Root Batch Execution with Self-Tamper Guardrails (`sudo_batch`):**
   - Agent accounts are blocked from interactive `sudo` (`deny_pam_sudo`) and submit scripts by value. The daemon snapshots the script into `/run/ha-sudo/staged/<id>.sh` (`0500 root:root`) and displays the SHA-256 digest and script body on your phone so the caller cannot mutate the file between request and approval (Zero-TOCTOU).
   - **Important Trust Boundary:** Once approved by the human operator, `sudo_batch` executes as **`root` (`UID 0`)**. It is **not** a containment sandbox against intentionally malicious `root` code approved by the operator. Instead, it enforces mount-namespace and transient `systemd-run` guardrails (`ProtectHome=yes`, `PrivateTmp=yes`, `InaccessiblePaths=/etc/ha-sudo /run/ha-sudo/tickets /dev/shm /run/user`, read-only mounts over `/usr/local/libexec/ha-sudo /etc/pam.d /etc/sudoers /etc/sudoers.d /etc/systemd /etc/ssh /run/ha-sudo/staged`, PID namespace isolation, and dropped capabilities) to prevent accidental self-tampering with the gate or execution of unpinned code from user-writable directories (`/home`, `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`).
3. **Opt-In 2FA PAM Stack & Physical Console Break-Glass:** Host PAM modification is strictly opt-in (`sudo ./install.sh --enable-pam-sudo`). When enabled, human `sudo` sessions retain the system's password prompt (`pam_unix.so` / `@include common-auth`) as a first factor followed by `pam_ha_sudo.sh` as an OOB second factor. If the daemon or Home Assistant is unreachable (`exit 75`), members of the root-managed `ha-breakglass` group on a physical or serial console (`tty[1-6]`, `ttyS[0-3]`) can still authenticate for emergency recovery.
4. **Structural Command Allowlists (`ssh_gate` & `pam_sudo`):** Command-pinned `pam_sudo` and OpenSSH `ForceCommand` (`--ssh-enforce`) resolve canonical root-owned binaries inside safe system directories (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`) against configurable command-prefix allowlists and reject shells, versioned interpreters (`python3.12`, `perl5.38`, `ruby3.2`, `node20`), pagers, and editors. `ssh_gate` tracks session/process groups across `/proc` so orphaned child processes are reliably terminated on lease revocation or expiry.
5. **Filtered Home Assistant REST Proxy (`ha_api`):** Agents never receive the raw Home Assistant admin token. Mutations on `/api/states/*` and indirect escalation services (`homeassistant/turn_on`, `script`, `automation`, `shell_command`, `rest_command`, `mqtt`, etc.) are blocked, structured JSON payloads (`entity_id`, `event_type`, `action`) are inspected against OOB automation entities, and `scope="admin"` enforces the approved `--domains` allowlist on every call.
6. **Kubernetes JIT Leases & Parameterized `ValidatingAdmissionPolicy`:** Mints 30-minute `TokenRequest` JWTs bound to scoped `RoleBinding`s with atomic rollback on error, paired with a parameterized Kubernetes `ValidatingAdmissionPolicy` (`ConfigMap/jit-guardrails-config`) blocking `privileged`, `hostPID`, `hostNetwork`, `hostIPC`, `hostPort`, `ephemeralContainers`, RBAC mutations, and unapproved `hostPath` mounts.
7. **Structured JSONL Security Audit Log (`audit.py`):** Every request submission, auto-approval, callback decision, and revocation is recorded to `/var/log/ha-oob-gate/audit.jsonl` with recursive redaction (`"[REDACTED]"`) of sensitive keys, tokens, secrets, passwords, and nonces.

---

## Built-in Gate Modules

| Module | CLI Subcommand | MCP Tool(s) | Description |
| :--- | :--- | :--- | :--- |
| `sudo_batch` | `oob-auth sudo-batch` | `oob_sudo_batch` | Human-approved `root` execution of a SHA-256-pinned bash snapshot with mount-namespace & `systemd-run` self-tamper guardrails |
| `pam_sudo` | *(invoked by `/etc/pam.d/sudo`)* | — | Single-use HMAC-signed command-pinned tickets (`timestamp_timeout=0`) with `/proc/<pid>/cmdline` verification & allowlist enforcement |
| `ssh_gate` | `oob-auth --ssh-enforce` | — | OpenSSH `ForceCommand` wrapper with canonical binary allowlists, `RuntimeMaxSec`, and `/proc`-verified group/session termination |
| `k8s_token` | `oob-auth k8s-token` | `oob_k8s_token` | Mints 30-minute namespace-scoped Kubernetes `TokenRequest` JWTs (`view`, `jit-workload-operator`, `jit-storage-operator`) |
| `github_token` | `oob-auth github-token` | `oob_github_token` | Mints 1-hour single-repo GitHub App installation tokens evaluated via live repository topics (`oob-read`/`oob-write`/`oob-oob`/`oob-deny`) |
| `ha_api` | `oob-auth ha-api` | `oob_ha_api`, `oob_ha_api_call` | Filtered Home Assistant REST API proxy (single-shot or 15m lease) with zero raw token exposure |
| `secret_checkout` | `oob-auth secret-checkout` | `oob_secret_checkout` | One-time secret checkout from `/etc/ha-sudo/vault.json` or Kubernetes Secrets into `0600` user-private runtime storage |
| `generic_confirm` | `oob-auth confirm` | `oob_confirm` | Signed mobile approval receipt (`HMAC-SHA256`) before high-impact actions |
| *(lease revoke)* | `oob-auth revoke` | `oob_revoke` | Immediately revokes an active lease by `request_id` and `caller_nonce` |

---

## Quick Start

### 1. Install on a Linux Host
```bash
git clone https://github.com/Locknes/ha-oob-gate.git
cd ha-oob-gate
sudo ./install.sh
```
By default, `install.sh` installs the daemon, CLI (`/usr/local/bin/oob-auth`), `0600` config (`/etc/ha-sudo/config.json`), 256-bit `ha_approval_token`, `0400` SAN TLS certificate (`/etc/ha-sudo/tls.crt`), `ha-breakglass` group, and `ha-sudo-gate.service` **without** modifying `/etc/pam.d/sudo` or `/etc/sudoers.d/`.

Once you have configured `/etc/ha-sudo/config.json` and verified connectivity with `oob-auth --test`, you can optionally enable interactive `sudo` 2FA:
```bash
sudo usermod -aG ha-breakglass <your-admin-user>
sudo ./install.sh --enable-pam-sudo
```

### 2. Import the Home Assistant Blueprint
1. Copy [`homeassistant/universal_oob_auth_blueprint.yaml`](homeassistant/universal_oob_auth_blueprint.yaml) into your Home Assistant `config/blueprints/automation/custom/` directory.
2. Add the `rest_command.oob_gate_callback` snippet from the blueprint header into your Home Assistant `configuration.yaml` and set `ha_oob_approval_token` in `secrets.yaml` to match `ha_approval_token` in `/etc/ha-sudo/config.json`.
3. Create an automation from **Universal Out-of-Band (OOB) Privileged Auth & Sudo Gate**, select your mobile notify service, and set your Home Assistant User ID in `allowed_approver_user_id`.

### 3. Connect Any AI Agent via MCP (`--mcp-stdio`)
Add `ha-oob-gate` to your agent's MCP configuration (`~/.claude.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, etc.):

```json
{
  "mcpServers": {
    "ha-oob-gate": {
      "command": "oob-auth",
      "args": ["--mcp-stdio"]
    }
  }
}
```
Or copy [`skills/oob-auth/SKILL.md`](skills/oob-auth/SKILL.md), [`AGENTS.md`](AGENTS.md), or [`CLAUDE.md`](CLAUDE.md) into your repository so any CLI agent knows how to request elevation automatically.

---

## Running the Test Suite

```bash
python3 -m unittest discover -s tests -v
```

---

## License

Released under the [MIT License](LICENSE).
