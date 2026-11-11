---
name: oob-auth
description: Request Out-of-Band (OOB) privileged elevation via Home Assistant mobile push notifications (`sudo-batch`, `k8s-token`, `github-token`, `ha-api`, `confirm`, `secret-checkout`, `revoke`) or MCP tools (`oob_*`). Activate whenever a task requires root/sudo privileges, Kubernetes write access, GitHub repository tokens, Home Assistant API access, secret checkout, or human approval.
---

# Out-of-Band (OOB) Privileged Elevation (`oob-auth`)

This environment enforces **Out-of-Band (OOB) Authorization** via `ha-oob-gate`.
Interactive `sudo` is blocked for autonomous agent accounts (`deny_pam_sudo`). Use either the **MCP tools** (`oob_sudo_batch`, `oob_k8s_token`, `oob_github_token`, `oob_ha_api`, `oob_ha_api_call`, `oob_secret_checkout`, `oob_confirm`, `oob_revoke`) when registered, or the **`oob-auth` CLI** below.

All `oob-auth` CLI subcommands emit human status banners on `stderr` and clean machine-consumable values on `stdout`.

---

## 1. Human-Approved Root Batch Execution (`oob-auth sudo-batch`)

Never run `sudo <cmd>` directly from an agent account. Bundle required root commands into a single `oob-auth sudo-batch` script so the human operator reviews and approves one SHA-256-pinned snapshot on their phone:

```bash
oob-auth sudo-batch \
  --reason "Restart nginx and verify service status" \
  --script "systemctl restart nginx && systemctl is-active nginx"
```

Security model & constraints:
- Approved scripts execute as **`root` (`UID 0`)** inside a transient `systemd-run` unit and isolated PID/mount namespace (`ProtectHome=yes`, `PrivateTmp=yes`).
- Mutable user directories (`/home`, `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`) are masked or mounted as fresh private `tmpfs` instances inside the batch namespace so scripts cannot execute unpinned files staged by unprivileged users.
- Gate configuration, tickets, PAM, sudoers, systemd, and SSH paths (`/etc/ha-sudo`, `/run/ha-sudo/tickets`, `/usr/local/libexec/ha-sudo`, `/etc/pam.d`, `/etc/sudoers*`, `/etc/systemd`, `/etc/ssh`) are kernel-enforced inaccessible or read-only.
- If a script specify a `#!` shebang, only `#!/bin/bash`, `#!/usr/bin/bash`, or `#!/usr/bin/env bash` is permitted.

---

## 2. Scoped Kubernetes Access (`oob-auth k8s-token`)

Request a 30-minute namespace-scoped Kubernetes JWT (`stdout` emits `export K8S_JIT_TOKEN=...`, or pass `--raw` for the bare JWT):

```bash
eval "$(oob-auth k8s-token \
  --role jit-workload-operator \
  --namespaces default app-workloads \
  --reason "Restart deployment and inspect pod logs")"

kubectl --token="$K8S_JIT_TOKEN" -n default get pods

# Always revoke when finished:
oob-auth revoke
```

Allowed roles: `view`, `jit-workload-operator`, `jit-storage-operator`.

---

## 3. GitHub Repository Token (`oob-auth github-token`)

Request a 1-hour single-repository token evaluated against live repository topics (`oob-read` / `oob-write` / `oob-oob` / `oob-deny`):

```bash
TOKEN="$(oob-auth github-token \
  --repo owner/repo \
  --permission write \
  --reason "Push feature branch and open PR")"
```

---

## 4. Filtered Home Assistant REST Proxy (`oob-auth ha-api`)

Never read raw Home Assistant tokens. Use the filtered proxy (`read` or `admin` with mandatory `--domains`):

```bash
# Request a 15-minute read lease and fetch states:
oob-auth ha-api --lease --scope read --method GET --path /api/states --reason "Inspect sensor states"

# Subsequent calls within the 15-minute lease reuse it automatically without re-prompting:
oob-auth ha-api --method GET --path /api/config

# Request a single scoped admin call (requires explicit --domains):
oob-auth ha-api --single --scope admin --domains light switch \
  --method POST --path /api/services/light/turn_on \
  --data '{"entity_id": "light.office"}' \
  --reason "Turn on office light"
```

When using MCP:
1. Call `oob_ha_api(mode="lease", scope="read", reason="Inspect sensors")` -> returns `{request_id, caller_nonce, ...}`.
2. Call `oob_ha_api_call(request_id=..., caller_nonce=..., method="GET", path="/api/states")` for each call under the lease.
3. Call `oob_revoke(request_id=..., caller_nonce=...)` when finished.

---

## 5. Secret Checkout & Generic Confirmation

```bash
# Checkout a named secret into a 0600 user-private runtime file (stdout prints only the file path):
SECRET_FILE="$(oob-auth secret-checkout --key external_api_key --reason "Run backup job")"

# Request a signed Yes/No mobile confirmation before a high-impact operation (stdout prints receipt HMAC):
RECEIPT="$(oob-auth confirm --summary "Prune unused volumes" --reason "Reclaim disk space")"
```
