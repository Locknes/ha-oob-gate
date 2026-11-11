#!/usr/bin/env bash
# ==============================================================================
# Out-of-Band Kubernetes Broker Bootstrap Script
# ==============================================================================
# Applies the consolidated RBAC & ValidatingAdmissionPolicy manifest
# (`k8s-jit-rbac-and-guardrails.yaml`) and bootstraps the
# `jit-elevation-broker` ServiceAccount token into `ha-oob-gate` (`K8sTokenModule`)
# over `/v1/bootstrap-k8s-token` (verified via Kubernetes TokenReview).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_HOST="${GATE_HOST:-oob-gate.example.com}"
GATE_PORT="${GATE_PORT:-8443}"
TLS_CA_CERT="${TLS_CA_CERT:-/etc/ha-sudo/tls.crt}"
HA_APPROVAL_TOKEN="${HA_APPROVAL_TOKEN:-}"

if [[ -z "${HA_APPROVAL_TOKEN}" && -r "/etc/ha-sudo/config.json" ]]; then
    HA_APPROVAL_TOKEN="$(python3 -c 'import json; print(json.load(open("/etc/ha-sudo/config.json")).get("ha_approval_token", ""))' 2>/dev/null || true)"
fi
if [[ -z "${HA_APPROVAL_TOKEN}" ]]; then
    echo "Error: Set HA_APPROVAL_TOKEN (from /etc/ha-sudo/config.json) before bootstrapping." >&2
    exit 1
fi

echo "=== [1/2] Applying Consolidated K8s JIT RBAC & ValidatingAdmissionPolicy ==="
kubectl apply -f "${SCRIPT_DIR}/k8s-jit-rbac-and-guardrails.yaml"

echo "=== [2/2] Bootstrapping jit-elevation-broker Token into ha-oob-gate over TLS ==="
BROKER_TOKEN="$(kubectl -n jit-system get secret jit-elevation-broker-token -o jsonpath='{.data.token}' | base64 -d)"
curl -fsS --cacert "${TLS_CA_CERT}" \
  -X POST "https://${GATE_HOST}:${GATE_PORT}/v1/bootstrap-k8s-token" \
  -H "Content-Type: application/json" \
  -H "X-HA-Approval-Token: ${HA_APPROVAL_TOKEN}" \
  -d "{\"token\": \"${BROKER_TOKEN}\"}"
echo ""
echo "================================================================================"
echo "Bootstrap complete! K8sTokenModule is now active on ${GATE_HOST}:${GATE_PORT}."
echo "================================================================================"
