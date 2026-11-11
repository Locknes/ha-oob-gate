#!/usr/bin/env bash
# ==============================================================================
# install.sh - Installer for Modular ha-oob-gate Daemon
# Deploys the daemon, PAM helper, TLS SAN certificate, and systemd service onto
# a Linux host. Host PAM / sudoers modification is strictly opt-in via
# `--enable-pam-sudo` so installing the daemon never risks locking out `sudo`.
# ==============================================================================
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

PAM_UNIX_ENTRY="auth       requisite    pam_unix.so"
PAM_ENTRY="auth       requisite    pam_exec.so quiet stdout seteuid /usr/local/libexec/ha-sudo/pam_ha_sudo.sh"

configure_pam_sudo_file() {
    local pam_file="$1"
    [[ -f "${pam_file}" ]] || return 1

    python3 - "${pam_file}" "${PAM_UNIX_ENTRY}" "${PAM_ENTRY}" << 'PYEOF'
import os
import re
import sys

pam_path, pam_unix_entry, pam_entry = sys.argv[1], sys.argv[2], sys.argv[3]
with open(pam_path, "r", encoding="utf-8") as f:
    raw_lines = f.read().splitlines()

# Strip any prior pam_ha_sudo.sh entries for idempotent re-runs
lines = [ln for ln in raw_lines if "pam_ha_sudo.sh" not in ln]

out = []
inserted = False

for ln in lines:
    stripped = ln.strip()
    if not inserted and not stripped.startswith("#"):
        # Case 1: Debian / Ubuntu `@include common-auth` (already prompts via pam_unix inside common-auth)
        if re.match(r"^@include\s+\S+", stripped):
            out.append(ln)
            out.append(pam_entry)
            inserted = True
            continue

        # Case 2: RHEL / Fedora / Arch `auth include <stack>` or `auth substack <stack>`
        m_inc = re.match(r"^auth\s+(include|substack)\s+(\S+)(.*)$", stripped)
        if m_inc:
            stack_name = m_inc.group(2)
            trailing = m_inc.group(3) or ""
            out.append(f"auth       substack     {stack_name}{trailing}")
            out.append(pam_entry)
            inserted = True
            continue

        # Case 3: Explicit `auth ... pam_unix.so` line
        if re.match(r"^auth\s+.*\bpam_unix\.so\b", stripped):
            out.append(pam_unix_entry)
            out.append(pam_entry)
            inserted = True
            continue

    out.append(ln)

if not inserted:
    insert_at = 1 if (out and out[0].startswith("#%PAM")) else 0
    out[insert_at:insert_at] = [pam_unix_entry, pam_entry]

tmp_path = f"{pam_path}.tmp.{os.getpid()}"
st_mode = os.stat(pam_path).st_mode & 0o777
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, st_mode or 0o644)
with os.fdopen(fd, "w", encoding="utf-8") as out_f:
    out_f.write("\n".join(out) + "\n")
os.replace(tmp_path, pam_path)
PYEOF
}

ENABLE_PAM_SUDO=0
CONFIGURE_PAM_FILE_ONLY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --enable-pam-sudo)
            ENABLE_PAM_SUDO=1
            shift
            ;;
        --configure-pam-file)
            CONFIGURE_PAM_FILE_ONLY="${2:-}"
            if [[ -z "${CONFIGURE_PAM_FILE_ONLY}" ]]; then
                echo "Error: --configure-pam-file requires a file path" >&2
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            cat << 'EOF'
Usage: sudo ./install.sh [--enable-pam-sudo]

Options:
  --enable-pam-sudo   Also configure /etc/sudoers.d/ha-oob-gate (timestamp_timeout=0)
                      and /etc/pam.d/sudo to require mobile 2FA on interactive sudo.
                      Omit this flag to install the daemon, CLI, and MCP server
                      without modifying host PAM or sudoers.
EOF
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1' (use --help for usage)" >&2
            exit 1
            ;;
    esac
done

if [[ -n "${CONFIGURE_PAM_FILE_ONLY}" ]]; then
    configure_pam_sudo_file "${CONFIGURE_PAM_FILE_ONLY}"
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: install.sh must be run as root (sudo ./install.sh [--enable-pam-sudo])" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "${SCRIPT_DIR}/ha_oob_gate" ]]; then
    SERVICES_DIR="${SCRIPT_DIR}"
    REPO_ROOT="${SCRIPT_DIR}"
else
    SERVICES_DIR="$(dirname "${SCRIPT_DIR}")"
    REPO_ROOT="$(dirname "${SERVICES_DIR}")"
fi
INSTALL_DIR="/usr/local/libexec/ha-sudo"
CONFIG_DIR="/etc/ha-sudo"
CONFIG_FILE="${CONFIG_DIR}/config.json"

echo "[1/5] Installing ha_oob_gate package to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
chmod 0755 "${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}/ha_oob_gate"
cp -r "${SERVICES_DIR}/ha_oob_gate" "${INSTALL_DIR}/ha_oob_gate"
chown -R root:root "${INSTALL_DIR}/ha_oob_gate"
chmod -R u=rwX,go=rX "${INSTALL_DIR}/ha_oob_gate"
chmod 0755 "${INSTALL_DIR}/ha_oob_gate/cli.py" "${INSTALL_DIR}/ha_oob_gate/daemon.py"
cp "${SERVICES_DIR}/ha_sudo_gate.py" "${INSTALL_DIR}/ha_sudo_gate.py"
chown root:root "${INSTALL_DIR}/ha_sudo_gate.py"
chmod 0755 "${INSTALL_DIR}/ha_sudo_gate.py"

if [[ -f "${REPO_ROOT}/homeassistant/universal_oob_auth_blueprint.yaml" ]]; then
    cp -f "${REPO_ROOT}/homeassistant/universal_oob_auth_blueprint.yaml" "${INSTALL_DIR}/universal_oob_auth_blueprint.yaml"
    chown root:root "${INSTALL_DIR}/universal_oob_auth_blueprint.yaml"
    chmod 0644 "${INSTALL_DIR}/universal_oob_auth_blueprint.yaml"
fi

if [[ -f "${REPO_ROOT}/kubernetes/k8s-jit-rbac-and-guardrails.yaml" ]]; then
    cp -f "${REPO_ROOT}/kubernetes/k8s-jit-rbac-and-guardrails.yaml" "${INSTALL_DIR}/k8s-jit-rbac-and-guardrails.yaml"
    chown root:root "${INSTALL_DIR}/k8s-jit-rbac-and-guardrails.yaml"
    chmod 0644 "${INSTALL_DIR}/k8s-jit-rbac-and-guardrails.yaml"
fi

ln -sf "${INSTALL_DIR}/ha_sudo_gate.py" /usr/local/bin/oob-auth
ln -sf "${INSTALL_DIR}/ha_sudo_gate.py" /usr/local/bin/ha-oob-gate

if [[ -f "${REPO_ROOT}/systemd/pam_ha_sudo.sh" ]]; then
    cp -f "${REPO_ROOT}/systemd/pam_ha_sudo.sh" "${INSTALL_DIR}/pam_ha_sudo.sh"
else
    cp -f "${SERVICES_DIR}/pam_ha_sudo.sh" "${INSTALL_DIR}/pam_ha_sudo.sh"
fi
chown root:root "${INSTALL_DIR}/pam_ha_sudo.sh"
chmod 0755 "${INSTALL_DIR}/pam_ha_sudo.sh"

echo "[2/5] Initializing root-only configuration, TLS SAN certificate & runtime directories (${CONFIG_DIR}, /run/ha-sudo)..."
mkdir -p "${CONFIG_DIR}" /run/ha-sudo/tickets /run/ha-sudo/staged
chmod 0700 "${CONFIG_DIR}" /run/ha-sudo/tickets /run/ha-sudo/staged
chmod 0755 /run/ha-sudo
chown root:root "${CONFIG_DIR}" /run/ha-sudo /run/ha-sudo/tickets /run/ha-sudo/staged

if [[ ! -s "${CONFIG_DIR}/k8s_ca.crt" ]]; then
    K8S_CA_CANDIDATE="${K8S_CA_FILE:-/etc/kubernetes/pki/ca.crt}"
    if [[ -s "${K8S_CA_CANDIDATE}" ]]; then
        cp -f "${K8S_CA_CANDIDATE}" "${CONFIG_DIR}/k8s_ca.crt"
        chown root:root "${CONFIG_DIR}/k8s_ca.crt"
        chmod 0644 "${CONFIG_DIR}/k8s_ca.crt"
        echo "      Copied Kubernetes CA from ${K8S_CA_CANDIDATE} to ${CONFIG_DIR}/k8s_ca.crt"
    else
        echo "      [INFO] Optional Kubernetes CA not present at ${CONFIG_DIR}/k8s_ca.crt (provision if using k8s_token)."
    fi
fi

cat > /etc/tmpfiles.d/ha-sudo.conf << 'EOF'
d /run/ha-sudo 0755 root root -
d /run/ha-sudo/tickets 0700 root root -
d /run/ha-sudo/staged 0700 root root -
EOF

if [[ ! -f "${CONFIG_FILE}" ]]; then
    cp "${SCRIPT_DIR}/config.example.json" "${CONFIG_FILE}"
    chown root:root "${CONFIG_FILE}"
    chmod 0600 "${CONFIG_FILE}"
    echo "      Created ${CONFIG_FILE} from template. Edit ha_url, ha_trusted_ip, and webhook_id!"
else
    chown root:root "${CONFIG_FILE}"
    chmod 0600 "${CONFIG_FILE}"
    echo "      Preserved existing ${CONFIG_FILE} (mode 0600, root:root)."
fi

python3 - "${CONFIG_FILE}" << 'PYEOF'
import json, os, secrets, sys

cfg_path = sys.argv[1]
with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

changed = False
tok = str(cfg.get("ha_approval_token", "") or "").strip()
if not tok or tok.startswith("REPLACE_WITH_"):
    cfg["ha_approval_token"] = secrets.token_hex(32)
    changed = True
    print("      Generated new 256-bit ha_approval_token in config.json (copy to Home Assistant secrets.yaml).")

for k, v in (
    ("tls_enabled", True),
    ("tls_cert_path", "/etc/ha-sudo/tls.crt"),
    ("tls_key_path", "/etc/ha-sudo/tls.key"),
):
    if k not in cfg:
        cfg[k] = v
        changed = True

if changed:
    tmp_path = cfg_path + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(cfg, out, indent=2)
        out.write("\n")
    os.chown(tmp_path, 0, 0)
    os.replace(tmp_path, cfg_path)
PYEOF

TLS_CRT="${CONFIG_DIR}/tls.crt"
TLS_KEY="${CONFIG_DIR}/tls.key"
if [[ ! -s "${TLS_CRT}" || ! -s "${TLS_KEY}" ]]; then
    HOST_CN="$(hostname -f 2>/dev/null || hostname)"
    CB_HOST="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print((c.get("callback_host") or "").strip())' "${CONFIG_FILE}" 2>/dev/null || true)"
    SAN_ENTRIES="DNS:${HOST_CN},DNS:$(hostname -s 2>/dev/null || hostname),DNS:localhost,IP:127.0.0.1"
    if [[ -n "${CB_HOST}" && "${CB_HOST}" != "127.0.0.1" ]]; then
        if [[ "${CB_HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "${CB_HOST}" =~ : ]]; then
            SAN_ENTRIES="${SAN_ENTRIES},IP:${CB_HOST}"
        else
            SAN_ENTRIES="${SAN_ENTRIES},DNS:${CB_HOST}"
        fi
    fi
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 \
        -subj "/CN=${HOST_CN}" \
        -addext "subjectAltName=${SAN_ENTRIES}" \
        -keyout "${TLS_KEY}" \
        -out "${TLS_CRT}" >/dev/null 2>&1
    chown root:root "${TLS_KEY}" "${TLS_CRT}"
    chmod 0400 "${TLS_KEY}" "${TLS_CRT}"
    if [[ -d "/etc/pki/ca-trust/source/anchors" ]]; then
        cp -f "${TLS_CRT}" /etc/pki/ca-trust/source/anchors/ha-oob-gate.crt
        chmod 0644 /etc/pki/ca-trust/source/anchors/ha-oob-gate.crt
        update-ca-trust extract 2>/dev/null || true
    fi
    echo "      Generated root-owned (0400) self-signed SAN TLS certificate at ${TLS_CRT}"
else
    chown root:root "${TLS_KEY}" "${TLS_CRT}"
    chmod 0400 "${TLS_KEY}" "${TLS_CRT}"
    echo "      Preserved existing TLS certificate and key (0400, root:root)."
fi

groupadd -f -r ha-breakglass
if [[ "${ENABLE_PAM_SUDO}" -eq 1 ]]; then
    echo "[3/5] Enabling PAM sudo 2FA (/etc/sudoers.d/ha-oob-gate and /etc/pam.d/sudo)..."
    cat > /etc/sudoers.d/ha-oob-gate << 'EOF'
# Force sudo to consult PAM on every invocation so single-use command-pinned tickets cannot be bypassed
Defaults timestamp_timeout=0
EOF
    chmod 0440 /etc/sudoers.d/ha-oob-gate
    visudo -cf /etc/sudoers.d/ha-oob-gate

    PAM_SUDO="/etc/pam.d/sudo"
    if [[ -f "${PAM_SUDO}" ]]; then
        cp "${PAM_SUDO}" "${PAM_SUDO}.bak.$(date +%s)"
        configure_pam_sudo_file "${PAM_SUDO}"
    fi
else
    echo "[3/5] Skipping /etc/pam.d/sudo and /etc/sudoers.d/ha-oob-gate modification (pass --enable-pam-sudo after verifying HA connectivity to enable interactive sudo 2FA)."
fi

echo "[4/5] Installing and restarting hardened systemd service ha-sudo-gate.service..."
if [[ -f "${REPO_ROOT}/systemd/ha-sudo-gate.service" ]]; then
    cp -f "${REPO_ROOT}/systemd/ha-sudo-gate.service" /etc/systemd/system/ha-sudo-gate.service
else
    cp -f "${SERVICES_DIR}/ha-sudo-gate.service" /etc/systemd/system/ha-sudo-gate.service
fi
chown root:root /etc/systemd/system/ha-sudo-gate.service
chmod 0644 /etc/systemd/system/ha-sudo-gate.service

systemctl daemon-reload
systemctl enable ha-sudo-gate.service
systemctl restart ha-sudo-gate.service

echo "[5/5] Installation complete! Running self-test..."
/usr/local/bin/oob-auth --test || true
