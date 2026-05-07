#!/bin/bash
# =============================================================================
# install-kali-tools.sh
# Adds Kali rolling repos to Ubuntu 22.04 and installs the lateral-movement
# attack toolset. Idempotent (state markers in /var/lib/lab-bootstrap/).
# =============================================================================

set -eo pipefail

LOG=/var/log/lab-bootstrap.log
exec > >(tee -a "$LOG") 2>&1
echo "=== install-kali-tools.sh starting at $(date -Is) ==="

STATE_DIR=/var/lib/lab-bootstrap
mkdir -p "$STATE_DIR"

export DEBIAN_FRONTEND=noninteractive


# -----------------------------------------------------------------------------
# 1. Add Kali rolling repository
# -----------------------------------------------------------------------------
if [[ ! -f "$STATE_DIR/01-kali-repo.done" ]]; then
    echo "[1/3] Adding Kali rolling repository"

    # Kali archive key (current as of 2024 — pinned to specific URL)
    curl -fsSL https://archive.kali.org/archive-key.asc \
        | gpg --dearmor -o /usr/share/keyrings/kali-archive-keyring.gpg

    # Repo source — uses the keyring above for verification
    cat > /etc/apt/sources.list.d/kali.list <<'EOF'
deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
EOF

    # Pin Kali packages to lower priority than Ubuntu by default — only
    # install Kali packages when explicitly requested. Prevents accidentally
    # upgrading the entire system to Kali.
    cat > /etc/apt/preferences.d/kali.pref <<'EOF'
Package: *
Pin: release o=Kali
Pin-Priority: 50

Package: nmap crackmapexec impacket-scripts evil-winrm freerdp2-x11 hydra responder seclists netexec
Pin: release o=Kali
Pin-Priority: 990
EOF

    apt-get update -qq

    touch "$STATE_DIR/01-kali-repo.done"
else
    echo "[1/3] Kali repo already configured (skipping)"
fi


# -----------------------------------------------------------------------------
# 2. Install attack toolset
# -----------------------------------------------------------------------------
if [[ ! -f "$STATE_DIR/02-tools.done" ]]; then
    echo "[2/3] Installing attack toolset (this takes 3-5 minutes)"

    # Core tools always wanted from Ubuntu repos
    apt-get install -yq \
        curl wget jq tmux vim git python3-pip \
        net-tools dnsutils tcpdump

    # Tools from Kali repo (selected via the pin above)
    # Note: package names occasionally drift between Kali releases. If any of
    # these fail to install, check `apt-cache search <tool>` against the Kali
    # repo and update this list. crackmapexec was renamed to netexec in 2023
    # but the old name is still aliased.
    apt-get install -yq \
        nmap \
        crackmapexec \
        impacket-scripts \
        evil-winrm \
        freerdp2-x11 \
        hydra \
        responder \
        seclists || {
            echo "Some Kali packages failed; continuing with what installed."
            echo "Verify available packages with: apt-cache policy <pkg>"
        }

    # Verify the critical tools landed
    echo
    echo "Tool verification:"
    for tool in nmap crackmapexec evil-winrm xfreerdp; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  OK  $tool ($(command -v $tool))"
        else
            echo "  MISSING $tool"
        fi
    done

    touch "$STATE_DIR/02-tools.done"
else
    echo "[2/3] Tools already installed (skipping)"
fi


# -----------------------------------------------------------------------------
# 3. Lab convenience — ubuntu user defaults
# -----------------------------------------------------------------------------
if [[ ! -f "$STATE_DIR/03-userprep.done" ]]; then
    echo "[3/3] Preparing ubuntu user environment"

    # Drop a quick reference card in the home directory so you don't have to
    # remember command syntax mid-attack
    cat > /home/ubuntu/ATTACK-QUICKREF.md <<'EOF'
# Attack quickref — lateral movement

These reference the lab's hosts:
  DC01    10.0.2.10    lab.local
  WIN01   10.0.2.20    member server (lateral movement target)
  bob     local admin on WIN01
  svc_backup    domain user, in Remote Management Users

Get passwords with: terraform output -raw bob_password (etc.) from your laptop.

## T1021.001 — RDP
xfreerdp /u:bob /p:'<bob_password>' /v:10.0.2.20 /cert-ignore +clipboard /size:1024x768

## T1021.002 — SMB / Admin shares
crackmapexec smb 10.0.2.20 -u bob -p '<bob_password>'
smbclient //10.0.2.20/C$ -U lab/bob -W lab

## T1021.006 — WinRM
evil-winrm -i 10.0.2.20 -u svc_backup -p '<svc_backup_password>'

## Recon
nmap -Pn -sS -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985 10.0.2.0/24
crackmapexec smb 10.0.2.0/24
EOF

    chown ubuntu:ubuntu /home/ubuntu/ATTACK-QUICKREF.md

    touch "$STATE_DIR/03-userprep.done"
else
    echo "[3/3] User prep already done (skipping)"
fi

echo "=== install-kali-tools.sh done at $(date -Is) ==="
echo
echo "SSH in with: ssh -i <key.pem> ubuntu@<eip>"
echo "Then read: cat ~/ATTACK-QUICKREF.md"
