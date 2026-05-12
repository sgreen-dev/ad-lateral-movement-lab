#!/bin/bash
# =============================================================================
# install-kali-tools.sh
# Installs lateral-movement attack toolkit on Ubuntu 24.04.
#
# Strategy: avoid the Kali rolling repo entirely. Kali tracks Debian sid which
# diverges from Ubuntu stable releases too fast for apt pinning to keep up.
# Instead we use:
#   - Ubuntu apt for tools that exist there (nmap, xfreerdp, hydra)
#   - pipx for Python-based tools (netexec, impacket)
#   - Ruby gem for evil-winrm
#
# This is the modern best-practice approach for offensive tooling on a
# non-Kali base. More reproducible, no repo conflicts.
# =============================================================================

set -eo pipefail

LOG=/var/log/lab-bootstrap.log
exec > >(tee -a "$LOG") 2>&1
echo "=== install-kali-tools.sh starting at $(date -Is) ==="

STATE_DIR=/var/lib/lab-bootstrap
mkdir -p "$STATE_DIR"

export DEBIAN_FRONTEND=noninteractive


# -----------------------------------------------------------------------------
# 1. apt-installed tools
# -----------------------------------------------------------------------------
if [[ ! -f "$STATE_DIR/01-apt-tools.done" ]]; then
    echo "[1/4] Installing apt packages (curl, jq, tmux, vim, git, python3-pip, pipx, nmap, xfreerdp, hydra, samba-client, tcpdump, dnsutils)"

    apt-get update -qq
    apt-get install -yq \
        curl wget jq tmux vim git python3-pip pipx \
        net-tools dnsutils tcpdump \
        nmap freerdp2-x11 \
        hydra \
        smbclient \
        ruby ruby-dev build-essential

    # Verify essentials installed
    echo "Tool verification (apt):"
    for tool in nmap xfreerdp hydra smbclient; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  OK  $tool ($(command -v $tool))"
        else
            echo "  MISSING $tool"
        fi
    done

    touch "$STATE_DIR/01-apt-tools.done"
else
    echo "[1/4] apt tools already installed (skipping)"
fi


# -----------------------------------------------------------------------------
# 2. pipx tools (Python-based, run as the ubuntu user so they're on its PATH)
# -----------------------------------------------------------------------------
if [[ ! -f "$STATE_DIR/02-pipx-tools.done" ]]; then
    echo "[2/4] Installing pipx tools (netexec, impacket) for the ubuntu user"

    # Ensure ubuntu's pipx PATH is set up
    sudo -u ubuntu bash -c 'pipx ensurepath' || true

    # NetExec is the maintained successor to CrackMapExec.
    # Install from git for the latest release; pinning happens at the Python
    # package level (netexec's own deps are pinned in its setup.py).
    echo "Installing netexec..."
    sudo -u ubuntu bash -c 'pipx install git+https://github.com/Pennyw0rth/NetExec.git' || {
        echo "  WARN: netexec install via git failed; trying pypi"
        sudo -u ubuntu bash -c 'pipx install netexec' || echo "  ERROR: netexec install failed"
    }

    # Impacket — collection of Python classes for SMB1-3, MSRPC, etc.
    echo "Installing impacket..."
    sudo -u ubuntu bash -c 'pipx install impacket' || echo "  ERROR: impacket install failed"

    # Symlink the binaries into /usr/local/bin so root and any user can run them
    # pipx installs to /home/ubuntu/.local/bin by default
    for bin in nxc netexec smbexec.py psexec.py wmiexec.py secretsdump.py getTGT.py getST.py GetUserSPNs.py impacket-secretsdump; do
        src="/home/ubuntu/.local/bin/$bin"
        if [[ -f "$src" || -L "$src" ]]; then
            ln -sf "$src" "/usr/local/bin/$bin"
            echo "  symlinked $bin"
        fi
    done

    echo "Tool verification (pipx):"
    for tool in nxc impacket-secretsdump; do
        if sudo -u ubuntu bash -c "command -v $tool" >/dev/null 2>&1; then
            echo "  OK  $tool"
        else
            echo "  MISSING $tool"
        fi
    done

    touch "$STATE_DIR/02-pipx-tools.done"
else
    echo "[2/4] pipx tools already installed (skipping)"
fi


# -----------------------------------------------------------------------------
# 3. Ruby gem: evil-winrm
# -----------------------------------------------------------------------------
if [[ ! -f "$STATE_DIR/03-gem-tools.done" ]]; then
    echo "[3/4] Installing evil-winrm via gem"

    gem install evil-winrm --no-document || {
        echo "  ERROR: evil-winrm install failed"
    }

    if command -v evil-winrm >/dev/null 2>&1; then
        echo "  OK  evil-winrm ($(command -v evil-winrm))"
    else
        echo "  MISSING evil-winrm"
    fi

    touch "$STATE_DIR/03-gem-tools.done"
else
    echo "[3/4] gem tools already installed (skipping)"
fi


# -----------------------------------------------------------------------------
# 4. Lab convenience — quickref for the ubuntu user
# -----------------------------------------------------------------------------
if [[ ! -f "$STATE_DIR/04-userprep.done" ]]; then
    echo "[4/4] Preparing ubuntu user environment"

    cat > /home/ubuntu/ATTACK-QUICKREF.md <<'EOF'
# Attack quickref — lateral movement

These reference the lab's hosts:
  DC01    10.0.2.10    lab.local
  WIN01   10.0.2.20    member server (lateral movement target)
  bob     local admin on WIN01
  svc_backup    domain user, in Remote Management Users

Get passwords with: terraform output -raw bob_password (etc.) from your laptop.

## T1021.001 - RDP
xfreerdp /u:bob /p:'<bob_password>' /v:10.0.2.20 /cert-ignore +clipboard /size:1024x768

## T1021.002 - SMB / Admin shares
# NetExec (formerly CrackMapExec)
nxc smb 10.0.2.20 -u bob -p '<bob_password>'
smbclient //10.0.2.20/C$ -U lab/bob -W lab

## T1021.006 - WinRM
evil-winrm -i 10.0.2.20 -u svc_backup -p '<svc_backup_password>'

## Recon
nmap -Pn -sS -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985 10.0.2.0/24
nxc smb 10.0.2.0/24
EOF

    chown ubuntu:ubuntu /home/ubuntu/ATTACK-QUICKREF.md

    touch "$STATE_DIR/04-userprep.done"
else
    echo "[4/4] User prep already done (skipping)"
fi


echo "=== install-kali-tools.sh done at $(date -Is) ==="
echo
echo "SSH in with: ssh -i <key.pem> ubuntu@<eip>"
echo "Then read: cat ~/ATTACK-QUICKREF.md"
echo
echo "Note: This host uses Ubuntu 24.04 with attack tools installed via apt + pipx + gem."
echo "      The 'CrackMapExec' tool is now called 'nxc' (NetExec is the maintained fork)."
