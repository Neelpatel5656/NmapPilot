#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────
#  NmapPilot — One-command installer
# ───────────────────────────────────────────────────────────────────
set -e

# Colors
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[✔]${RESET} $1"; }
warn() { echo -e "  ${YELLOW}[⚠]${RESET} $1"; }
err()  { echo -e "  ${RED}[✘]${RESET} $1"; }
info() { echo -e "  ${CYAN}[ℹ]${RESET} $1"; }

echo ""
echo -e "${CYAN}${BOLD}  ╔══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}  ║       NmapPilot — Installer              ║${RESET}"
echo -e "${CYAN}${BOLD}  ╚══════════════════════════════════════════╝${RESET}"
echo ""

# ── Check Python ──
info "Checking Python…"
if command -v python3 &>/dev/null; then
    PY=$(command -v python3)
    PY_VER=$($PY --version 2>&1 | awk '{print $2}')
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
        ok "Python $PY_VER found at $PY"
    else
        err "Python 3.8+ is required (found $PY_VER)"
        exit 1
    fi
else
    err "Python 3 not found. Please install Python 3.8+ first."
    exit 1
fi

# ── Check nmap ──
info "Checking nmap…"
if command -v nmap &>/dev/null; then
    NMAP_VER=$(nmap --version 2>&1 | head -1)
    ok "$NMAP_VER"
else
    warn "nmap not found. NmapPilot requires nmap to function."
    warn "Install it with:  sudo pacman -S nmap  /  sudo apt install nmap"
fi

# ── Check searchsploit (optional) ──
info "Checking searchsploit (optional)…"
if command -v searchsploit &>/dev/null; then
    ok "searchsploit found"
else
    info "searchsploit not found — ExploitDB integration will be unavailable"
fi

# ── Install package ──
echo ""
info "Installing NmapPilot system-wide…"
cd "$(dirname "$0")"

if command -v sudo &>/dev/null; then
    SUDO="sudo"
else
    SUDO=""
fi

if $SUDO pip install . 2>&1 | tail -2; then
    ok "NmapPilot installed successfully"
else
    warn "pip install failed, trying with --break-system-packages…"
    if $SUDO pip install . --break-system-packages 2>&1 | tail -2; then
        ok "NmapPilot installed successfully"
    else
        err "Installation failed. Try manually: sudo pip install . --break-system-packages"
        exit 1
    fi
fi


# ── Ensure ~/.local/bin is in PATH ──
echo ""
info "Checking PATH…"

LOCAL_BIN="$HOME/.local/bin"

add_to_path() {
    # Fish shell
    if [ -d "$HOME/.config/fish" ]; then
        FISH_CONF="$HOME/.config/fish/config.fish"
        if ! grep -q "local/bin" "$FISH_CONF" 2>/dev/null; then
            mkdir -p "$HOME/.config/fish"
            echo "" >> "$FISH_CONF"
            echo "# Added by NmapPilot installer" >> "$FISH_CONF"
            echo "fish_add_path $LOCAL_BIN" >> "$FISH_CONF"
            ok "Added $LOCAL_BIN to fish config"
        else
            ok "fish config already has local/bin in PATH"
        fi
    fi

    # Bash
    if [ -f "$HOME/.bashrc" ]; then
        if ! grep -q "local/bin" "$HOME/.bashrc" 2>/dev/null; then
            echo "" >> "$HOME/.bashrc"
            echo "# Added by NmapPilot installer" >> "$HOME/.bashrc"
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
            ok "Added $LOCAL_BIN to .bashrc"
        fi
    fi

    # Zsh
    if [ -f "$HOME/.zshrc" ]; then
        if ! grep -q "local/bin" "$HOME/.zshrc" 2>/dev/null; then
            echo "" >> "$HOME/.zshrc"
            echo "# Added by NmapPilot installer" >> "$HOME/.zshrc"
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
            ok "Added $LOCAL_BIN to .zshrc"
        fi
    fi
}

if echo "$PATH" | grep -q "$LOCAL_BIN"; then
    ok "$LOCAL_BIN already in PATH"
else
    warn "$LOCAL_BIN not in PATH — adding it now"
    add_to_path
    export PATH="$LOCAL_BIN:$PATH"
fi

# ── Create sudo-compatible wrapper in /usr/local/bin ──
echo ""
info "Configuring sudo access…"
PKG_DIR="$(cd "$(dirname "$0")" && pwd)"

WRAPPER_CONTENT="#!/bin/bash
# NmapPilot wrapper — ensures the package is always found under sudo
PKG_DIR=\"$PKG_DIR\"
export PYTHONPATH=\"\$PKG_DIR\${PYTHONPATH:+:\$PYTHONPATH}\"
exec python3 -m nmappilot \"\$@\"
"

if command -v sudo &>/dev/null; then
    echo "$WRAPPER_CONTENT" | sudo tee /usr/local/bin/nmappilot > /dev/null
    sudo chmod +x /usr/local/bin/nmappilot
    ok "Created /usr/local/bin/nmappilot wrapper — sudo nmappilot is ready"
else
    warn "sudo not found — skipping wrapper creation"
fi

# ── Verify ──
echo ""
info "Verifying installation…"
if command -v nmappilot &>/dev/null; then
    ok "nmappilot command is available"
elif [ -f "$LOCAL_BIN/nmappilot" ]; then
    ok "nmappilot installed at $LOCAL_BIN/nmappilot"
elif $PY -m nmappilot --version &>/dev/null; then
    ok "NmapPilot is available via: python -m nmappilot"
else
    err "Verification failed"
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}  ✔ Installation complete!${RESET}"
echo -e "${DIM}  Usage:  sudo nmappilot${RESET}"
echo -e "${DIM}          sudo nmappilot -t scanme.nmap.org${RESET}"
echo ""
echo -e "${YELLOW}  Note: If 'nmappilot' is not found, restart your terminal or run:${RESET}"
echo -e "${DIM}    fish:  fish_add_path ~/.local/bin${RESET}"
echo -e "${DIM}    bash:  source ~/.bashrc${RESET}"
echo ""
