#!/usr/bin/env bash
set -e

# ================= UI =================
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

line() { echo -e "${CYAN}${BOLD}=========================================${RESET}"; }
msg()  { echo -e "${BLUE}➜${RESET} $1"; }
ok()   { echo -e "${GREEN}✔${RESET} $1"; }
warn() { echo -e "${YELLOW}⚠${RESET} $1"; }
err()  { echo -e "${RED}✖${RESET} $1"; exit 1; }

# ================= ROOT CHECK =================
[[ $EUID -ne 0 ]] && err "Please run this script as root"

clear
line
echo -e "${BOLD}        🚀 SSHBot Universal Installer${RESET}"
line
echo

# ================= PATHS =================
INSTALL_DIR="/opt/sshbot"
BOT_FILE="$INSTALL_DIR/ssh-bot.py"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_FILE="/etc/systemd/system/sshbot.service"

# ================= CLEANUP EXISTING BOT =================
if systemctl list-units --all | grep -q sshbot; then
    warn "Existing SSHBot installation detected. Removing..."
    systemctl stop sshbot >/dev/null 2>&1 || true
    systemctl disable sshbot >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    rm -rf "$INSTALL_DIR"
    systemctl daemon-reload
    ok "Old SSHBot removed"
fi

# ================= BOT TOKEN =================
read -rp "$(echo -e ${YELLOW}'🤖 Enter Telegram Bot Token: '${RESET})" BOT_TOKEN
[[ -z "$BOT_TOKEN" ]] && err "Bot token cannot be empty"

# ================= OS / PACKAGE MANAGER =================
msg "Detecting Linux distribution"

if command -v apt >/dev/null 2>&1; then
  PM="apt"
elif command -v dnf >/dev/null 2>&1; then
  PM="dnf"
elif command -v yum >/dev/null 2>&1; then
  PM="yum"
else
  err "Unsupported distro: no apt / dnf / yum found"
fi

ok "Package manager detected: $PM"

# ================= INSTALL DEPS =================
msg "Installing system dependencies"

if [[ "$PM" == "apt" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt update -y >/dev/null
  apt install -y python3 python3-venv python3-pip openssh-client curl >/dev/null
else
  $PM install -y epel-release >/dev/null || true
  $PM install -y python3 python3-pip python3-virtualenv openssh-clients curl >/dev/null
fi

ok "System packages installed"

# ================= DOWNLOAD BOT =================
msg "Downloading SSHBot"

mkdir -p "$INSTALL_DIR"

curl -fsSL \
  https://github.com/ItzGlace/SSHBot/raw/refs/heads/main/ssh-bot.py \
  -o "$BOT_FILE" || err "Failed to download bot file"

chmod +x "$BOT_FILE"
ok "Bot downloaded"

# ================= PYTHON VENV =================
msg "Creating Python virtual environment"

python3 -m venv "$VENV_DIR"

source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null
pip install python-telegram-bot==13.15 paramiko pyte >/dev/null
deactivate

ok "Virtual environment ready"

# ================= FETCH BOT VERSION =================
msg "Fetching latest bot version"

LATEST_VERSION=$(curl -s https://api.github.com/repos/ItzGlace/SSHBot/commits/main | grep -m1 '"message":' | cut -d '"' -f4)
[[ -z "$LATEST_VERSION" ]] && LATEST_VERSION="Unknown"
ok "Latest bot version: $LATEST_VERSION"

# ================= SYSTEMD SERVICE =================
msg "Creating systemd service"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Telegram SSH Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=BOT_TOKEN=$BOT_TOKEN
ExecStart=$VENV_DIR/bin/python $BOT_FILE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

ok "Service created"

# ================= START SERVICE =================
msg "Starting SSHBot service"

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable sshbot >/dev/null
systemctl restart sshbot

sleep 1

# ================= STATUS =================
if systemctl is-active --quiet sshbot; then
  echo
  line
  echo -e "${GREEN}${BOLD}✅ SSHBot installed and running!${RESET}"
  echo -e "${YELLOW}🔖 Bot version: ${BOLD}$LATEST_VERSION${RESET}"
  line
else
  err "SSHBot failed to start — check logs: journalctl -u sshbot -f"
fi

# ================= HELP =================
echo
echo -e "${CYAN}📌 Useful commands:${RESET}"
echo -e "  ${BOLD}systemctl status sshbot${RESET}"
echo -e "  ${BOLD}journalctl -u sshbot -f${RESET}"
echo
echo -e "${GREEN}🎉 Installation complete on $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')${RESET}"
