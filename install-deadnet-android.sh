#!/bin/bash
# DeadNet - Android (Termux) Installer
# Step 1: pkg update && pkg install -y python git wget clang libffi openssl
# Step 2: wget https://raw.githubusercontent.com/risunCode/Deadnet-Windows/main/install-android.sh
# Step 3: bash install-android.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}"
echo "     ____                 _  _   _      _   "
echo "    |  _ \\  ___  ____  __| || \\ | | ___| |_ "
echo "    | | | |/ _ \\/ _  |/ _\` ||  \\| |/ _ \\ __|"
echo "    | |_| |  __/ (_| | (_| || |\\  |  __/ |_ "
echo "    |____/ \\___|\\__,_|\\__,_||_| \\_|\\___|\\__|"
echo -e "${NC}"
echo -e "${YELLOW}Android/Termux Installer${NC}"
echo "=========================================="
echo ""

# Check Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}[!] Termux only! Get from F-Droid${NC}"
    exit 1
fi

# Check root
echo -e "${BLUE}[*]${NC} Checking root..."
if su -c "id" &>/dev/null; then
    echo -e "${GREEN}[+] Root OK${NC}"
else
    echo -e "${RED}[!] Root NOT detected!${NC}"
    echo "    Need rooted device (Magisk/KernelSU)"
    read -p "    Continue? (y/n): " cont
    [ "$cont" != "y" ] && exit 1
fi

echo ""
echo -e "${BLUE}[1/2]${NC} Installing Python packages..."
pip install scapy netifaces flask flask-cors || {
    echo -e "${RED}[!] pip install failed. Try:${NC}"
    echo "    pkg install python-pip"
    exit 1
}

echo ""
echo -e "${BLUE}[2/2]${NC} Cloning DeadNet..."
INSTALL_DIR="$HOME/deadnet"
rm -rf "$INSTALL_DIR" 2>/dev/null
git clone https://github.com/risunCode/Deadnet-Windows.git "$INSTALL_DIR" || {
    echo -e "${RED}[!] git clone failed${NC}"
    exit 1
}

echo ""
echo -e "${GREEN}=========================================="
echo "  Installation Complete!"
echo "==========================================${NC}"
echo ""
echo -e "  Run DeadNet:"
echo -e "  ${YELLOW}su -c \"/data/data/com.termux/files/usr/bin/python /data/data/com.termux/files/home/deadnet/main.py --browser\"${NC}"
echo ""
echo -e "  Then open: ${BLUE}http://127.0.0.1:5000${NC}"
echo ""

read -p "Start now? (y/n): " start
if [ "$start" = "y" ]; then
    echo ""
    echo -e "${BLUE}[*] Starting...${NC}"
    echo "    Open browser: http://127.0.0.1:5000"
    echo ""
    su -c "/data/data/com.termux/files/usr/bin/python /data/data/com.termux/files/home/deadnet/main.py --browser"
fi
