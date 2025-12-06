#!/bin/bash
# DeadNet - Android (Termux) One-Line Installer
# Usage: curl -sL https://raw.githubusercontent.com/risunCode/Deadnet-Windows/main/install-android.sh | bash
# Or: wget -qO- https://raw.githubusercontent.com/risunCode/Deadnet-Windows/main/install-android.sh | bash

set -e

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

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}[!] This script is for Termux only!${NC}"
    echo "    Install Termux from F-Droid: https://f-droid.org/packages/com.termux/"
    exit 1
fi

# Check root
if [ "$(id -u)" != "0" ]; then
    echo -e "${YELLOW}[!] Root access required for network attacks${NC}"
    echo "    Checking for root..."
    if command -v su &> /dev/null; then
        echo -e "${GREEN}[+] Root available (su found)${NC}"
    elif command -v tsu &> /dev/null; then
        echo -e "${GREEN}[+] Root available (tsu found)${NC}"
    else
        echo -e "${RED}[!] No root access detected${NC}"
        echo "    DeadNet requires root for raw packet injection"
        echo "    Install tsu: pkg install tsu"
        echo ""
        read -p "Continue anyway? (y/n): " cont
        if [ "$cont" != "y" ]; then exit 1; fi
    fi
fi

echo -e "${BLUE}[1/4]${NC} Updating packages..."
pkg update -y

echo -e "${BLUE}[2/4]${NC} Installing dependencies..."
pkg install -y python git root-repo

echo -e "${BLUE}[3/4]${NC} Installing Python packages..."
pip install --upgrade pip
pip install scapy netifaces2 flask flask-cors

echo -e "${BLUE}[4/4]${NC} Cloning DeadNet..."
INSTALL_DIR="$HOME/deadnet"
if [ -d "$INSTALL_DIR" ]; then
    echo "    Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull
else
    git clone https://github.com/risunCode/Deadnet-Windows.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Web assets (dist/) are pre-built in repo - no npm needed!

# Create launcher script
cat > "$INSTALL_DIR/deadnet" << 'LAUNCHER'
#!/bin/bash
cd "$(dirname "$0")"

# Get device IP
get_ip() {
    ip addr show wlan0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1
}

IP=$(get_ip)
PORT=${1:-5000}

echo ""
echo "  DeadNet - Android"
echo "  ================="
echo ""
echo "  Local:   http://127.0.0.1:$PORT"
[ -n "$IP" ] && echo "  Network: http://$IP:$PORT"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

# Run with root if available
if command -v tsu &> /dev/null; then
    tsu -c "python main.py --browser --port $PORT"
elif command -v su &> /dev/null; then
    su -c "python main.py --browser --port $PORT"
else
    echo "[!] Running without root (limited functionality)"
    python main.py --browser --port $PORT
fi
LAUNCHER

chmod +x "$INSTALL_DIR/deadnet"

# Add to PATH
if ! grep -q "deadnet" "$HOME/.bashrc" 2>/dev/null; then
    echo "alias deadnet='$INSTALL_DIR/deadnet'" >> "$HOME/.bashrc"
fi

echo ""
echo -e "${GREEN}=========================================="
echo "  Installation Complete!"
echo "==========================================${NC}"
echo ""
echo "  Run DeadNet:"
echo -e "    ${YELLOW}cd ~/deadnet && ./deadnet${NC}"
echo ""
echo "  Or after restart terminal:"
echo -e "    ${YELLOW}deadnet${NC}"
echo ""
echo "  Then open browser:"
echo -e "    ${BLUE}http://127.0.0.1:5000${NC}"
[ -n "$IP" ] && echo -e "    ${BLUE}http://$IP:5000${NC} (from other device)"
echo ""
echo -e "${RED}[!] Remember: Root required for attacks!${NC}"
echo ""

read -p "Start DeadNet now? (y/n): " start
if [ "$start" = "y" ]; then
    exec "$INSTALL_DIR/deadnet"
fi
