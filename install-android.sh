#!/bin/bash
# DeadNet - Android (Termux) One-Line Installer
# curl -sL https://raw.githubusercontent.com/risunCode/Deadnet-Windows/main/install-android.sh | bash

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

# Check Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}[!] Termux only! Get it from F-Droid${NC}"
    exit 1
fi

# Check/install tsu for root
if ! command -v tsu &> /dev/null && ! command -v su &> /dev/null; then
    echo -e "${YELLOW}[!] Installing tsu for root access...${NC}"
    pkg install -y tsu
fi

echo -e "${BLUE}[1/3]${NC} Installing dependencies..."
pkg update -y && pkg install -y python git root-repo tsu

echo -e "${BLUE}[2/3]${NC} Installing Python packages..."
pip install scapy netifaces2 flask flask-cors

echo -e "${BLUE}[3/3]${NC} Cloning DeadNet..."
INSTALL_DIR="$HOME/deadnet"
rm -rf "$INSTALL_DIR" 2>/dev/null
git clone https://github.com/risunCode/Deadnet-Windows.git "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Create launcher
cat > "$INSTALL_DIR/deadnet" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
IP=$(ip addr show wlan0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
PORT=${1:-5000}
echo ""
echo "  DeadNet - Android"
echo "  Local:   http://127.0.0.1:$PORT"
[ -n "$IP" ] && echo "  Network: http://$IP:$PORT"
echo "  Press Ctrl+C to stop"
echo ""
tsu -c "python main.py --browser --port $PORT" 2>/dev/null || su -c "python main.py --browser --port $PORT"
EOF
chmod +x "$INSTALL_DIR/deadnet"

# Add alias
grep -q "alias deadnet" "$HOME/.bashrc" 2>/dev/null || echo "alias deadnet='$INSTALL_DIR/deadnet'" >> "$HOME/.bashrc"

echo ""
echo -e "${GREEN}[+] Installation Complete!${NC}"
echo ""
echo -e "  Next time run: ${YELLOW}deadnet${NC} (after restart terminal)"
echo -e "  Or: ${YELLOW}cd ~/deadnet && ./deadnet${NC}"
echo ""
echo -e "${BLUE}[*] Starting DeadNet...${NC}"
echo ""

# Auto-run
exec "$INSTALL_DIR/deadnet"
