#!/bin/bash

# DeadNet - Network Security Tool Launcher

cd "$(dirname "$0")"

# Venv paths
VENV_DIR=".venv"
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!]${NC} Root privileges required!"
        echo "    Please run with: sudo $0"
        exit 1
    fi
}

show_menu() {
    clear
    echo ""
    echo "========================================"
    echo "  DeadNet - Network Security Tool"
    echo "========================================"
    echo ""
    echo "  [1] Run (WebView)"
    echo "  [2] Run (Browser)"
    echo "  [3] Run (Browser, No auto-open)"
    echo "  [4] Build AppImage (Linux)"
    echo "  [5] Install Dependencies"
    echo "  [6] Clean Build Files"
    echo "  [7] Exit"
    echo ""
    read -p "  Select: " choice
}

check_venv() {
    if [ ! -f "$VENV_PYTHON" ]; then
        echo ""
        echo -e "${RED}[!]${NC} Virtual environment not found!"
        echo "    Please run option [5] Install Dependencies first."
        read -p "Press Enter to continue..."
        return 1
    fi
    return 0
}

check_dist() {
    if [ ! -f "dist/index.html" ]; then
        echo ""
        echo -e "${BLUE}[*]${NC} Building web assets..."
        npm install
        npm run build
        if [ ! -f "dist/index.html" ]; then
            echo -e "${RED}[!]${NC} Build failed!"
            return 1
        fi
    fi
    return 0
}

install_deps() {
    echo ""
    echo -e "${GREEN}[+]${NC} Setting up virtual environment..."
    
    # Create venv if not exists
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${BLUE}[*]${NC} Creating virtual environment..."
        python3 -m venv $VENV_DIR
    fi
    
    # Upgrade pip
    echo -e "${BLUE}[*]${NC} Upgrading pip..."
    "$VENV_PYTHON" -m pip install --upgrade pip > /dev/null 2>&1
    
    # Install Python dependencies
    echo -e "${BLUE}[*]${NC} Installing Python dependencies..."
    "$VENV_PIP" install -r requirements.txt
    
    # Install Node dependencies
    echo -e "${BLUE}[*]${NC} Installing Node dependencies..."
    npm install
    
    # Build web assets
    echo -e "${BLUE}[*]${NC} Building web assets..."
    npm run build
    
    echo ""
    echo -e "${GREEN}[+]${NC} Done! Virtual environment ready at: $VENV_DIR"
    read -p "Press Enter to continue..."
}

build_app() {
    echo ""
    echo "========================================"
    echo "  Building Application"
    echo "========================================"
    echo ""
    
    check_venv || return
    check_dist || return
    
    echo -e "${BLUE}[1/2]${NC} Checking dependencies..."
    "$VENV_PIP" install -r requirements.txt > /dev/null 2>&1
    
    echo -e "${BLUE}[2/2]${NC} Building with PyInstaller..."
    echo ""
    
    "$VENV_PYTHON" -m PyInstaller --noconfirm --onefile \
        --name "DeadNet" \
        --add-data "dist:dist" \
        --add-data "backend:backend" \
        --hidden-import "netifaces" \
        --hidden-import "scapy.all" \
        --hidden-import "scapy.layers.l2" \
        --hidden-import "scapy.layers.inet" \
        --hidden-import "scapy.layers.inet6" \
        --hidden-import "flask" \
        --hidden-import "flask_cors" \
        --hidden-import "webview" \
        --exclude-module "tkinter" \
        --exclude-module "scapy.contrib" \
        --exclude-module "scapy.tools" \
        --exclude-module "scapy.modules" \
        --exclude-module "matplotlib" \
        --exclude-module "numpy" \
        --exclude-module "pandas" \
        --exclude-module "scipy" \
        --exclude-module "cryptography" \
        main.py
    
    # Cleanup build artifacts
    rm -rf build 2>/dev/null
    rm -f DeadNet.spec 2>/dev/null
    
    echo ""
    if [ -f "dist/DeadNet" ]; then
        chmod +x dist/DeadNet
        echo -e "${GREEN}[+]${NC} Success: dist/DeadNet"
        echo -e "${BLUE}[*]${NC} Size: $(du -h dist/DeadNet | cut -f1)"
    else
        echo -e "${RED}[!]${NC} Build failed"
    fi
    echo ""
    read -p "Press Enter to continue..."
}

clean_build() {
    echo ""
    echo -e "${BLUE}[*]${NC} Cleaning build files..."
    rm -rf build 2>/dev/null
    rm -f DeadNet.spec 2>/dev/null
    rm -f dist/DeadNet 2>/dev/null
    rm -rf __pycache__ 2>/dev/null
    rm -rf backend/__pycache__ 2>/dev/null
    rm -f deadnet.log 2>/dev/null
    echo -e "${GREEN}[+]${NC} Done!"
    read -p "Press Enter to continue..."
}

# Check root first
check_root

# Main loop
while true; do
    show_menu
    
    case $choice in
        1)
            check_venv || continue
            check_dist || continue
            echo ""
            echo -e "${GREEN}[+]${NC} Starting in WebView mode..."
            "$VENV_PYTHON" main.py --webview
            read -p "Press Enter to continue..."
            ;;
        2)
            check_venv || continue
            check_dist || continue
            echo ""
            echo -e "${GREEN}[+]${NC} Starting in Browser mode..."
            "$VENV_PYTHON" main.py --browser
            read -p "Press Enter to continue..."
            ;;
        3)
            check_venv || continue
            check_dist || continue
            echo ""
            echo -e "${GREEN}[+]${NC} Starting in Browser mode (no auto-open)..."
            "$VENV_PYTHON" main.py --browser --no-open
            read -p "Press Enter to continue..."
            ;;
        4)
            build_app
            ;;
        5)
            install_deps
            ;;
        6)
            clean_build
            ;;
        7)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            sleep 1
            ;;
    esac
done
