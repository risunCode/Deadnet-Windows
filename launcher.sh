#!/bin/bash

# DeadNet - Network Security Tool Launcher

cd "$(dirname "$0")"

# Venv paths
VENV_DIR=".venv"
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Requesting root privileges..."
    sudo "$0" "$@"
    exit $?
fi

show_menu() {
    echo ""
    echo "========================================"
    echo "  DeadNet - Network Security Tool"
    echo "========================================"
    echo ""
    echo "  [1] WebView Mode"
    echo "  [2] Browser Mode"
    echo "  [3] Browser Mode (No auto-open)"
    echo "  [4] Install Dependencies"
    echo "  [5] Exit"
    echo ""
    read -p "  Select: " choice
}

check_venv() {
    if [ ! -f "$VENV_PYTHON" ]; then
        echo ""
        echo "[!] Virtual environment not found!"
        echo "[!] Please run option [4] Install Dependencies first."
        read -p "Press Enter to continue..."
        return 1
    fi
    return 0
}

check_dist() {
    if [ ! -f "dist/index.html" ]; then
        echo ""
        echo "[!] Building web assets..."
        npm install
        npm run build
    fi
}

install_deps() {
    echo ""
    echo "[+] Setting up virtual environment..."
    
    # Create venv if not exists
    if [ ! -d "$VENV_DIR" ]; then
        echo "[*] Creating virtual environment..."
        python3 -m venv $VENV_DIR
    fi
    
    # Upgrade pip
    echo "[*] Upgrading pip..."
    "$VENV_PYTHON" -m pip install --upgrade pip > /dev/null 2>&1
    
    # Install Python dependencies
    echo "[*] Installing Python dependencies..."
    "$VENV_PIP" install -r requirements.txt
    
    # Install Node dependencies
    echo "[*] Installing Node dependencies..."
    npm install
    
    # Build web assets
    echo "[*] Building web assets..."
    npm run build
    
    echo ""
    echo "[+] Done! Virtual environment ready at: $VENV_DIR"
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    clear
    show_menu
    
    case $choice in
        1)
            check_venv || continue
            check_dist
            echo ""
            echo "[+] Starting in WebView mode..."
            "$VENV_PYTHON" main.py --webview
            ;;
        2)
            check_venv || continue
            check_dist
            echo ""
            echo "[+] Starting in Browser mode..."
            "$VENV_PYTHON" main.py --browser
            ;;
        3)
            check_venv || continue
            check_dist
            echo ""
            echo "[+] Starting in Browser mode (no auto-open)..."
            "$VENV_PYTHON" main.py --browser --no-open
            ;;
        4)
            install_deps
            ;;
        5)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid option"
            sleep 1
            ;;
    esac
done
