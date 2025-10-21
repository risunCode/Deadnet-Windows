#!/usr/bin/env python3
"""
DeadNet - Network Security Testing Tool (WebView Version)
WARNING: This tool is for authorized penetration testing only.
Unauthorized use is illegal and unethical.
"""

import logging
import threading
import time
import sys
import os
import webbrowser
from flask import Flask
from flask_cors import CORS

# Try to import webview, fallback to browser if unavailable
try:
    import webview
    WEBVIEW_AVAILABLE = True
except (ImportError, Exception) as e:
    WEBVIEW_AVAILABLE = False
    print(f"[!] WebView not available: {e}")
    print(f"[*] Will use default browser instead...")

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

# Fix template and static paths for PyInstaller
if getattr(sys, 'frozen', False):
    # Running in PyInstaller bundle
    base_path = sys._MEIPASS
else:
    # Running in normal Python environment
    base_path = os.path.dirname(os.path.abspath(__file__))

template_folder = os.path.join(base_path, 'web', 'templates')
static_folder = os.path.join(base_path, 'web', 'static')

from utils import *

conf.verb = 0

# Flask app setup
app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
CORS(app)

# Global attack state
attack_state = {
    'active': False,
    'mode': None,
    'interface': None,
    'attacks_enabled': {
        'arp_poison': True,
        'ipv6_ra': True,
        'dead_router': True
    },
    'statistics': {
        'cycles': 0,
        'packets_sent': 0,
        'start_time': None,
        'last_cycle_duration': 0
    },
    'network_info': {},
    'logs': []
}

attack_lock = threading.Lock()

# Setup all API routes
setup_routes(app, attack_state, attack_lock)


# All attack logic and API routes have been moved to utils modules


def check_webview_available():
    """Check if WebView is actually usable (Edge WebView2 installed on Windows)"""
    if not WEBVIEW_AVAILABLE:
        return False
    
    # On Windows, check if Edge WebView2 is installed
    if os_is_windows():
        try:
            # Try to detect WebView2 runtime
            import winreg
            key_path = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                return True
            except FileNotFoundError:
                # Try alternative location
                key_path = r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                return True
        except:
            return False
    
    # On Linux/Mac, assume it's available if imported successfully
    return True


def start_flask():
    """Start Flask server in a separate thread"""
    # Suppress Flask startup messages
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None
    
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)


def open_browser():
    """Fallback: Open browser if WebView is not available"""
    time.sleep(2)
    webbrowser.open('http://localhost:5000')


if __name__ == '__main__':
    print(f"\n{BANNER}")
    platform_info = "Windows" if os_is_windows() else "Linux" if os_is_linux() else "Cross-Platform"
    print(f"Written by @flashnuke | {platform_info} Version")
    print(DELIM)
    
    if not is_admin():
        print(f"{RED}[!]{WHITE} This tool requires administrator privileges!")
        print(f"{YELLOW}[!]{WHITE} Please run as administrator")
        input("Press Enter to exit...")
        exit(1)
    
    print(f"{GREEN}[+]{WHITE} Starting DeadNet Attacker...")
    
    # Check WebView availability
    use_webview = check_webview_available()
    
    if use_webview:
        print(f"{BLUE}[*]{WHITE} Initializing WebView interface...")
    else:
        print(f"{YELLOW}[!]{WHITE} WebView not available (Edge WebView2 not installed)")
        print(f"{BLUE}[*]{WHITE} Falling back to browser mode...")
    
    print(DELIM)
    print(f"\n{YELLOW}{'!' * 49}{WHITE}")
    print(f"{YELLOW}WARNING: This tool is for authorized penetration testing ONLY!")
    print(f"Unauthorized network attacks are ILLEGAL and UNETHICAL.")
    print(f"Use responsibly and only on networks you own or have permission to test.{WHITE}")
    print(f"{YELLOW}{'!' * 49}{WHITE}\n")
    
    # Start Flask in background thread
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    
    # Wait a bit for Flask to start
    time.sleep(2)
    
    if use_webview:
        # WebView mode
        print(f"{GREEN}[+]{WHITE} Opening control panel (WebView)...")
        webview.create_window(
            'DeadNet Attacker - Control Panel',
            'http://127.0.0.1:5000',
            width=1200,
            height=800,
            resizable=True,
            min_size=(800, 600)
        )
        
        # Hide console after GUI is ready (only for exe builds)
        if getattr(sys, 'frozen', False):
            # Small delay to ensure window is visible before hiding console
            threading.Timer(1.5, hide_console).start()
        
        webview.start()
    else:
        # Browser fallback mode
        print(f"{GREEN}[+]{WHITE} Opening control panel (Browser)...")
        print(f"{BLUE}[*]{WHITE} Server started at http://localhost:5000")
        print(f"{YELLOW}[!]{WHITE} Browser should open automatically...")
        print(f"{YELLOW}[!]{WHITE} If not, manually open: http://localhost:5000")
        print(f"\n{RED}[!]{WHITE} Press Ctrl+C to stop the server\n")
        
        # Open browser
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{RED}[-]{WHITE} Shutting down...")
            exit(0)
