#!/usr/bin/env python3
"""
DeadNet - Network Security Testing Tool (Browser Version)
WARNING: This tool is for authorized penetration testing only.
Unauthorized use is illegal and unethical.
"""

import logging
import threading
import time
import webbrowser
from flask import Flask
from flask_cors import CORS

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from utils import *

conf.verb = 0

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
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


def start_flask():
    """Start Flask server in a separate thread"""
    # Suppress Flask startup messages
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    import sys
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)


def open_browser():
    """Open browser after a short delay"""
    time.sleep(2)
    webbrowser.open('http://localhost:5000')


if __name__ == '__main__':
    print(f"\n{BANNER}")
    print("Written by @flashnuke | Browser Version")
    print(DELIM)
    
    if not is_admin():
        print(f"{RED}[!]{WHITE} This tool requires administrator privileges!")
        print(f"{YELLOW}[!]{WHITE} Please run as administrator")
        input("Press Enter to exit...")
        exit(1)
    
    print(f"{GREEN}[+]{WHITE} Starting DeadNet Attacker...")
    print(f"{BLUE}[*]{WHITE} Opening browser control panel...")
    print(DELIM)
    print(f"\n{YELLOW}{'!' * 49}{WHITE}")
    print(f"{YELLOW}WARNING: This tool is for authorized penetration testing ONLY!")
    print(f"Unauthorized network attacks are ILLEGAL and UNETHICAL.")
    print(f"Use responsibly and only on networks you own or have permission to test.{WHITE}")
    print(f"{YELLOW}{'!' * 49}{WHITE}\n")
    
    # Start Flask in background thread
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    
    # Open browser
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    print(f"{GREEN}[+]{WHITE} Server started at http://localhost:5000")
    print(f"{BLUE}[*]{WHITE} Browser should open automatically...")
    print(f"{YELLOW}[!]{WHITE} If not, manually open: http://localhost:5000")
    print(f"\n{RED}[!]{WHITE} Press Ctrl+C to stop the server\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{RED}[-]{WHITE} Shutting down...")
        exit(0)
