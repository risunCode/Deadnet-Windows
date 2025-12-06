#!/usr/bin/env python3
"""
DeadNet - Network Security Testing & Defense Tool
Unified Backend Server with CLI options
"""

import argparse
import logging
import threading
import time
import os
import sys
import webbrowser
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Determine if running as frozen exe
IS_FROZEN = getattr(sys, 'frozen', False)

if IS_FROZEN:
    # PyInstaller extracts to temp folder, use _MEIPASS for bundled files
    BASE_DIR = sys._MEIPASS
    # For log file, use exe directory
    EXE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    EXE_DIR = BASE_DIR

# Setup logging to file for frozen exe (no console)
LOG_FILE = os.path.join(EXE_DIR, 'deadnet.log')
if IS_FROZEN:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(LOG_FILE, mode='w')]
    )
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger('DeadNet')

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import netifaces
    from scapy.all import *
    from backend.defines import *
    from backend.misc_utils import is_admin, os_is_windows
    from backend.network_utils import get_network_interfaces
    from backend.attacker import DeadNetAttacker
    from backend.detector import PacketDetector
    from backend.database import DefenderDatabase
except Exception as e:
    logger.error(f"Import error: {e}")
    if IS_FROZEN:
        # Show error dialog for frozen exe
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, f"Failed to load modules:\n{e}", "DeadNet Error", 0x10)
        except:
            pass
    sys.exit(1)

conf.verb = 0

DIST_DIR = os.path.join(BASE_DIR, 'dist')

app = Flask(__name__, static_folder=DIST_DIR, static_url_path='')
CORS(app)

# Attacker State
attack_state = {
    'active': False, 'mode': None, 'interface': None,
    'attacks_enabled': {'arp_poison': True, 'ipv6_ra': True, 'dead_router': True},
    'statistics': {'cycles': 0, 'packets_sent': 0, 'start_time': None, 'last_cycle_duration': 0},
    'network_info': {}, 'logs': []
}
attack_lock = threading.Lock()
current_attacker = None

# Defender State
monitor_state = {
    'active': False, 'interface': None, 'start_time': None,
    'statistics': {
        'total_packets': 0, 'suspicious_packets': 0, 'flagged_ips': 0,
        'flagged_macs': 0, 'arp_packets': 0, 'ipv6_packets': 0,
        'suspicious_arp': 0, 'suspicious_ipv6': 0
    },
    'recent_alerts': []
}
monitor_lock = threading.Lock()
sniffer = None
detector = None
db = DefenderDatabase()


# Static Files
@app.route('/')
def index():
    return send_from_directory(DIST_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(DIST_DIR, path)

# Attacker API
@app.route('/api/status', methods=['GET'])
def get_attack_status():
    with attack_lock:
        return jsonify({
            'active': attack_state['active'], 'mode': attack_state['mode'],
            'interface': attack_state['interface'],
            'attacks_enabled': attack_state['attacks_enabled'].copy(),
            'statistics': attack_state['statistics'].copy(),
            'network_info': attack_state['network_info'].copy()
        })

@app.route('/api/logs', methods=['GET'])
def get_attack_logs():
    limit = request.args.get('limit', 50, type=int)
    with attack_lock:
        return jsonify({'logs': attack_state['logs'][-limit:]})

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    return jsonify({'interfaces': get_network_interfaces()})

@app.route('/api/start', methods=['POST'])
def start_attack():
    global current_attacker
    data = request.json
    iface = data.get('interface')
    
    if not iface:
        return jsonify({'success': False, 'error': 'Interface required'}), 400
    
    with attack_lock:
        if attack_state['active']:
            return jsonify({'success': False, 'error': 'Attack already running'}), 400
        attack_state['active'] = True
        attack_state['mode'] = data.get('mode', 'local')
        attack_state['interface'] = iface
        attack_state['statistics'] = {'cycles': 0, 'packets_sent': 0, 'start_time': None, 'last_cycle_duration': 0}
        attack_state['logs'] = []
    
    target_ips = None
    target_ips_str = data.get('target_ips') or ''
    if target_ips_str and target_ips_str.strip():
        target_ips = [ip.strip() for ip in target_ips_str.split(',') if ip.strip()]
        logger.info(f"Target IPs parsed: {target_ips}")
    
    def run_attack():
        global current_attacker
        try:
            current_attacker = DeadNetAttacker(
                iface=iface, cidrlen=data.get('cidrlen', 24),
                interval=data.get('interval', 5), gateway_ipv4=None, gateway_mac=None,
                disable_ipv6=not data.get('enable_ipv6', True), ipv6_preflen=64,
                mode=data.get('mode', 'local'), fake_ip=data.get('fake_ip'),
                target_ips=target_ips, attack_state=attack_state, attack_lock=attack_lock
            )
            with attack_lock:
                attack_state['network_info'] = {
                    'interface': current_attacker.network_interface,
                    'ip': current_attacker.user_ipv4,
                    'gateway': current_attacker.gateway_ipv4,
                    'gateway_mac': current_attacker.gateway_mac,
                    'subnet': current_attacker.subnet_ipv4_sr,
                    'target_hosts': len(current_attacker.host_ipv4s)
                }
            current_attacker.start_attack()
        except Exception as e:
            with attack_lock:
                attack_state['logs'].append({'timestamp': time.time(), 'message': f"[!] Error: {e}"})
        finally:
            with attack_lock:
                attack_state['active'] = False
    
    threading.Thread(target=run_attack, daemon=True).start()
    return jsonify({'success': True, 'message': 'Attack started'})

@app.route('/api/stop', methods=['POST'])
def stop_attack():
    global current_attacker
    with attack_lock:
        if not attack_state['active']:
            return jsonify({'success': False, 'error': 'No attack running'}), 400
        attack_state['active'] = False
    if current_attacker:
        current_attacker.stop()
        current_attacker = None
    return jsonify({'success': True, 'message': 'Attack stopped'})


# Defender API
def add_alert(alert_type, severity, message, ip=None, mac=None, details=None):
    alert = {'timestamp': datetime.now().isoformat(), 'type': alert_type, 'severity': severity,
             'message': message, 'ip': ip, 'mac': mac, 'details': details or {}}
    with monitor_lock:
        monitor_state['recent_alerts'].insert(0, alert)
        if len(monitor_state['recent_alerts']) > 100:
            monitor_state['recent_alerts'] = monitor_state['recent_alerts'][:100]
    db.add_alert(alert)
    if ip:
        db.flag_ip(ip, alert_type, severity, message)
        with monitor_lock:
            monitor_state['statistics']['flagged_ips'] = db.get_flagged_count('ip')
    if mac:
        db.flag_mac(mac, alert_type, severity, message)
        with monitor_lock:
            monitor_state['statistics']['flagged_macs'] = db.get_flagged_count('mac')

def packet_callback(packet):
    global detector
    try:
        with monitor_lock:
            monitor_state['statistics']['total_packets'] += 1
        results = detector.analyze_packet(packet)
        if results['suspicious']:
            with monitor_lock:
                monitor_state['statistics']['suspicious_packets'] += 1
            for d in results['detections']:
                add_alert(d['type'], d['severity'], d['message'], d.get('ip'), d.get('mac'), d.get('details'))
                with monitor_lock:
                    if 'ARP' in d['type']:
                        monitor_state['statistics']['suspicious_arp'] += 1
                    elif 'IPv6' in d['type']:
                        monitor_state['statistics']['suspicious_ipv6'] += 1
        if packet.haslayer(ARP):
            with monitor_lock:
                monitor_state['statistics']['arp_packets'] += 1
        if packet.haslayer(IPv6):
            with monitor_lock:
                monitor_state['statistics']['ipv6_packets'] += 1
    except Exception as e:
        print(f"Packet error: {e}")

def start_monitoring(interface):
    global detector, sniffer
    detector = PacketDetector(interface)
    with monitor_lock:
        monitor_state['active'] = True
        monitor_state['interface'] = interface
        monitor_state['start_time'] = time.time()
    try:
        sniffer = AsyncSniffer(iface=interface, prn=packet_callback, store=False)
        sniffer.start()
        while monitor_state['active']:
            time.sleep(0.1)
        if sniffer:
            sniffer.stop()
    except Exception as e:
        print(f"Monitor error: {e}")
        with monitor_lock:
            monitor_state['active'] = False

@app.route('/api/defender/status', methods=['GET'])
def get_defender_status():
    with monitor_lock:
        return jsonify({
            'active': monitor_state['active'], 'interface': monitor_state['interface'],
            'start_time': monitor_state['start_time'],
            'statistics': monitor_state['statistics'].copy(),
            'uptime': int(time.time() - monitor_state['start_time']) if monitor_state['start_time'] else 0
        })

@app.route('/api/defender/alerts', methods=['GET'])
def get_defender_alerts():
    limit = request.args.get('limit', 50, type=int)
    with monitor_lock:
        return jsonify({'alerts': monitor_state['recent_alerts'][:limit]})

@app.route('/api/defender/flagged', methods=['GET'])
def get_flagged():
    return jsonify({'ips': db.get_flagged_ips(), 'macs': db.get_flagged_macs()})

@app.route('/api/defender/start', methods=['POST'])
def start_defender():
    data = request.json
    iface = data.get('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'Interface required'}), 400
    with monitor_lock:
        if monitor_state['active']:
            return jsonify({'success': False, 'error': 'Already monitoring'}), 400
        monitor_state['statistics'] = {
            'total_packets': 0, 'suspicious_packets': 0, 'flagged_ips': 0,
            'flagged_macs': 0, 'arp_packets': 0, 'ipv6_packets': 0,
            'suspicious_arp': 0, 'suspicious_ipv6': 0
        }
        monitor_state['recent_alerts'] = []
    threading.Thread(target=start_monitoring, args=(iface,), daemon=True).start()
    return jsonify({'success': True, 'message': 'Monitoring started'})

@app.route('/api/defender/stop', methods=['POST'])
def stop_defender():
    global sniffer
    with monitor_lock:
        if not monitor_state['active']:
            return jsonify({'success': False, 'error': 'Not monitoring'}), 400
        monitor_state['active'] = False
    if sniffer and sniffer.running:
        try:
            sniffer.stop()
        except:
            pass
    return jsonify({'success': True, 'message': 'Monitoring stopped'})

@app.route('/api/defender/unflag', methods=['POST'])
def unflag_address():
    data = request.json
    addr_type, address = data.get('type'), data.get('address')
    if not addr_type or not address:
        return jsonify({'success': False, 'error': 'Type and address required'}), 400
    if addr_type == 'ip':
        db.unflag_ip(address)
    elif addr_type == 'mac':
        db.unflag_mac(address)
    with monitor_lock:
        monitor_state['statistics']['flagged_ips'] = db.get_flagged_count('ip')
        monitor_state['statistics']['flagged_macs'] = db.get_flagged_count('mac')
    return jsonify({'success': True})

@app.route('/api/defender/clear_flags', methods=['POST'])
def clear_flags():
    db.clear_all_flags()
    with monitor_lock:
        monitor_state['statistics']['flagged_ips'] = 0
        monitor_state['statistics']['flagged_macs'] = 0
    return jsonify({'success': True})

@app.route('/api/minimize', methods=['POST'])
def minimize_window():
    """Minimize window to taskbar"""
    global webview_window
    if webview_window:
        try:
            webview_window.minimize()
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return jsonify({'success': False, 'error': 'Not in WebView mode'})

@app.route('/api/shutdown', methods=['POST'])
def shutdown_app():
    """Panic exit - stop everything and shutdown"""
    global current_attacker, sniffer
    
    # Stop attacker
    with attack_lock:
        attack_state['active'] = False
    if current_attacker:
        try:
            current_attacker.stop()
        except:
            pass
        current_attacker = None
    
    # Stop defender
    with monitor_lock:
        monitor_state['active'] = False
    if sniffer and sniffer.running:
        try:
            sniffer.stop()
        except:
            pass
    
    # Schedule shutdown
    def do_shutdown():
        time.sleep(0.5)
        os._exit(0)
    
    threading.Thread(target=do_shutdown, daemon=True).start()
    return jsonify({'success': True, 'message': 'Shutting down'})

# Main Entry Point
def run_browser_mode(port, no_open):
    print(f"{GREEN}[+]{WHITE} Server: http://localhost:{port}")
    if not no_open:
        def open_browser():
            time.sleep(1.5)
            webbrowser.open(f'http://localhost:{port}')
        threading.Thread(target=open_browser, daemon=True).start()
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

webview_window = None

def run_webview_mode(port):
    global webview_window
    try:
        import webview
    except ImportError:
        print(f"{RED}[!]{WHITE} pywebview not installed. Falling back to browser...")
        run_browser_mode(port, False)
        return
    
    print(f"{GREEN}[+]{WHITE} Starting WebView...")
    threading.Thread(target=lambda: app.run(host='127.0.0.1', port=port, debug=False, threaded=True), daemon=True).start()
    time.sleep(1.5)
    webview_window = webview.create_window('DeadNet', f'http://127.0.0.1:{port}', width=1100, height=700, resizable=True, min_size=(900, 600))
    webview.start()

def show_error(message):
    """Show error message - dialog for frozen, print for console"""
    logger.error(message)
    if IS_FROZEN:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, "DeadNet Error", 0x10)
        except:
            pass
    else:
        print(f"{RED}[!]{WHITE} {message}")

def main():
    try:
        parser = argparse.ArgumentParser(description='DeadNet - Network Security Tool')
        parser.add_argument('--browser', '-b', action='store_true', help='Browser mode')
        parser.add_argument('--webview', '-w', action='store_true', help='WebView mode')
        parser.add_argument('--port', '-p', type=int, default=5000, help='Port (default: 5000)')
        parser.add_argument('--no-open', action='store_true', help='Don\'t auto-open browser')
        args = parser.parse_args()
        
        logger.info("DeadNet starting...")
        
        if not IS_FROZEN:
            print(f"\n{BANNER}")
            print("DeadNet - Network Security Testing & Defense Tool")
            print("=" * 60)
        
        if not is_admin():
            show_error("Administrator privileges required!\nPlease run as administrator.")
            sys.exit(1)
        
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        sys.modules['flask.cli'].show_server_banner = lambda *x: None
        
        if args.browser and args.webview:
            show_error("Cannot use both --browser and --webview")
            sys.exit(1)
        
        # Check dist folder exists
        if not os.path.exists(os.path.join(DIST_DIR, 'index.html')):
            show_error(f"Web assets not found in: {DIST_DIR}\nRun 'npm run build' first.")
            sys.exit(1)
        
        mode = 'browser' if args.browser else ('webview' if args.webview else ('webview' if os_is_windows() else 'browser'))
        logger.info(f"Mode: {mode.upper()} | Port: {args.port}")
        
        if not IS_FROZEN:
            print(f"{BLUE}[*]{WHITE} Mode: {mode.upper()} | Port: {args.port}")
            print("=" * 60 + "\n")
        
        if mode == 'webview':
            run_webview_mode(args.port)
        else:
            run_browser_mode(args.port, args.no_open)
            
    except Exception as e:
        logger.exception("Fatal error")
        show_error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
