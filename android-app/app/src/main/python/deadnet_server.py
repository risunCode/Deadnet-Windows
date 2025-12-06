"""
DeadNet Server for Android
Entry point that imports from backend modules
"""

import os
import sys
import threading
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DeadNet')

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Import backend modules
from backend.defines import *
from backend.misc_utils import is_admin, os_is_windows, get_ts_ms
from backend.network_utils import get_network_interfaces, get_gateway_ipv4, get_gateway_mac, generate_host_ips

# Lazy load scapy - don't import at top level to avoid permission errors
SCAPY_AVAILABLE = False
DeadNetAttacker = None
PacketDetector = None

def init_scapy():
    """Initialize scapy modules - call this only when needed"""
    global SCAPY_AVAILABLE, DeadNetAttacker, PacketDetector
    if SCAPY_AVAILABLE:
        return True
    try:
        from scapy.all import conf
        conf.verb = 0
        from backend.attacker import DeadNetAttacker as Attacker
        from backend.detector import PacketDetector as Detector
        DeadNetAttacker = Attacker
        PacketDetector = Detector
        SCAPY_AVAILABLE = True
        logger.info("Scapy initialized successfully")
        return True
    except Exception as e:
        logger.warning(f"Scapy not available: {e}")
        return False

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(SCRIPT_DIR, 'dist')

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

server_running = False


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
    
    # Lazy init scapy when attack starts
    if not init_scapy():
        return jsonify({'success': False, 'error': 'Scapy not available - need root access'}), 400
    
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
    return jsonify({'ips': {}, 'macs': {}})

@app.route('/api/defender/start', methods=['POST'])
def start_defender():
    global detector, sniffer
    
    # Lazy init scapy when defender starts
    if not init_scapy():
        return jsonify({'success': False, 'error': 'Scapy not available - need root access'}), 400
    
    data = request.json
    iface = data.get('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'Interface required'}), 400
    
    with monitor_lock:
        if monitor_state['active']:
            return jsonify({'success': False, 'error': 'Already monitoring'}), 400
        monitor_state['active'] = True
        monitor_state['interface'] = iface
        monitor_state['start_time'] = time.time()
        monitor_state['statistics'] = {
            'total_packets': 0, 'suspicious_packets': 0, 'flagged_ips': 0,
            'flagged_macs': 0, 'arp_packets': 0, 'ipv6_packets': 0,
            'suspicious_arp': 0, 'suspicious_ipv6': 0
        }
        monitor_state['recent_alerts'] = []
    
    def run_monitor():
        global detector, sniffer
        try:
            # Import scapy components here (lazy load)
            from scapy.all import AsyncSniffer, ARP
            
            detector = PacketDetector(iface)
            
            def packet_callback(packet):
                try:
                    with monitor_lock:
                        monitor_state['statistics']['total_packets'] += 1
                    results = detector.analyze_packet(packet)
                    if results['suspicious']:
                        with monitor_lock:
                            monitor_state['statistics']['suspicious_packets'] += 1
                            for d in results['detections']:
                                alert = {
                                    'timestamp': time.time(),
                                    'type': d['type'],
                                    'severity': d['severity'],
                                    'message': d['message'],
                                    'ip': d.get('ip'),
                                    'mac': d.get('mac')
                                }
                                monitor_state['recent_alerts'].insert(0, alert)
                                if len(monitor_state['recent_alerts']) > 100:
                                    monitor_state['recent_alerts'] = monitor_state['recent_alerts'][:100]
                    if packet.haslayer(ARP):
                        with monitor_lock:
                            monitor_state['statistics']['arp_packets'] += 1
                except Exception as e:
                    pass
            
            sniffer = AsyncSniffer(iface=iface, prn=packet_callback, store=False)
            sniffer.start()
            
            while monitor_state['active']:
                time.sleep(0.1)
            
            if sniffer:
                sniffer.stop()
        except Exception as e:
            logger.error(f"Monitor error: {e}")
        finally:
            with monitor_lock:
                monitor_state['active'] = False
    
    threading.Thread(target=run_monitor, daemon=True).start()
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

@app.route('/api/defender/clear_flags', methods=['POST'])
def clear_flags():
    return jsonify({'success': True})

@app.route('/api/shutdown', methods=['POST'])
def shutdown_app():
    global current_attacker, sniffer, server_running
    
    with attack_lock:
        attack_state['active'] = False
    if current_attacker:
        try:
            current_attacker.stop()
        except:
            pass
        current_attacker = None
    
    with monitor_lock:
        monitor_state['active'] = False
    if sniffer and sniffer.running:
        try:
            sniffer.stop()
        except:
            pass
    
    server_running = False
    return jsonify({'success': True, 'message': 'Shutting down'})


def start_server(port=5000):
    """Start the Flask server"""
    global server_running
    server_running = True
    logger.info(f"Starting DeadNet server on port {port}")
    logger.info(f"Serving static files from: {DIST_DIR}")
    
    # Try multiple ports if default fails
    ports_to_try = [port, 8080, 8000, 9000, 5050]
    
    for p in ports_to_try:
        try:
            logger.info(f"Trying port {p}...")
            app.run(host='127.0.0.1', port=p, debug=False, threaded=True, use_reloader=False)
            break
        except OSError as e:
            if "Address already in use" in str(e) or "Permission denied" in str(e):
                logger.warning(f"Port {p} failed: {e}")
                continue
            raise
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise


def stop_server():
    """Stop the server"""
    global server_running
    server_running = False
    logger.info("Server stopped")
