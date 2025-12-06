"""
DeadNet Server API Routes
Registers all API endpoints to a Flask app
"""

import threading
import time
import logging

logger = logging.getLogger('DeadNet')

from flask import jsonify, request

# State
attack_state = {
    'active': False, 'mode': None, 'interface': None,
    'attacks_enabled': {'arp_poison': True, 'ipv6_ra': True, 'dead_router': True},
    'statistics': {'cycles': 0, 'packets_sent': 0, 'start_time': None, 'last_cycle_duration': 0},
    'network_info': {}, 'logs': []
}
attack_lock = threading.Lock()

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

# Globals
current_attacker = None
sniffer = None
detector = None
SCAPY_AVAILABLE = False
DeadNetAttacker = None
PacketDetector = None


def init_scapy():
    """Initialize scapy modules - call only when needed"""
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
        logger.info("Scapy initialized")
        return True
    except Exception as e:
        logger.warning(f"Scapy error: {e}")
        return False


def get_interfaces_list():
    """Get network interfaces - lazy import"""
    try:
        from backend.network_utils import get_network_interfaces
        return get_network_interfaces()
    except Exception as e:
        logger.error(f"Interface error: {e}")
        return []


def register_routes(app):
    """Register all API routes to the Flask app"""
    
    @app.route('/api/status')
    def api_status():
        with attack_lock:
            return jsonify({
                'active': attack_state['active'],
                'mode': attack_state['mode'],
                'interface': attack_state['interface'],
                'attacks_enabled': attack_state['attacks_enabled'].copy(),
                'statistics': attack_state['statistics'].copy(),
                'network_info': attack_state['network_info'].copy()
            })
    
    @app.route('/api/logs')
    def api_logs():
        limit = request.args.get('limit', 50, type=int)
        with attack_lock:
            return jsonify({'logs': attack_state['logs'][-limit:]})
    
    @app.route('/api/interfaces')
    def api_interfaces():
        return jsonify({'interfaces': get_interfaces_list()})
    
    @app.route('/api/start', methods=['POST'])
    def api_start():
        global current_attacker
        
        if not init_scapy():
            return jsonify({'success': False, 'error': 'Scapy not available - need root'}), 400
        
        data = request.json or {}
        iface = data.get('interface')
        if not iface:
            return jsonify({'success': False, 'error': 'Interface required'}), 400
        
        with attack_lock:
            if attack_state['active']:
                return jsonify({'success': False, 'error': 'Already running'}), 400
            attack_state['active'] = True
            attack_state['interface'] = iface
            attack_state['statistics'] = {'cycles': 0, 'packets_sent': 0, 'start_time': time.time(), 'last_cycle_duration': 0}
            attack_state['logs'] = []
        
        target_ips = None
        if data.get('target_ips'):
            target_ips = [ip.strip() for ip in data['target_ips'].split(',') if ip.strip()]
        
        def run():
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
                        'subnet': current_attacker.subnet_ipv4_sr,
                        'target_hosts': len(current_attacker.host_ipv4s)
                    }
                current_attacker.start_attack()
            except Exception as e:
                with attack_lock:
                    attack_state['logs'].append({'timestamp': time.time(), 'message': f"[!] {e}"})
            finally:
                with attack_lock:
                    attack_state['active'] = False
        
        threading.Thread(target=run, daemon=True).start()
        return jsonify({'success': True})
    
    @app.route('/api/stop', methods=['POST'])
    def api_stop():
        global current_attacker
        with attack_lock:
            attack_state['active'] = False
        if current_attacker:
            current_attacker.stop()
            current_attacker = None
        return jsonify({'success': True})
    
    # Defender routes
    @app.route('/api/defender/status')
    def api_def_status():
        with monitor_lock:
            return jsonify({
                'active': monitor_state['active'],
                'interface': monitor_state['interface'],
                'start_time': monitor_state['start_time'],
                'statistics': monitor_state['statistics'].copy(),
                'uptime': int(time.time() - monitor_state['start_time']) if monitor_state['start_time'] else 0
            })
    
    @app.route('/api/defender/alerts')
    def api_def_alerts():
        with monitor_lock:
            return jsonify({'alerts': monitor_state['recent_alerts'][:50]})
    
    @app.route('/api/defender/flagged')
    def api_def_flagged():
        return jsonify({'ips': {}, 'macs': {}})
    
    @app.route('/api/defender/start', methods=['POST'])
    def api_def_start():
        global detector, sniffer
        
        if not init_scapy():
            return jsonify({'success': False, 'error': 'Scapy not available'}), 400
        
        data = request.json or {}
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
        
        def run():
            global detector, sniffer
            try:
                from scapy.all import AsyncSniffer, ARP
                detector = PacketDetector(iface)
                
                def callback(pkt):
                    try:
                        with monitor_lock:
                            monitor_state['statistics']['total_packets'] += 1
                        res = detector.analyze_packet(pkt)
                        if res['suspicious']:
                            with monitor_lock:
                                monitor_state['statistics']['suspicious_packets'] += 1
                                for d in res['detections']:
                                    monitor_state['recent_alerts'].insert(0, {
                                        'timestamp': time.time(), 'type': d['type'],
                                        'severity': d['severity'], 'message': d['message'],
                                        'ip': d.get('ip'), 'mac': d.get('mac')
                                    })
                        if pkt.haslayer(ARP):
                            with monitor_lock:
                                monitor_state['statistics']['arp_packets'] += 1
                    except:
                        pass
                
                sniffer = AsyncSniffer(iface=iface, prn=callback, store=False)
                sniffer.start()
                while monitor_state['active']:
                    time.sleep(0.1)
                sniffer.stop()
            except Exception as e:
                logger.error(f"Monitor error: {e}")
            finally:
                with monitor_lock:
                    monitor_state['active'] = False
        
        threading.Thread(target=run, daemon=True).start()
        return jsonify({'success': True})
    
    @app.route('/api/defender/stop', methods=['POST'])
    def api_def_stop():
        global sniffer
        with monitor_lock:
            monitor_state['active'] = False
        if sniffer:
            try:
                sniffer.stop()
            except:
                pass
        return jsonify({'success': True})
    
    @app.route('/api/defender/clear_flags', methods=['POST'])
    def api_clear():
        return jsonify({'success': True})
    
    @app.route('/api/shutdown', methods=['POST'])
    def api_shutdown():
        global current_attacker, sniffer
        with attack_lock:
            attack_state['active'] = False
        if current_attacker:
            try:
                current_attacker.stop()
            except:
                pass
        with monitor_lock:
            monitor_state['active'] = False
        if sniffer:
            try:
                sniffer.stop()
            except:
                pass
        return jsonify({'success': True})
    
    logger.info("API routes registered")
