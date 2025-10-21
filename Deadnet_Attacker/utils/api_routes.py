"""
DeadNet Attacker - Flask API Routes
"""

import time
import threading
from flask import render_template, jsonify, request

from .network_utils import get_network_interfaces
from .attacker import DeadNetAttacker
from .defines import RED, WHITE


def setup_routes(app, attack_state, attack_lock):
    """Setup all Flask API routes"""
    
    # Global variables for attack management
    attack_thread = None
    current_attacker = None
    
    @app.route('/')
    def index():
        """Serve the web control panel"""
        return render_template('index.html')
    
    @app.route('/api/status', methods=['GET'])
    def get_status():
        """Get current attack status"""
        with attack_lock:
            status = {
                'active': attack_state['active'],
                'mode': attack_state['mode'],
                'interface': attack_state['interface'],
                'attacks_enabled': attack_state['attacks_enabled'].copy(),
                'statistics': attack_state['statistics'].copy(),
                'network_info': attack_state['network_info'].copy()
            }
        return jsonify(status)
    
    @app.route('/api/logs', methods=['GET'])
    def get_logs():
        """Get recent log entries"""
        limit = request.args.get('limit', 50, type=int)
        with attack_lock:
            logs = attack_state['logs'][-limit:]
        return jsonify({'logs': logs})
    
    @app.route('/api/interfaces', methods=['GET'])
    def get_interfaces():
        """Get available network interfaces"""
        interfaces = get_network_interfaces()
        return jsonify({'interfaces': interfaces})
    
    @app.route('/api/start', methods=['POST'])
    def start_attack():
        """Start the attack"""
        nonlocal attack_thread, current_attacker
        
        data = request.json
        iface = data.get('interface')
        mode = data.get('mode', 'local')
        cidrlen = data.get('cidrlen', 24)
        interval = data.get('interval', 5)
        disable_ipv6 = not data.get('enable_ipv6', True)
        fake_ip = data.get('fake_ip')
        target_ips_str = data.get('target_ips', '')
        
        target_ips = None
        if target_ips_str and target_ips_str.strip():
            target_ips = [ip.strip() for ip in target_ips_str.split(',') if ip.strip()]
        
        if not iface:
            return jsonify({'success': False, 'error': 'Interface required'}), 400
        
        with attack_lock:
            if attack_state['active']:
                return jsonify({'success': False, 'error': 'Attack already running'}), 400
            
            attack_state['active'] = True
            attack_state['mode'] = mode
            attack_state['interface'] = iface
            attack_state['statistics'] = {
                'cycles': 0,
                'packets_sent': 0,
                'start_time': None,
                'last_cycle_duration': 0
            }
            attack_state['logs'] = []
        
        def run_attack():
            nonlocal current_attacker
            try:
                current_attacker = DeadNetAttacker(
                    iface=iface,
                    cidrlen=cidrlen,
                    interval=interval,
                    gateway_ipv4=None,
                    gateway_mac=None,
                    disable_ipv6=disable_ipv6,
                    ipv6_preflen=64,
                    mode=mode,
                    fake_ip=fake_ip,
                    target_ips=target_ips,
                    attack_state=attack_state,
                    attack_lock=attack_lock
                )
                
                with attack_lock:
                    attack_state['network_info'] = {
                        'interface': current_attacker.network_interface,
                        'ip': current_attacker.user_ipv4,
                        'user_ipv4': current_attacker.user_ipv4,
                        'gateway': current_attacker.gateway_ipv4,
                        'gateway_ipv4': current_attacker.gateway_ipv4,
                        'gateway_mac': current_attacker.gateway_mac,
                        'mac': current_attacker.gateway_mac,
                        'subnet': current_attacker.subnet_ipv4_sr,
                        'target_hosts': len(current_attacker.host_ipv4s),
                        'fake_ip': current_attacker.fake_ip
                    }
                
                current_attacker.start_attack()
            except Exception as e:
                with attack_lock:
                    attack_state['active'] = False
                    attack_state['logs'].append({
                        'timestamp': time.time(),
                        'message': f"{RED}[!]{WHITE} Error: {str(e)}"
                    })
            finally:
                with attack_lock:
                    attack_state['active'] = False
        
        attack_thread = threading.Thread(target=run_attack, daemon=True)
        attack_thread.start()
        
        return jsonify({'success': True, 'message': 'Attack started'})
    
    @app.route('/api/stop', methods=['POST'])
    def stop_attack():
        """Stop the attack"""
        nonlocal current_attacker
        
        with attack_lock:
            if not attack_state['active']:
                return jsonify({'success': False, 'error': 'No attack running'}), 400
            
            attack_state['active'] = False
        
        if current_attacker:
            current_attacker.stop()
            current_attacker = None
        
        return jsonify({'success': True, 'message': 'Attack stopped'})
    
    @app.route('/api/toggle_attack', methods=['POST'])
    def toggle_attack():
        """Toggle specific attack type"""
        data = request.json
        attack_type = data.get('attack_type')
        enabled = data.get('enabled', True)
        
        if attack_type not in attack_state['attacks_enabled']:
            return jsonify({'success': False, 'error': 'Invalid attack type'}), 400
        
        with attack_lock:
            attack_state['attacks_enabled'][attack_type] = enabled
        
        return jsonify({'success': True, 'message': f'Attack {attack_type} {"enabled" if enabled else "disabled"}'})
