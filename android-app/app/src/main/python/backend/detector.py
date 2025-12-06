"""
Packet Detection Engine for DeadNet Defender
"""

try:
    from scapy.all import ARP, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, Ether, get_if_hwaddr
except ImportError:
    ARP = None
    IPv6 = None
    ICMPv6ND_RA = None
    ICMPv6NDOptPrefixInfo = None
    Ether = None
    get_if_hwaddr = lambda x: None

from collections import defaultdict
import time


class PacketDetector:
    """Advanced packet detector for network security monitoring"""
    
    def __init__(self, interface):
        self.interface = interface
        self.arp_table = {}
        self.mac_to_ip = defaultdict(set)
        self.packet_counts = defaultdict(int)
        self.ipv6_routers = {}
        self.suspicious_activity = defaultdict(list)
        
        try:
            self.own_mac = get_if_hwaddr(interface)
        except:
            self.own_mac = None
        
        print(f"[+] Detector initialized for interface: {interface}")
    
    def analyze_packet(self, packet):
        """Main packet analysis function"""
        results = {
            'suspicious': False,
            'detections': []
        }
        
        if packet.haslayer(ARP):
            arp_results = self._analyze_arp(packet)
            if arp_results:
                results['suspicious'] = True
                results['detections'].extend(arp_results)
        
        if packet.haslayer(IPv6):
            ipv6_results = self._analyze_ipv6(packet)
            if ipv6_results:
                results['suspicious'] = True
                results['detections'].extend(ipv6_results)
        
        return results
    
    def _analyze_arp(self, packet):
        """Analyze ARP packets for suspicious activity"""
        detections = []
        
        arp = packet[ARP]
        op = arp.op
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        dst_mac = arp.hwdst
        
        if src_mac == self.own_mac:
            return detections
        
        # Detection 1: ARP Reply with broadcast destination
        if op == 2 and dst_mac == "ff:ff:ff:ff:ff:ff":
            detections.append({
                'type': 'ARP_BROADCAST_REPLY',
                'severity': 'high',
                'message': 'ARP reply sent to broadcast address (potential poisoning)',
                'ip': src_ip,
                'mac': src_mac,
                'details': {'target_ip': dst_ip, 'operation': 'reply'}
            })
        
        # Detection 2: ARP spoofing - IP address changes MAC
        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                detections.append({
                    'type': 'ARP_SPOOFING',
                    'severity': 'critical',
                    'message': f'ARP spoofing detected: IP {src_ip} changed MAC from {self.arp_table[src_ip]} to {src_mac}',
                    'ip': src_ip,
                    'mac': src_mac,
                    'details': {'old_mac': self.arp_table[src_ip], 'new_mac': src_mac}
                })
        else:
            self.arp_table[src_ip] = src_mac
        
        # Detection 3: One MAC claims multiple IPs
        self.mac_to_ip[src_mac].add(src_ip)
        if len(self.mac_to_ip[src_mac]) > 5:
            detections.append({
                'type': 'MAC_MULTI_IP',
                'severity': 'high',
                'message': f'MAC {src_mac} claims {len(self.mac_to_ip[src_mac])} different IP addresses',
                'mac': src_mac,
                'details': {'ip_count': len(self.mac_to_ip[src_mac]), 'ips': list(self.mac_to_ip[src_mac])}
            })
        
        # Detection 4: Gratuitous ARP flood
        if op == 2 and src_ip == dst_ip:
            key = f"garp_{src_mac}"
            self.packet_counts[key] += 1
            
            if self.packet_counts[key] > 10:
                detections.append({
                    'type': 'ARP_FLOOD',
                    'severity': 'medium',
                    'message': f'Excessive gratuitous ARP packets from {src_mac}',
                    'ip': src_ip,
                    'mac': src_mac,
                    'details': {'packet_count': self.packet_counts[key]}
                })
                self.packet_counts[key] = 0
        
        # Detection 5: Invalid MAC address
        if src_mac in ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']:
            detections.append({
                'type': 'INVALID_MAC',
                'severity': 'medium',
                'message': f'ARP packet with invalid source MAC: {src_mac}',
                'ip': src_ip,
                'mac': src_mac,
                'details': {'invalid_type': 'zero' if src_mac == '00:00:00:00:00:00' else 'broadcast'}
            })
        
        # Detection 6: Random MAC pattern detection
        if len(src_mac) >= 2:
            second_char = src_mac[1].lower()
            if second_char in ['2', '6', 'a', 'e'] and op == 2:
                key = f"random_mac_{src_mac}"
                current_time = time.time()
                self.suspicious_activity[key].append(current_time)
                
                self.suspicious_activity[key] = [
                    t for t in self.suspicious_activity[key] 
                    if current_time - t < 60
                ]
                
                if len(self.suspicious_activity[key]) > 3:
                    detections.append({
                        'type': 'RANDOM_MAC_ACTIVITY',
                        'severity': 'high',
                        'message': f'Suspicious activity from randomly generated MAC: {src_mac}',
                        'ip': src_ip,
                        'mac': src_mac,
                        'details': {'packet_count': len(self.suspicious_activity[key])}
                    })
        
        return detections
    
    def _analyze_ipv6(self, packet):
        """Analyze IPv6 packets for suspicious activity"""
        detections = []
        
        if packet.haslayer(ICMPv6ND_RA):
            ra = packet[ICMPv6ND_RA]
            ipv6 = packet[IPv6]
            src_ip = ipv6.src
            
            src_mac = None
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
            
            if src_mac == self.own_mac:
                return detections
            
            # Detection 1: Router lifetime set to 0 (Dead Router Attack)
            if ra.routerlifetime == 0:
                detections.append({
                    'type': 'IPV6_DEAD_ROUTER',
                    'severity': 'critical',
                    'message': 'IPv6 Router Advertisement with lifetime 0 detected (Dead Router Attack)',
                    'ip': src_ip,
                    'mac': src_mac,
                    'details': {'router_lifetime': 0, 'attack_type': 'dead_router'}
                })
            
            # Detection 2: RA spoofing
            if src_ip in self.ipv6_routers:
                if self.ipv6_routers[src_ip] != src_mac:
                    detections.append({
                        'type': 'IPV6_RA_SPOOFING',
                        'severity': 'critical',
                        'message': f'IPv6 RA spoofing: Router {src_ip} changed MAC address',
                        'ip': src_ip,
                        'mac': src_mac,
                        'details': {'old_mac': self.ipv6_routers[src_ip], 'new_mac': src_mac}
                    })
            else:
                self.ipv6_routers[src_ip] = src_mac
            
            # Detection 3: RA flood detection
            key = f"ra_flood_{src_mac}"
            current_time = time.time()
            self.suspicious_activity[key].append(current_time)
            
            self.suspicious_activity[key] = [
                t for t in self.suspicious_activity[key] 
                if current_time - t < 60
            ]
            
            if len(self.suspicious_activity[key]) > 5:
                detections.append({
                    'type': 'IPV6_RA_FLOOD',
                    'severity': 'high',
                    'message': f'Excessive IPv6 Router Advertisements from {src_mac}',
                    'ip': src_ip,
                    'mac': src_mac,
                    'details': {'ra_count': len(self.suspicious_activity[key])}
                })
            
            # Detection 4: Suspicious prefix
            if packet.haslayer(ICMPv6NDOptPrefixInfo):
                prefix_info = packet[ICMPv6NDOptPrefixInfo]
                if prefix_info.prefix.startswith('fe80::'):
                    detections.append({
                        'type': 'IPV6_SUSPICIOUS_PREFIX',
                        'severity': 'medium',
                        'message': 'Router Advertisement with link-local prefix detected',
                        'ip': src_ip,
                        'mac': src_mac,
                        'details': {'prefix': prefix_info.prefix, 'prefixlen': prefix_info.prefixlen}
                    })
        
        return detections
    
    def get_statistics(self):
        """Get detector statistics"""
        return {
            'arp_table_size': len(self.arp_table),
            'tracked_macs': len(self.mac_to_ip),
            'ipv6_routers': len(self.ipv6_routers)
        }
