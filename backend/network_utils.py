"""
DeadNet - Network Utilities
"""

import subprocess
import ipaddress
import netifaces
from scapy.all import *
from .misc_utils import os_is_windows


def get_wifi_info():
    """Get WiFi connection info (Windows)"""
    wifi_info = {}
    if not os_is_windows():
        return wifi_info
    
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                              capture_output=True, text=True, timeout=5)
        output = result.stdout
        
        for line in output.split('\n'):
            line = line.strip()
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip().lower()
                value = value.strip()
                
                if 'ssid' in key and 'bssid' not in key:
                    wifi_info['ssid'] = value
                elif 'bssid' in key:
                    wifi_info['bssid'] = value
                elif 'radio type' in key or 'tipo de rádio' in key:
                    wifi_info['radio_type'] = value  # e.g., 802.11ax, 802.11ac
                elif 'band' in key or 'banda' in key:
                    wifi_info['band'] = value  # e.g., 2.4 GHz, 5 GHz
                elif 'channel' in key or 'canal' in key:
                    wifi_info['channel'] = value
                elif 'receive rate' in key or 'taxa de recepção' in key:
                    wifi_info['rx_rate'] = value
                elif 'transmit rate' in key or 'taxa de transmissão' in key:
                    wifi_info['tx_rate'] = value
                elif 'signal' in key or 'sinal' in key:
                    wifi_info['signal'] = value
                elif 'authentication' in key or 'autenticação' in key:
                    wifi_info['auth'] = value
    except:
        pass
    
    return wifi_info


def get_network_interfaces():
    """Get all available network interfaces"""
    try:
        interfaces = netifaces.interfaces()
        interface_details = []
        
        # Get WiFi info once
        wifi_info = get_wifi_info()
        
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            ipv4 = None
            mac = None
            subnet = None
            
            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0].get('addr')
                subnet = addrs[netifaces.AF_INET][0].get('netmask')
            
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0].get('addr')
            elif hasattr(netifaces, 'AF_PACKET') and netifaces.AF_PACKET in addrs:
                mac = addrs[netifaces.AF_PACKET][0].get('addr')
            
            if ipv4 and ipv4 != '127.0.0.1' and not ipv4.startswith('169.254.'):
                gateway = get_gateway_ipv4(iface)
                
                iface_data = {
                    'name': iface,
                    'ip': ipv4,
                    'ipv4': ipv4,
                    'mac': mac,
                    'subnet': subnet,
                    'gateway': gateway,
                    'friendly_name': iface,
                    'wifi': None
                }
                
                # Check if this is WiFi interface (has WiFi info)
                if wifi_info and ('wi-fi' in iface.lower() or 'wlan' in iface.lower() or 'wireless' in iface.lower()):
                    iface_data['wifi'] = wifi_info
                    iface_data['type'] = 'wifi'
                else:
                    iface_data['type'] = 'ethernet'
                
                interface_details.append(iface_data)
        
        return interface_details
    except Exception as e:
        return []


def get_gateway_ipv4(iface):
    """Get gateway IPv4 address for interface"""
    # Method 1: Try netifaces
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][0]
        if netifaces.AF_INET in gateways:
            ipv4_gateways = gateways[netifaces.AF_INET]
            for ipv4_data in ipv4_gateways:
                if ipv4_data[1] == iface:
                    return ipv4_data[0]
    except Exception:
        pass
    
    # Method 2: Try scapy route table
    try:
        return [r[2] for r in conf.route.routes if r[3] == iface and r[2] != '0.0.0.0'][0]
    except Exception:
        pass
    
    # Method 3: Windows fallback
    if os_is_windows():
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            output = result.stdout
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if 'Default Gateway' in line or 'Gateway Padrão' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[1].strip()
                        gateway = gateway.split('%')[0].split(' ')[0]
                        if gateway and gateway != '' and '.' in gateway:
                            return gateway
        except Exception:
            pass
    
    return None


def get_gateway_mac_windows(gateway_ip):
    """Get gateway MAC address on Windows using arp -a"""
    try:
        result = subprocess.run(['arp', '-a', gateway_ip], 
                              capture_output=True, text=True, timeout=5)
        output = result.stdout.strip()
        
        for line in output.split('\n'):
            if gateway_ip in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == gateway_ip and i + 1 < len(parts):
                        mac = parts[i + 1]
                        mac = mac.replace('-', ':')
                        return mac
    except Exception:
        pass
    return None


def get_gateway_mac_linux(gateway_ip, iface):
    """Get gateway MAC address on Linux using ip neighbor"""
    try:
        result = subprocess.run(['ip', 'neighbor', 'show', 'default'], 
                              capture_output=True, text=True, timeout=5)
        output = result.stdout.strip()
        
        for line in output.split('\n'):
            columns = line.split()
            if len(columns) >= 4:
                if columns[3] == 'lladdr' and columns[4] != '<incomplete>' and \
                        columns[2] == iface:
                    return columns[4]
    except Exception:
        pass
    return None


def get_gateway_mac(gateway_ip, iface):
    """Get gateway MAC address (cross-platform)"""
    gateway_hwaddr = getmacbyip(gateway_ip)
    
    if not gateway_hwaddr:
        if os_is_windows():
            gateway_hwaddr = get_gateway_mac_windows(gateway_ip)
        else:
            gateway_hwaddr = get_gateway_mac_linux(gateway_ip, iface)
    
    return gateway_hwaddr


def generate_host_ips(subnet_cidr, exclude_ips):
    """Generate list of host IPs in subnet excluding specified IPs"""
    try:
        network = ipaddress.IPv4Network(subnet_cidr, strict=False)
        return [str(ip) for ip in network.hosts() if str(ip) not in exclude_ips]
    except Exception:
        return []


def ping_ipv6_subnet(iface):
    """Ping IPv6 subnet to discover hosts (Linux only)"""
    ipv6_hosts = []
    if os_is_windows():
        return ipv6_hosts
    
    try:
        IPV6_MULTIC_ADDR = "ff02::1"
        IPV6_LL_PREF = "fe80"
        
        ping_output = subprocess.check_output(
            ['ping6', '-I', iface, IPV6_MULTIC_ADDR, "-c", "3"], 
            stderr=subprocess.DEVNULL, 
            timeout=10
        ).decode()
        
        for line in ping_output.splitlines():
            s_idx = line.find(IPV6_LL_PREF)
            e_idx = line.find(f"%{iface}")
            if s_idx > 0 and e_idx > 0:
                host = line[s_idx:e_idx]
                if host not in ipv6_hosts:
                    ipv6_hosts.append(host)
    except Exception:
        pass
    
    return ipv6_hosts
