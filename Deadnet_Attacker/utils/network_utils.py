import subprocess
import ipaddress
import netifaces
from scapy.all import *
from .misc_utils import os_is_windows


def get_network_interfaces():
    """Get all available network interfaces"""
    try:
        interfaces = netifaces.interfaces()
        interface_details = []
        
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
            
            if ipv4 and ipv4 != '127.0.0.1':
                # Get gateway for this interface
                gateway = get_gateway_ipv4(iface)
                
                interface_details.append({
                    'name': iface,
                    'ip': ipv4,
                    'ipv4': ipv4,  # Keep for backward compatibility
                    'mac': mac,
                    'subnet': subnet,
                    'gateway': gateway,
                    'friendly_name': iface
                })
        
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
    
    # Method 3: Windows fallback - use ipconfig
    if os_is_windows():
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            output = result.stdout
            
            # Parse ipconfig output to find default gateway
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if 'Default Gateway' in line or 'Gateway Padrão' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[1].strip()
                        # Remove any extra info (like % zone id)
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
                        # Normalize MAC format
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
    # Try scapy first
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
