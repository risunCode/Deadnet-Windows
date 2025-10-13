import re
import sys
import time
import platform


def is_valid_mac(mac):
    """Check if MAC address is valid"""
    return re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac)


def mac2ipv6_ll(mac, pref):
    """Convert MAC address to IPv6 link-local address"""
    m = hex(int(mac.translate(str.maketrans('', '', ' .:-')), 16) ^ 0x020000000000)[2:]
    return f'{pref}::%s:%sff:fe%s:%s' % (m[:4], m[4:6], m[6:8], m[8:12])


def get_ts_ms():
    """Get current timestamp in milliseconds"""
    return int(time.time() * 1_000)


def os_is_linux():
    """Check if running on Linux"""
    return "linux" in sys.platform


def os_is_windows():
    """Check if running on Windows"""
    return sys.platform.startswith('win')


def is_admin():
    """Check if running with administrator privileges"""
    if os_is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        import os
        return os.geteuid() == 0


def get_platform_info():
    """Get platform information"""
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor()
    }
