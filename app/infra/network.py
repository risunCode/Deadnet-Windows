import ipaddress
import subprocess
import sys
from typing import Any


def os_is_windows() -> bool:
    return sys.platform.startswith("win")


def get_wifi_info() -> dict[str, str]:
    info: dict[str, str] = {}
    if os_is_windows():
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                key, _, value = line.partition(":")
                if not value:
                    continue
                k = key.strip().lower()
                v = value.strip()
                if "ssid" in k and "bssid" not in k:
                    info["ssid"] = v
                elif "bssid" in k:
                    info["bssid"] = v
                elif "radio type" in k or "tipo de radio" in k:
                    info["radio_type"] = v
                elif "band" in k or "banda" in k:
                    info["band"] = v
                elif "channel" in k or "canal" in k:
                    info["channel"] = v
                elif "receive rate" in k or "taxa de recepcao" in k:
                    info["rx_rate"] = v
                elif "signal" in k or "sinal" in k:
                    info["signal"] = v
        except Exception:
            return {}
        return info

    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
    except Exception:
        return info
    for line in result.stdout.splitlines():
        if "ESSID:" in line:
            info["ssid"] = line.split("ESSID:")[1].strip().strip('"')
        elif "Frequency:" in line:
            info["band"] = line.split("Frequency:")[1].split()[0]
        elif "Signal level=" in line:
            info["signal"] = line.split("Signal level=")[1].split()[0]
    return info


def _netifaces() -> Any:
    try:
        import netifaces
    except Exception:
        return None
    return netifaces


def get_gateway_ipv4(iface: str) -> str | None:
    netifaces = _netifaces()
    if netifaces is not None:
        try:
            gateways = netifaces.gateways()
            if "default" in gateways and netifaces.AF_INET in gateways["default"]:
                return gateways["default"][netifaces.AF_INET][0]
            for gw in gateways.get(netifaces.AF_INET, []):
                if len(gw) >= 2 and gw[1] == iface:
                    return gw[0]
        except Exception:
            pass

    if os_is_windows():
        try:
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                if "Default Gateway" in line or "Gateway Padrao" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        gw = parts[1].strip().split("%")[0].split()[0]
                        if "." in gw:
                            return gw
        except Exception:
            return None
    return None


def get_gateway_mac(gateway_ip: str, iface: str) -> str | None:
    from app.infra.scapy_adapter import load_scapy

    try:
        scapy = load_scapy().mod
        mac = scapy.getmacbyip(gateway_ip)
        if mac:
            return mac
    except Exception:
        pass

    if os_is_windows():
        try:
            result = subprocess.run(["arp", "-a", gateway_ip], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                if gateway_ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].replace("-", ":")
        except Exception:
            return None
    else:
        try:
            result = subprocess.run(["ip", "neighbor", "show", "default"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                cols = line.split()
                if len(cols) >= 5 and cols[2] == iface and cols[3] == "lladdr":
                    return cols[4]
        except Exception:
            return None
    return None


def generate_host_ips(subnet_cidr: str, exclude_ips: list[str]) -> list[str]:
    try:
        network = ipaddress.IPv4Network(subnet_cidr, strict=False)
        return [str(ip) for ip in network.hosts() if str(ip) not in exclude_ips]
    except Exception:
        return []


def get_network_interfaces() -> list[dict[str, Any]]:
    netifaces = _netifaces()
    if netifaces is None:
        return []

    interfaces: list[dict[str, Any]] = []
    wifi = get_wifi_info()
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ipv4 = None
            mac = None
            subnet = None

            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0].get("addr")
                subnet = addrs[netifaces.AF_INET][0].get("netmask")

            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0].get("addr")
            elif hasattr(netifaces, "AF_PACKET") and netifaces.AF_PACKET in addrs:
                mac = addrs[netifaces.AF_PACKET][0].get("addr")

            if not ipv4 or ipv4 == "127.0.0.1" or ipv4.startswith("169.254."):
                continue

            iface_data = {
                "name": iface,
                "ip": ipv4,
                "ipv4": ipv4,
                "mac": mac,
                "subnet": subnet,
                "gateway": get_gateway_ipv4(iface),
                "friendly_name": iface,
                "wifi": None,
                "type": "ethernet",
            }

            lowered = iface.lower()
            if wifi and any(tag in lowered for tag in ("wi-fi", "wlan", "wireless")):
                iface_data["wifi"] = wifi
                iface_data["type"] = "wifi"

            interfaces.append(iface_data)
    except Exception:
        return []
    return interfaces
