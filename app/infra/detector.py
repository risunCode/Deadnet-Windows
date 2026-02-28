from __future__ import annotations

import time
from collections import defaultdict
from typing import Any


class PacketDetector:
    def __init__(self, interface: str):
        from app.infra.scapy_adapter import load_scapy

        self.scapy = load_scapy().mod
        self.interface = interface
        self.arp_table: dict[str, str] = {}
        self.mac_to_ip: defaultdict[str, set[str]] = defaultdict(set)
        self.packet_counts: defaultdict[str, int] = defaultdict(int)
        self.ipv6_routers: dict[str, str] = {}
        self.suspicious_activity: defaultdict[str, list[float]] = defaultdict(list)
        try:
            self.own_mac = self.scapy.get_if_hwaddr(interface)
        except Exception:
            self.own_mac = None

    def analyze_packet(self, packet: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"suspicious": False, "detections": []}
        if packet.haslayer(self.scapy.ARP):
            arp = self._analyze_arp(packet)
            if arp:
                out["suspicious"] = True
                out["detections"].extend(arp)
        if packet.haslayer(self.scapy.IPv6):
            ipv6 = self._analyze_ipv6(packet)
            if ipv6:
                out["suspicious"] = True
                out["detections"].extend(ipv6)
        return out

    def _analyze_arp(self, packet: Any) -> list[dict[str, Any]]:
        detections: list[dict[str, Any]] = []
        arp = packet[self.scapy.ARP]
        op = arp.op
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        dst_mac = arp.hwdst

        if src_mac == self.own_mac:
            return detections

        if op == 2 and dst_mac == "ff:ff:ff:ff:ff:ff":
            detections.append(
                {
                    "type": "ARP_BROADCAST_REPLY",
                    "severity": "high",
                    "message": "ARP reply sent to broadcast address (potential poisoning)",
                    "ip": src_ip,
                    "mac": src_mac,
                    "details": {"target_ip": dst_ip, "operation": "reply"},
                }
            )

        old_mac = self.arp_table.get(src_ip)
        if old_mac and old_mac != src_mac:
            detections.append(
                {
                    "type": "ARP_SPOOFING",
                    "severity": "critical",
                    "message": f"ARP spoofing detected: IP {src_ip} changed MAC from {old_mac} to {src_mac}",
                    "ip": src_ip,
                    "mac": src_mac,
                    "details": {"old_mac": old_mac, "new_mac": src_mac},
                }
            )
        else:
            self.arp_table[src_ip] = src_mac

        self.mac_to_ip[src_mac].add(src_ip)
        if len(self.mac_to_ip[src_mac]) > 5:
            detections.append(
                {
                    "type": "MAC_MULTI_IP",
                    "severity": "high",
                    "message": f"MAC {src_mac} claims {len(self.mac_to_ip[src_mac])} different IP addresses",
                    "mac": src_mac,
                    "details": {
                        "ip_count": len(self.mac_to_ip[src_mac]),
                        "ips": list(self.mac_to_ip[src_mac]),
                    },
                }
            )

        if op == 2 and src_ip == dst_ip:
            key = f"garp_{src_mac}"
            self.packet_counts[key] += 1
            if self.packet_counts[key] > 10:
                detections.append(
                    {
                        "type": "ARP_FLOOD",
                        "severity": "medium",
                        "message": f"Excessive gratuitous ARP packets from {src_mac}",
                        "ip": src_ip,
                        "mac": src_mac,
                        "details": {"packet_count": self.packet_counts[key]},
                    }
                )
                self.packet_counts[key] = 0

        if src_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            detections.append(
                {
                    "type": "INVALID_MAC",
                    "severity": "medium",
                    "message": f"ARP packet with invalid source MAC: {src_mac}",
                    "ip": src_ip,
                    "mac": src_mac,
                    "details": {"invalid_type": "zero" if src_mac.startswith("00") else "broadcast"},
                }
            )

        if len(src_mac) >= 2 and src_mac[1].lower() in ("2", "6", "a", "e") and op == 2:
            key = f"random_mac_{src_mac}"
            now = time.time()
            self.suspicious_activity[key].append(now)
            self.suspicious_activity[key] = [t for t in self.suspicious_activity[key] if now - t < 60]
            if len(self.suspicious_activity[key]) > 3:
                detections.append(
                    {
                        "type": "RANDOM_MAC_ACTIVITY",
                        "severity": "high",
                        "message": f"Suspicious activity from randomly generated MAC: {src_mac}",
                        "ip": src_ip,
                        "mac": src_mac,
                        "details": {"packet_count": len(self.suspicious_activity[key])},
                    }
                )

        return detections

    def _analyze_ipv6(self, packet: Any) -> list[dict[str, Any]]:
        detections: list[dict[str, Any]] = []

        if not packet.haslayer(self.scapy.ICMPv6ND_RA):
            return detections

        ra = packet[self.scapy.ICMPv6ND_RA]
        src_ip = packet[self.scapy.IPv6].src
        src_mac = packet[self.scapy.Ether].src if packet.haslayer(self.scapy.Ether) else None

        if src_mac == self.own_mac:
            return detections

        if ra.routerlifetime == 0:
            detections.append(
                {
                    "type": "IPV6_DEAD_ROUTER",
                    "severity": "critical",
                    "message": "IPv6 Router Advertisement with lifetime 0 detected (Dead Router Attack)",
                    "ip": src_ip,
                    "mac": src_mac,
                    "details": {"router_lifetime": 0, "attack_type": "dead_router"},
                }
            )

        old_mac = self.ipv6_routers.get(src_ip)
        if old_mac and old_mac != src_mac:
            detections.append(
                {
                    "type": "IPV6_RA_SPOOFING",
                    "severity": "critical",
                    "message": f"IPv6 RA spoofing: Router {src_ip} changed MAC address",
                    "ip": src_ip,
                    "mac": src_mac,
                    "details": {"old_mac": old_mac, "new_mac": src_mac},
                }
            )
        else:
            self.ipv6_routers[src_ip] = src_mac

        key = f"ra_flood_{src_mac}"
        now = time.time()
        self.suspicious_activity[key].append(now)
        self.suspicious_activity[key] = [t for t in self.suspicious_activity[key] if now - t < 60]
        if len(self.suspicious_activity[key]) > 5:
            detections.append(
                {
                    "type": "IPV6_RA_FLOOD",
                    "severity": "high",
                    "message": f"Excessive IPv6 Router Advertisements from {src_mac}",
                    "ip": src_ip,
                    "mac": src_mac,
                    "details": {"ra_count": len(self.suspicious_activity[key])},
                }
            )

        if packet.haslayer(self.scapy.ICMPv6NDOptPrefixInfo):
            pref = packet[self.scapy.ICMPv6NDOptPrefixInfo]
            if str(pref.prefix).startswith("fe80::"):
                detections.append(
                    {
                        "type": "IPV6_SUSPICIOUS_PREFIX",
                        "severity": "medium",
                        "message": "Router Advertisement with link-local prefix detected",
                        "ip": src_ip,
                        "mac": src_mac,
                        "details": {"prefix": str(pref.prefix), "prefixlen": pref.prefixlen},
                    }
                )

        return detections
