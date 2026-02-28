from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any

from app.core.models import DefenderStatistics
from app.core.state import AppState
from app.infra.detector import PacketDetector
from app.infra.scapy_adapter import load_scapy


class DefenderService:
    def __init__(self, state: AppState) -> None:
        self.state = state

    def status(self) -> dict[str, Any]:
        with self.state.defender_lock:
            start_time = self.state.defender.start_time
            return {
                "active": self.state.defender.active,
                "interface": self.state.defender.interface,
                "start_time": start_time,
                "statistics": self.state.defender.statistics.__dict__.copy(),
                "uptime": int(time.time() - start_time) if start_time else 0,
            }

    def alerts(self, limit: int) -> dict[str, Any]:
        with self.state.defender_lock:
            return {"alerts": self.state.defender.recent_alerts[:limit]}

    def flagged(self) -> dict[str, Any]:
        return {
            "ips": self.state.db.get_flagged_ips(),
            "macs": self.state.db.get_flagged_macs(),
        }

    def start(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        iface = payload.get("interface")
        if not iface:
            return {"success": False, "error": "Interface required"}, 400

        with self.state.defender_lock:
            if self.state.defender.active:
                return {"success": False, "error": "Already monitoring"}, 400
            self.state.defender.active = True
            self.state.defender.interface = iface
            self.state.defender.start_time = time.time()
            self.state.defender.statistics = DefenderStatistics(
                flagged_ips=self.state.db.get_flagged_count("ip"),
                flagged_macs=self.state.db.get_flagged_count("mac"),
            )
            self.state.defender.recent_alerts = []
            self.state.defender_stop_event = threading.Event()

        thread = threading.Thread(target=self._monitor_loop, args=(iface, self.state.defender_stop_event), daemon=True)
        self.state.defender_thread = thread
        thread.start()
        return {"success": True, "message": "Monitoring started"}, 200

    def _monitor_loop(self, interface: str, stop_event: threading.Event) -> None:
        try:
            scapy = load_scapy().mod
            self.state.detector = PacketDetector(interface)

            def packet_callback(packet):
                self._packet_callback(packet, scapy)

            self.state.sniffer = scapy.AsyncSniffer(iface=interface, prn=packet_callback, store=False)
            self.state.sniffer.start()
            while not stop_event.is_set():
                time.sleep(0.1)
        except Exception:
            pass
        finally:
            try:
                if self.state.sniffer:
                    self.state.sniffer.stop()
            except Exception:
                pass
            with self.state.defender_lock:
                self.state.defender.active = False
                self.state.defender_stop_event = None
                self.state.defender_thread = None
            self.state.sniffer = None
            self.state.detector = None

    def _packet_callback(self, packet, scapy) -> None:
        detector = self.state.detector
        if detector is None:
            return
        try:
            with self.state.defender_lock:
                self.state.defender.statistics.total_packets += 1

            results = detector.analyze_packet(packet)
            if results["suspicious"]:
                with self.state.defender_lock:
                    self.state.defender.statistics.suspicious_packets += 1
                for detection in results["detections"]:
                    self._add_alert(
                        detection["type"],
                        detection["severity"],
                        detection["message"],
                        detection.get("ip"),
                        detection.get("mac"),
                        detection.get("details"),
                    )
                    with self.state.defender_lock:
                        if "ARP" in detection["type"]:
                            self.state.defender.statistics.suspicious_arp += 1
                        elif "IPV6" in detection["type"] or "IPv6" in detection["type"]:
                            self.state.defender.statistics.suspicious_ipv6 += 1

            if packet.haslayer(scapy.ARP):
                with self.state.defender_lock:
                    self.state.defender.statistics.arp_packets += 1
            if packet.haslayer(scapy.IPv6):
                with self.state.defender_lock:
                    self.state.defender.statistics.ipv6_packets += 1
        except Exception:
            return

    def _add_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        ip: str | None = None,
        mac: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "severity": severity,
            "message": message,
            "ip": ip,
            "mac": mac,
            "details": details or {},
        }
        with self.state.defender_lock:
            self.state.defender.recent_alerts.insert(0, alert)
            self.state.defender.recent_alerts = self.state.defender.recent_alerts[:100]

        self.state.db.add_alert(alert)
        if ip:
            self.state.db.flag_ip(ip, alert_type, severity, message)
        if mac:
            self.state.db.flag_mac(mac, alert_type, severity, message)

        with self.state.defender_lock:
            self.state.defender.statistics.flagged_ips = self.state.db.get_flagged_count("ip")
            self.state.defender.statistics.flagged_macs = self.state.db.get_flagged_count("mac")

    def stop(self) -> tuple[dict[str, Any], int]:
        with self.state.defender_lock:
            if not self.state.defender.active:
                return {"success": False, "error": "Not monitoring"}, 400
            self.state.defender.active = False
            event = self.state.defender_stop_event

        if event is not None:
            event.set()
        return {"success": True, "message": "Monitoring stopped"}, 200

    def unflag(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        addr_type = payload.get("type")
        address = payload.get("address")
        if not addr_type or not address:
            return {"success": False, "error": "Type and address required"}, 400

        if addr_type == "ip":
            self.state.db.unflag_ip(address)
        elif addr_type == "mac":
            self.state.db.unflag_mac(address)

        with self.state.defender_lock:
            self.state.defender.statistics.flagged_ips = self.state.db.get_flagged_count("ip")
            self.state.defender.statistics.flagged_macs = self.state.db.get_flagged_count("mac")
        return {"success": True}, 200

    def clear_flags(self) -> tuple[dict[str, Any], int]:
        self.state.db.clear_all_flags()
        with self.state.defender_lock:
            self.state.defender.statistics.flagged_ips = 0
            self.state.defender.statistics.flagged_macs = 0
        return {"success": True}, 200
