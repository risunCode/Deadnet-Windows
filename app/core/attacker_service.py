from __future__ import annotations

import threading
import time
from typing import Any

from app.core.models import AttackStatistics
from app.core.state import AppState
from app.infra.attacker_engine import DeadNetAttackerEngine
from app.infra.network import get_network_interfaces


class AttackerService:
    def __init__(self, state: AppState) -> None:
        self.state = state

    def get_status(self) -> dict[str, Any]:
        with self.state.attack_lock:
            return {
                "active": self.state.attack.active,
                "mode": self.state.attack.mode,
                "interface": self.state.attack.interface,
                "attacks_enabled": dict(self.state.attack.attacks_enabled),
                "statistics": self.state.attack.statistics.__dict__.copy(),
                "network_info": dict(self.state.attack.network_info),
            }

    def get_logs(self, limit: int) -> dict[str, Any]:
        with self.state.attack_lock:
            return {"logs": self.state.attack.logs[-limit:]}

    def get_interfaces(self) -> dict[str, Any]:
        return {"interfaces": get_network_interfaces()}

    def start(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        iface = payload.get("interface")
        if not iface:
            return {"success": False, "error": "Interface required"}, 400

        with self.state.attack_lock:
            if self.state.attack.active:
                return {"success": False, "error": "Attack already running"}, 400

            provided_attacks = payload.get("attacks_enabled") or {}
            merged_attacks = dict(self.state.attack.attacks_enabled)
            for key in ("arp_poison", "ipv6_ra", "dead_router"):
                if key in provided_attacks:
                    merged_attacks[key] = bool(provided_attacks[key])

            self.state.attack.active = True
            self.state.attack.mode = payload.get("mode", "local")
            self.state.attack.interface = iface
            self.state.attack.attacks_enabled = merged_attacks
            self.state.attack.statistics = AttackStatistics()
            self.state.attack.logs = []
            self.state.attack.network_info = {}
            self.state.attacker_stop_event = threading.Event()

        target_ips = None
        target_ips_str = payload.get("target_ips") or ""
        if target_ips_str.strip():
            target_ips = [ip.strip() for ip in target_ips_str.split(",") if ip.strip()]

        thread = threading.Thread(
            target=self._run_attack,
            args=(
                iface,
                payload,
                target_ips,
                self.state.attacker_stop_event,
            ),
            daemon=True,
        )
        self.state.attacker_thread = thread
        thread.start()
        return {"success": True, "message": "Attack started"}, 200

    def _run_attack(self, iface: str, payload: dict[str, Any], target_ips: list[str] | None, stop_event: threading.Event) -> None:
        try:
            engine = DeadNetAttackerEngine(
                iface=iface,
                cidrlen=int(payload.get("cidrlen", 24)),
                interval=int(payload.get("interval", 5)),
                disable_ipv6=not bool(payload.get("enable_ipv6", True)),
                mode=payload.get("mode", "local"),
                fake_ip=payload.get("fake_ip"),
                target_ips=target_ips,
                attacks_enabled=self.state.attack.attacks_enabled,
                log_fn=self._append_log,
                stats_fn=self._update_stats,
            )
            with self.state.attack_lock:
                self.state.attack.network_info = engine.network_info()
            engine.run(stop_event)
        except Exception as exc:
            self._append_log(f"Error: {exc}")
        finally:
            with self.state.attack_lock:
                self.state.attack.active = False
                self.state.attacker_stop_event = None
                self.state.attacker_thread = None

    def _append_log(self, message: str) -> None:
        with self.state.attack_lock:
            self.state.attack.logs.append({"timestamp": time.time(), "message": message})
            if len(self.state.attack.logs) > 100:
                self.state.attack.logs = self.state.attack.logs[-100:]

    def _update_stats(
        self,
        cycle_increment: int = 0,
        packets_increment: int = 0,
        last_cycle_duration: int | None = None,
        start_time: float | None = None,
    ) -> None:
        with self.state.attack_lock:
            s = self.state.attack.statistics
            s.cycles += cycle_increment
            s.packets_sent += packets_increment
            if last_cycle_duration is not None:
                s.last_cycle_duration = last_cycle_duration
            if start_time is not None:
                s.start_time = start_time

    def stop(self) -> tuple[dict[str, Any], int]:
        with self.state.attack_lock:
            if not self.state.attack.active:
                return {"success": False, "error": "No attack running"}, 400
            self.state.attack.active = False
            event = self.state.attacker_stop_event

        if event is not None:
            event.set()
        return {"success": True, "message": "Attack stopped"}, 200
