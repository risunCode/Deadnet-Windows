from __future__ import annotations

from dataclasses import dataclass, field
import threading

from app.core.models import AttackState, AttackStatistics, DefenderState, DefenderStatistics
from app.infra.storage import DefenderStore


@dataclass(slots=True)
class RuntimeContext:
    mode: str = "browser"
    webview_window: object | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def set_mode(self, mode: str) -> None:
        with self._lock:
            self.mode = mode

    def set_webview_window(self, window: object | None) -> None:
        with self._lock:
            self.webview_window = window

    def minimize_window(self) -> tuple[dict[str, object], int]:
        with self._lock:
            if self.mode != "webview":
                return {"success": False, "error": "Not in WebView mode"}, 200
            if self.webview_window is None:
                return {"success": False, "error": "WebView window is not ready"}, 200

            try:
                self.webview_window.minimize()
            except Exception as exc:
                return {"success": False, "error": str(exc)}, 200

            return {"success": True, "message": "Window minimized"}, 200


class AppState:
    def __init__(self) -> None:
        self.attack_lock = threading.RLock()
        self.defender_lock = threading.RLock()

        self.attack = AttackState()
        self.defender = DefenderState()

        self.attacker_thread: threading.Thread | None = None
        self.attacker_stop_event: threading.Event | None = None

        self.defender_thread: threading.Thread | None = None
        self.defender_stop_event: threading.Event | None = None
        self.sniffer = None
        self.detector = None
        self.runtime = RuntimeContext()

        self.db = DefenderStore()

    def reset_attack_statistics(self) -> None:
        with self.attack_lock:
            self.attack.statistics = AttackStatistics()
            self.attack.logs = []
            self.attack.network_info = {}

    def reset_defender_statistics(self) -> None:
        with self.defender_lock:
            self.defender.statistics = DefenderStatistics(
                flagged_ips=self.db.get_flagged_count("ip"),
                flagged_macs=self.db.get_flagged_count("mac"),
            )
            self.defender.recent_alerts = []
