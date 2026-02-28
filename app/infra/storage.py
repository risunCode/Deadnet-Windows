import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


class DefenderStore:
    def __init__(self, db_file: str | Path = "defender_data.json") -> None:
        self.db_file = Path(db_file)
        self._lock = threading.RLock()
        self.data: dict[str, Any] = {
            "flagged_ips": {},
            "flagged_macs": {},
            "alerts": [],
            "statistics": {"total_alerts": 0, "last_updated": None},
        }
        self._load()

    def _load(self) -> None:
        with self._lock:
            if not self.db_file.exists():
                return
            try:
                self.data = json.loads(self.db_file.read_text(encoding="utf-8"))
            except Exception:
                pass

    def _save(self) -> None:
        with self._lock:
            self.data["statistics"]["last_updated"] = datetime.now().isoformat()
            self.db_file.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def add_alert(self, alert: dict[str, Any]) -> None:
        with self._lock:
            self.data["alerts"].append(alert)
            self.data["statistics"]["total_alerts"] += 1
            if len(self.data["alerts"]) > 1000:
                self.data["alerts"] = self.data["alerts"][-1000:]
            self._save()

    def flag_ip(self, ip: str, alert_type: str, severity: str, message: str) -> None:
        with self._lock:
            info = self.data["flagged_ips"].setdefault(ip, {"first_seen": datetime.now().isoformat(), "incidents": []})
            info["incidents"].append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "type": alert_type,
                    "severity": severity,
                    "message": message,
                }
            )
            info["last_seen"] = datetime.now().isoformat()
            info["total_incidents"] = len(info["incidents"])
            self._save()

    def flag_mac(self, mac: str, alert_type: str, severity: str, message: str) -> None:
        with self._lock:
            info = self.data["flagged_macs"].setdefault(mac, {"first_seen": datetime.now().isoformat(), "incidents": []})
            info["incidents"].append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "type": alert_type,
                    "severity": severity,
                    "message": message,
                }
            )
            info["last_seen"] = datetime.now().isoformat()
            info["total_incidents"] = len(info["incidents"])
            self._save()

    def get_flagged_ips(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.data["flagged_ips"])

    def get_flagged_macs(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.data["flagged_macs"])

    def get_flagged_count(self, flag_type: str) -> int:
        with self._lock:
            if flag_type == "ip":
                return len(self.data["flagged_ips"])
            if flag_type == "mac":
                return len(self.data["flagged_macs"])
            return 0

    def unflag_ip(self, ip: str) -> None:
        with self._lock:
            self.data["flagged_ips"].pop(ip, None)
            self._save()

    def unflag_mac(self, mac: str) -> None:
        with self._lock:
            self.data["flagged_macs"].pop(mac, None)
            self._save()

    def clear_all_flags(self) -> None:
        with self._lock:
            self.data["flagged_ips"] = {}
            self.data["flagged_macs"] = {}
            self._save()
