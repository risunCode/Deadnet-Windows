from __future__ import annotations

import os
import threading
import time

from app.core.attacker_service import AttackerService
from app.core.defender_service import DefenderService
from app.core.state import AppState


class SystemService:
    def __init__(self, attacker: AttackerService, defender: DefenderService, state: AppState) -> None:
        self.attacker = attacker
        self.defender = defender
        self.state = state

    def minimize(self) -> tuple[dict[str, object], int]:
        return self.state.runtime.minimize_window()

    def shutdown(self) -> tuple[dict[str, object], int]:
        self.attacker.stop()
        self.defender.stop()

        def _exit_later() -> None:
            time.sleep(0.5)
            os._exit(0)

        threading.Thread(target=_exit_later, daemon=True).start()
        return {"success": True, "message": "Shutting down"}, 200
