from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ScapyRuntime:
    mod: Any

    @property
    def conf(self) -> Any:
        return self.mod.conf


def load_scapy() -> ScapyRuntime:
    try:
        import scapy.all as scapy
    except Exception as exc:
        raise RuntimeError("scapy is required for network operations") from exc
    return ScapyRuntime(mod=scapy)
