from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AttackStatistics:
    cycles: int = 0
    packets_sent: int = 0
    start_time: float | None = None
    last_cycle_duration: int = 0


@dataclass
class AttackState:
    active: bool = False
    mode: str | None = None
    interface: str | None = None
    attacks_enabled: dict[str, bool] = field(
        default_factory=lambda: {
            "arp_poison": True,
            "ipv6_ra": True,
            "dead_router": True,
        }
    )
    statistics: AttackStatistics = field(default_factory=AttackStatistics)
    network_info: dict[str, Any] = field(default_factory=dict)
    logs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class DefenderStatistics:
    total_packets: int = 0
    suspicious_packets: int = 0
    flagged_ips: int = 0
    flagged_macs: int = 0
    arp_packets: int = 0
    ipv6_packets: int = 0
    suspicious_arp: int = 0
    suspicious_ipv6: int = 0


@dataclass
class DefenderState:
    active: bool = False
    interface: str | None = None
    start_time: float | None = None
    statistics: DefenderStatistics = field(default_factory=DefenderStatistics)
    recent_alerts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
