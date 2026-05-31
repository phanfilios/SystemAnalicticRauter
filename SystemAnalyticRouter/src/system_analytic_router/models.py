from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class TrafficSample:
    timestamp: datetime
    interface: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin: int = 0
    errout: int = 0
    dropin: int = 0
    dropout: int = 0

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_recv


@dataclass(frozen=True)
class ConnectionSnapshot:
    timestamp: datetime
    protocol: str
    local_address: str
    local_port: int
    remote_address: Optional[str]
    remote_port: Optional[int]
    status: str
    pid: Optional[int]
    process_name: Optional[str]


@dataclass(frozen=True)
class Alert:
    timestamp: datetime
    severity: str
    category: str
    message: str
    interface: Optional[str] = None
    value: Optional[float] = None
    baseline: Optional[float] = None


@dataclass(frozen=True)
class FlowFeature:
    generated_at: datetime
    source_type: str
    device: str
    local_address: str
    remote_address: Optional[str]
    remote_port: Optional[int]
    protocol: str
    process_name: Optional[str]
    connection_count: int
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration_seconds: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    risk_score: float = 0.0
    tags: str = ""


@dataclass(frozen=True)
class DnsEvent:
    timestamp: datetime
    device: str
    query: str
    answer: Optional[str] = None
    record_type: Optional[str] = None
    source: str = "authorized_log"


@dataclass(frozen=True)
class HttpEventAuthorized:
    timestamp: datetime
    device: str
    method: str
    host: str
    path: str
    status_code: Optional[int] = None
    bytes_in: int = 0
    bytes_out: int = 0
    user_agent: Optional[str] = None
    source: str = "authorized_proxy"
