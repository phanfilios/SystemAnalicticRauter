from __future__ import annotations

from datetime import datetime

import psutil

from system_analytic_router.models import TrafficSample


def list_interfaces() -> list[str]:
    counters = psutil.net_io_counters(pernic=True)
    return sorted(counters.keys())


def collect_interface_totals(timestamp: datetime) -> list[TrafficSample]:
    counters = psutil.net_io_counters(pernic=True)
    samples: list[TrafficSample] = []
    for name, item in counters.items():
        samples.append(
            TrafficSample(
                timestamp=timestamp,
                interface=name,
                bytes_sent=item.bytes_sent,
                bytes_recv=item.bytes_recv,
                packets_sent=item.packets_sent,
                packets_recv=item.packets_recv,
                errin=item.errin,
                errout=item.errout,
                dropin=item.dropin,
                dropout=item.dropout,
            )
        )
    return samples


class InterfaceDeltaCollector:
    def __init__(self, interface: str | None = None) -> None:
        self.interface = interface
        self._previous: dict[str, TrafficSample] = {}

    def sample(self, timestamp: datetime) -> list[TrafficSample]:
        totals = collect_interface_totals(timestamp)
        deltas: list[TrafficSample] = []
        for current in totals:
            if self.interface and current.interface != self.interface:
                continue
            previous = self._previous.get(current.interface)
            self._previous[current.interface] = current
            if previous is None:
                continue
            deltas.append(
                TrafficSample(
                    timestamp=current.timestamp,
                    interface=current.interface,
                    bytes_sent=max(0, current.bytes_sent - previous.bytes_sent),
                    bytes_recv=max(0, current.bytes_recv - previous.bytes_recv),
                    packets_sent=max(0, current.packets_sent - previous.packets_sent),
                    packets_recv=max(0, current.packets_recv - previous.packets_recv),
                    errin=max(0, current.errin - previous.errin),
                    errout=max(0, current.errout - previous.errout),
                    dropin=max(0, current.dropin - previous.dropin),
                    dropout=max(0, current.dropout - previous.dropout),
                )
            )
        return deltas
