from __future__ import annotations

from system_analytic_router.models import TrafficSample


def bytes_per_second(sample: TrafficSample, interval_seconds: float) -> float:
    if interval_seconds <= 0:
        return float(sample.total_bytes)
    return sample.total_bytes / interval_seconds


def packets_per_second(sample: TrafficSample, interval_seconds: float) -> float:
    if interval_seconds <= 0:
        return float(sample.total_packets)
    return sample.total_packets / interval_seconds
