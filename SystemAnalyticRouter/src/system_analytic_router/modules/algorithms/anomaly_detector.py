from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean, pstdev

from system_analytic_router.models import Alert, TrafficSample
from system_analytic_router.modules.data_processing.normalizer import bytes_per_second


class RollingAnomalyDetector:
    def __init__(
        self,
        window: int = 30,
        zscore_threshold: float = 3.0,
        min_baseline_samples: int = 8,
        interval_seconds: float = 2.0,
    ) -> None:
        self.window = window
        self.zscore_threshold = zscore_threshold
        self.min_baseline_samples = min_baseline_samples
        self.interval_seconds = interval_seconds
        self._history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def analyze(self, sample: TrafficSample) -> list[Alert]:
        alerts: list[Alert] = []
        value = bytes_per_second(sample, self.interval_seconds)
        history = self._history[sample.interface]

        if len(history) >= self.min_baseline_samples:
            avg = mean(history)
            deviation = pstdev(history)
            if deviation > 0:
                zscore = (value - avg) / deviation
                is_spike = zscore >= self.zscore_threshold
            else:
                zscore = float("inf") if value > avg and value > 0 else 0.0
                is_spike = zscore == float("inf")
            if is_spike:
                alerts.append(
                    Alert(
                        timestamp=sample.timestamp,
                        severity="warning" if zscore < self.zscore_threshold * 1.5 else "critical",
                        category="traffic_spike",
                        interface=sample.interface,
                        value=value,
                        baseline=avg,
                        message=(
                            f"Traffic spike on {sample.interface}: "
                            f"{value:.2f} B/s vs baseline {avg:.2f} B/s"
                        ),
                    )
                )

        if sample.errin + sample.errout + sample.dropin + sample.dropout > 0:
            alerts.append(
                Alert(
                    timestamp=sample.timestamp,
                    severity="warning",
                    category="interface_errors",
                    interface=sample.interface,
                    value=float(sample.errin + sample.errout + sample.dropin + sample.dropout),
                    message=f"Interface errors or dropped packets detected on {sample.interface}",
                )
            )

        history.append(value)
        return alerts
