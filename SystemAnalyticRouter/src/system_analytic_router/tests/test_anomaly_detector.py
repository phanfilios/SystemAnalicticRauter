from datetime import datetime, timezone

from system_analytic_router.models import TrafficSample
from system_analytic_router.modules.algorithms.anomaly_detector import RollingAnomalyDetector


def sample(total_bytes: int) -> TrafficSample:
    return TrafficSample(
        timestamp=datetime.now(timezone.utc),
        interface="Wi-Fi",
        bytes_sent=0,
        bytes_recv=total_bytes,
        packets_sent=0,
        packets_recv=1,
    )


def test_detects_traffic_spike_after_baseline() -> None:
    detector = RollingAnomalyDetector(
        window=10,
        zscore_threshold=2.0,
        min_baseline_samples=5,
        interval_seconds=1.0,
    )
    for _ in range(5):
        assert detector.analyze(sample(100)) == []

    alerts = detector.analyze(sample(10000))

    assert len(alerts) == 1
    assert alerts[0].category == "traffic_spike"
