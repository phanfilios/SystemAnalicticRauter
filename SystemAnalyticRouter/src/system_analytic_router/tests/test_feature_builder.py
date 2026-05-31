from system_analytic_router.modules.algorithms.feature_risk import score_flow_feature
from system_analytic_router.modules.data_processing.feature_builder import build_flow_features_from_connections


def test_builds_flow_features_from_connection_rows() -> None:
    rows = [
        {
            "timestamp": "2026-05-31T21:27:01+00:00",
            "local_address": "192.168.1.10",
            "remote_address": "203.0.113.7",
            "remote_port": 4444,
            "protocol": "tcp",
            "process_name": "unknown",
        },
        {
            "timestamp": "2026-05-31T21:27:03+00:00",
            "local_address": "192.168.1.10",
            "remote_address": "203.0.113.7",
            "remote_port": 4444,
            "protocol": "tcp",
            "process_name": "unknown",
        },
    ]

    features = build_flow_features_from_connections(rows)
    scored = score_flow_feature(features[0])

    assert len(features) == 1
    assert features[0].connection_count == 2
    assert features[0].duration_seconds == 2
    assert scored.risk_score >= 35
    assert "uncommon_port" in scored.tags
