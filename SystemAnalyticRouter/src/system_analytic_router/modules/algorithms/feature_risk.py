from __future__ import annotations

from system_analytic_router.models import Alert, FlowFeature, utc_now


COMMON_PORTS = {53, 80, 123, 443, 445, 993, 995, 5228, 8080, 8443}


def score_flow_feature(feature: FlowFeature) -> FlowFeature:
    score = 0.0
    tags: list[str] = []

    if feature.remote_port and feature.remote_port not in COMMON_PORTS:
        score += 25.0
        tags.append("uncommon_port")
    if feature.connection_count >= 50:
        score += 30.0
        tags.append("many_connections")
    elif feature.connection_count >= 10:
        score += 15.0
        tags.append("repeated_connection")
    if not feature.process_name or feature.process_name == "unknown":
        score += 10.0
        tags.append("unknown_process")
    if feature.duration_seconds > 3600:
        score += 15.0
        tags.append("long_duration")

    merged_tags = ",".join(filter(None, [feature.tags, ",".join(tags)]))
    return FlowFeature(
        generated_at=feature.generated_at,
        source_type=feature.source_type,
        device=feature.device,
        local_address=feature.local_address,
        remote_address=feature.remote_address,
        remote_port=feature.remote_port,
        protocol=feature.protocol,
        process_name=feature.process_name,
        connection_count=feature.connection_count,
        bytes_sent=feature.bytes_sent,
        bytes_recv=feature.bytes_recv,
        duration_seconds=feature.duration_seconds,
        first_seen=feature.first_seen,
        last_seen=feature.last_seen,
        risk_score=score,
        tags=merged_tags.strip(","),
    )


def alerts_from_features(features: list[FlowFeature], threshold: float = 40.0) -> list[Alert]:
    alerts: list[Alert] = []
    for feature in features:
        if feature.risk_score < threshold:
            continue
        alerts.append(
            Alert(
                timestamp=utc_now(),
                severity="warning" if feature.risk_score < 70 else "critical",
                category="flow_feature_risk",
                message=(
                    f"Risky flow {feature.local_address} -> "
                    f"{feature.remote_address}:{feature.remote_port} "
                    f"score={feature.risk_score:.1f} tags={feature.tags}"
                ),
                value=feature.risk_score,
            )
        )
    return alerts
