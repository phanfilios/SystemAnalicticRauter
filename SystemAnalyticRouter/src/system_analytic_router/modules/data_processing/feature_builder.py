from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from system_analytic_router.models import FlowFeature


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def build_flow_features_from_connections(rows: list[dict[str, object]]) -> list[FlowFeature]:
    groups: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        remote_address = row.get("remote_address")
        if not remote_address:
            continue
        key = (
            row.get("local_address") or "local",
            remote_address,
            row.get("remote_port"),
            row.get("protocol") or "unknown",
            row.get("process_name") or "unknown",
        )
        groups[key].append(row)

    generated_at = datetime.now(timezone.utc)
    features: list[FlowFeature] = []
    for (local_address, remote_address, remote_port, protocol, process_name), group in groups.items():
        timestamps = [_parse_timestamp(str(item["timestamp"])) for item in group if item.get("timestamp")]
        first_seen = min(timestamps) if timestamps else generated_at
        last_seen = max(timestamps) if timestamps else generated_at
        duration = max(0.0, (last_seen - first_seen).total_seconds())
        features.append(
            FlowFeature(
                generated_at=generated_at,
                source_type="connection_snapshot",
                device=str(local_address),
                local_address=str(local_address),
                remote_address=str(remote_address),
                remote_port=int(remote_port) if remote_port is not None else None,
                protocol=str(protocol),
                process_name=str(process_name) if process_name else None,
                connection_count=len(group),
                duration_seconds=duration,
                first_seen=first_seen,
                last_seen=last_seen,
                tags="metadata_only",
            )
        )
    return features
