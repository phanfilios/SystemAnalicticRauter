from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AppConfig:
    database_path: Path
    sample_interval_seconds: float
    anomaly_window: int
    anomaly_zscore_threshold: float
    min_baseline_samples: int
    connection_scan_every: int
    authorized_capture_only: bool = True


DEFAULT_CONFIG = AppConfig(
    database_path=Path("data/router_analytics.sqlite3"),
    sample_interval_seconds=2.0,
    anomaly_window=30,
    anomaly_zscore_threshold=3.0,
    min_baseline_samples=8,
    connection_scan_every=5,
)


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must contain a mapping: {path}")
    return data


def load_config(settings_path: Path | None = None, database_path: Path | None = None) -> AppConfig:
    data = load_yaml(settings_path) if settings_path else {}
    analytics = data.get("analytics", {})
    capture = data.get("capture", {})

    configured_db = data.get("database", {}).get("path")
    db_path = database_path or Path(configured_db or DEFAULT_CONFIG.database_path)

    return AppConfig(
        database_path=db_path,
        sample_interval_seconds=float(capture.get("sample_interval_seconds", DEFAULT_CONFIG.sample_interval_seconds)),
        anomaly_window=int(analytics.get("window", DEFAULT_CONFIG.anomaly_window)),
        anomaly_zscore_threshold=float(analytics.get("zscore_threshold", DEFAULT_CONFIG.anomaly_zscore_threshold)),
        min_baseline_samples=int(analytics.get("min_baseline_samples", DEFAULT_CONFIG.min_baseline_samples)),
        connection_scan_every=int(capture.get("connection_scan_every", DEFAULT_CONFIG.connection_scan_every)),
        authorized_capture_only=bool(capture.get("authorized_capture_only", True)),
    )
