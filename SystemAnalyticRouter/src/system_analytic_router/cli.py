from __future__ import annotations

import argparse
import time
from pathlib import Path

from system_analytic_router.config import load_config
from system_analytic_router.models import Alert, utc_now
from system_analytic_router.modules.algorithms.anomaly_detector import RollingAnomalyDetector
from system_analytic_router.modules.algorithms.feature_risk import alerts_from_features, score_flow_feature
from system_analytic_router.modules.data_collection.authorized_logs import (
    load_dns_csv,
    load_http_authorized_csv,
)
from system_analytic_router.modules.data_collection.connections import collect_connections
from system_analytic_router.modules.data_collection.local_metrics import InterfaceDeltaCollector, list_interfaces
from system_analytic_router.modules.data_collection.packet_sniffer import sniff_packet_metadata
from system_analytic_router.modules.data_processing.feature_builder import build_flow_features_from_connections
from system_analytic_router.modules.storage.sqlite_store import SQLiteStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sarouter",
        description="Authorized real-time network analytics for a local computer/router environment.",
    )
    parser.add_argument("--settings", type=Path, help="Path to configs/settings.yml")
    parser.add_argument("--db", type=Path, help="SQLite database path")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("interfaces", help="List available network interfaces")
    subparsers.add_parser("init-db", help="Create the SQLite schema")

    monitor = subparsers.add_parser("monitor", help="Monitor traffic and store analytics")
    monitor.add_argument("--interface", help="Interface name to monitor. Default: all interfaces")
    monitor.add_argument("--interval", type=float, help="Sample interval in seconds")
    monitor.add_argument("--duration", type=int, help="Stop after this many seconds")
    monitor.add_argument("--connections", action="store_true", help="Store active connection snapshots")
    monitor.add_argument(
        "--packet-metadata-seconds",
        type=int,
        default=0,
        help="Optional scapy metadata sniff duration. Requires authorization, admin privileges and Npcap.",
    )

    import_dns = subparsers.add_parser("import-dns-csv", help="Import authorized DNS event CSV")
    import_dns.add_argument("input", type=Path)

    import_http = subparsers.add_parser("import-http-csv", help="Import authorized HTTP/proxy event CSV")
    import_http.add_argument("input", type=Path)

    build_features = subparsers.add_parser(
        "build-features",
        help="Build metadata-only flow features from collected connection snapshots",
    )
    build_features.add_argument("--limit", type=int, help="Only read the first N connection rows")
    build_features.add_argument(
        "--alert-threshold",
        type=float,
        default=40.0,
        help="Create alerts for features at or above this risk score",
    )

    export = subparsers.add_parser("export-csv", help="Export a database table to CSV")
    export.add_argument(
        "table",
        choices=[
            "traffic_samples",
            "connection_snapshots",
            "alerts",
            "flow_features",
            "dns_events",
            "http_events_authorized",
        ],
    )
    export.add_argument("output", type=Path)

    return parser


def print_alert(alert: Alert) -> None:
    print(f"[{alert.severity.upper()}] {alert.category}: {alert.message}")


def run_monitor(args: argparse.Namespace) -> int:
    config = load_config(args.settings, args.db)
    interval = args.interval or config.sample_interval_seconds
    store = SQLiteStore(config.database_path)
    store.init_db()

    detector = RollingAnomalyDetector(
        window=config.anomaly_window,
        zscore_threshold=config.anomaly_zscore_threshold,
        min_baseline_samples=config.min_baseline_samples,
        interval_seconds=interval,
    )
    collector = InterfaceDeltaCollector(interface=args.interface)

    print(f"Database: {store.path}")
    print(f"Monitoring: {args.interface or 'all interfaces'} every {interval}s")
    if args.duration:
        print(f"Duration: {args.duration}s")

    start = time.monotonic()
    iteration = 0

    try:
        if args.packet_metadata_seconds > 0:
            sniff_packet_metadata(args.interface, args.packet_metadata_seconds, print_alert)

        while True:
            now = utc_now()
            samples = collector.sample(now)
            store.save_traffic_samples(samples)

            alerts: list[Alert] = []
            for sample in samples:
                alerts.extend(detector.analyze(sample))
            store.save_alerts(alerts)
            for alert in alerts:
                print_alert(alert)

            if args.connections and iteration % max(1, config.connection_scan_every) == 0:
                store.save_connections(collect_connections(now))

            if samples:
                total = sum(sample.total_bytes for sample in samples)
                print(f"{now.isoformat()} samples={len(samples)} bytes={total}")

            iteration += 1
            if args.duration and time.monotonic() - start >= args.duration:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.settings, args.db)
    store = SQLiteStore(config.database_path)

    if args.command == "interfaces":
        for name in list_interfaces():
            print(name)
        return 0

    if args.command == "init-db":
        store.init_db()
        print(f"Database initialized: {store.path}")
        return 0

    if args.command == "monitor":
        return run_monitor(args)

    if args.command == "import-dns-csv":
        store.init_db()
        events = load_dns_csv(args.input)
        store.save_dns_events(events)
        print(f"Imported DNS events: {len(events)}")
        return 0

    if args.command == "import-http-csv":
        store.init_db()
        events = load_http_authorized_csv(args.input)
        store.save_http_events_authorized(events)
        print(f"Imported authorized HTTP events: {len(events)}")
        return 0

    if args.command == "build-features":
        store.init_db()
        rows = store.fetch_connection_rows(args.limit)
        features = [score_flow_feature(feature) for feature in build_flow_features_from_connections(rows)]
        alerts = alerts_from_features(features, threshold=args.alert_threshold)
        store.save_flow_features(features)
        store.save_alerts(alerts)
        print(f"Built flow features: {len(features)}")
        print(f"Created feature-risk alerts: {len(alerts)}")
        return 0

    if args.command == "export-csv":
        store.export_table_csv(args.table, args.output)
        print(f"Exported {args.table} to {args.output}")
        return 0

    parser.error("Unknown command")
    return 2
