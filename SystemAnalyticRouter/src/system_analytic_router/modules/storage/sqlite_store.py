from __future__ import annotations

import csv
import sqlite3
from pathlib import Path
from typing import Iterable

from system_analytic_router.models import (
    Alert,
    ConnectionSnapshot,
    DnsEvent,
    FlowFeature,
    HttpEventAuthorized,
    TrafficSample,
)


class SQLiteStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS traffic_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    bytes_sent INTEGER NOT NULL,
                    bytes_recv INTEGER NOT NULL,
                    packets_sent INTEGER NOT NULL,
                    packets_recv INTEGER NOT NULL,
                    errin INTEGER NOT NULL,
                    errout INTEGER NOT NULL,
                    dropin INTEGER NOT NULL,
                    dropout INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS connection_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    local_address TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    remote_address TEXT,
                    remote_port INTEGER,
                    status TEXT NOT NULL,
                    pid INTEGER,
                    process_name TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT NOT NULL,
                    interface TEXT,
                    value REAL,
                    baseline REAL
                );

                CREATE TABLE IF NOT EXISTS flow_features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    device TEXT NOT NULL,
                    local_address TEXT NOT NULL,
                    remote_address TEXT,
                    remote_port INTEGER,
                    protocol TEXT NOT NULL,
                    process_name TEXT,
                    connection_count INTEGER NOT NULL,
                    bytes_sent INTEGER NOT NULL,
                    bytes_recv INTEGER NOT NULL,
                    duration_seconds REAL NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    risk_score REAL NOT NULL,
                    tags TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS dns_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    device TEXT NOT NULL,
                    query TEXT NOT NULL,
                    answer TEXT,
                    record_type TEXT,
                    source TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS http_events_authorized (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    device TEXT NOT NULL,
                    method TEXT NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER,
                    bytes_in INTEGER NOT NULL,
                    bytes_out INTEGER NOT NULL,
                    user_agent TEXT,
                    source TEXT NOT NULL
                );
                """
            )

    def save_traffic_samples(self, samples: Iterable[TrafficSample]) -> None:
        rows = [
            (
                s.timestamp.isoformat(),
                s.interface,
                s.bytes_sent,
                s.bytes_recv,
                s.packets_sent,
                s.packets_recv,
                s.errin,
                s.errout,
                s.dropin,
                s.dropout,
            )
            for s in samples
        ]
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO traffic_samples (
                    timestamp, interface, bytes_sent, bytes_recv, packets_sent,
                    packets_recv, errin, errout, dropin, dropout
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def save_connections(self, snapshots: Iterable[ConnectionSnapshot]) -> None:
        rows = [
            (
                s.timestamp.isoformat(),
                s.protocol,
                s.local_address,
                s.local_port,
                s.remote_address,
                s.remote_port,
                s.status,
                s.pid,
                s.process_name,
            )
            for s in snapshots
        ]
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO connection_snapshots (
                    timestamp, protocol, local_address, local_port, remote_address,
                    remote_port, status, pid, process_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def save_alerts(self, alerts: Iterable[Alert]) -> None:
        rows = [
            (
                a.timestamp.isoformat(),
                a.severity,
                a.category,
                a.message,
                a.interface,
                a.value,
                a.baseline,
            )
            for a in alerts
        ]
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO alerts (
                    timestamp, severity, category, message, interface, value, baseline
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def save_flow_features(self, features: Iterable[FlowFeature]) -> None:
        rows = [
            (
                f.generated_at.isoformat(),
                f.source_type,
                f.device,
                f.local_address,
                f.remote_address,
                f.remote_port,
                f.protocol,
                f.process_name,
                f.connection_count,
                f.bytes_sent,
                f.bytes_recv,
                f.duration_seconds,
                f.first_seen.isoformat() if f.first_seen else None,
                f.last_seen.isoformat() if f.last_seen else None,
                f.risk_score,
                f.tags,
            )
            for f in features
        ]
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO flow_features (
                    generated_at, source_type, device, local_address, remote_address,
                    remote_port, protocol, process_name, connection_count, bytes_sent,
                    bytes_recv, duration_seconds, first_seen, last_seen, risk_score, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def save_dns_events(self, events: Iterable[DnsEvent]) -> None:
        rows = [
            (e.timestamp.isoformat(), e.device, e.query, e.answer, e.record_type, e.source)
            for e in events
        ]
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO dns_events (
                    timestamp, device, query, answer, record_type, source
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def save_http_events_authorized(self, events: Iterable[HttpEventAuthorized]) -> None:
        rows = [
            (
                e.timestamp.isoformat(),
                e.device,
                e.method,
                e.host,
                e.path,
                e.status_code,
                e.bytes_in,
                e.bytes_out,
                e.user_agent,
                e.source,
            )
            for e in events
        ]
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO http_events_authorized (
                    timestamp, device, method, host, path, status_code,
                    bytes_in, bytes_out, user_agent, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def fetch_connection_rows(self, limit: int | None = None) -> list[dict[str, object]]:
        query = "SELECT * FROM connection_snapshots ORDER BY id"
        params: tuple[object, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def export_table_csv(self, table: str, output_path: Path) -> None:
        allowed = {
            "traffic_samples",
            "connection_snapshots",
            "alerts",
            "flow_features",
            "dns_events",
            "http_events_authorized",
        }
        if table not in allowed:
            raise ValueError(f"Unsupported table: {table}")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn, output_path.open("w", newline="", encoding="utf-8") as handle:
            cursor = conn.execute(f"SELECT * FROM {table} ORDER BY id")
            writer = csv.writer(handle)
            writer.writerow([description[0] for description in cursor.description])
            writer.writerows(cursor.fetchall())
