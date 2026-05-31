from datetime import datetime, timezone

from system_analytic_router.models import DnsEvent, FlowFeature, HttpEventAuthorized, TrafficSample
from system_analytic_router.modules.storage.sqlite_store import SQLiteStore


def test_store_writes_traffic_sample(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "analytics.sqlite3")
    store.init_db()
    store.save_traffic_samples(
        [
            TrafficSample(
                timestamp=datetime.now(timezone.utc),
                interface="Ethernet",
                bytes_sent=1,
                bytes_recv=2,
                packets_sent=3,
                packets_recv=4,
            )
        ]
    )

    with store.connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM traffic_samples").fetchone()[0]

    assert count == 1


def test_store_writes_feature_dns_and_authorized_http(tmp_path) -> None:
    now = datetime.now(timezone.utc)
    store = SQLiteStore(tmp_path / "analytics.sqlite3")
    store.init_db()
    store.save_flow_features(
        [
            FlowFeature(
                generated_at=now,
                source_type="connection_snapshot",
                device="192.168.1.10",
                local_address="192.168.1.10",
                remote_address="8.8.8.8",
                remote_port=53,
                protocol="tcp",
                process_name="browser.exe",
                connection_count=2,
                first_seen=now,
                last_seen=now,
            )
        ]
    )
    store.save_dns_events([DnsEvent(timestamp=now, device="pc", query="example.com")])
    store.save_http_events_authorized(
        [
            HttpEventAuthorized(
                timestamp=now,
                device="pc",
                method="GET",
                host="example.com",
                path="/",
                status_code=200,
            )
        ]
    )

    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM flow_features").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM http_events_authorized").fetchone()[0] == 1
