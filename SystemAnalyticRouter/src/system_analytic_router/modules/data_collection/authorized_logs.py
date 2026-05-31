from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from system_analytic_router.models import DnsEvent, HttpEventAuthorized


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.strip())
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _int_or_zero(value: str | None) -> int:
    if value is None or value == "":
        return 0
    return int(value)


def load_dns_csv(path: Path) -> list[DnsEvent]:
    events: list[DnsEvent] = []
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            events.append(
                DnsEvent(
                    timestamp=parse_timestamp(row["timestamp"]),
                    device=row.get("device") or "unknown",
                    query=row["query"].strip().lower(),
                    answer=(row.get("answer") or "").strip() or None,
                    record_type=(row.get("record_type") or "").strip() or None,
                    source=row.get("source") or "authorized_log",
                )
            )
    return events


def load_http_authorized_csv(path: Path) -> list[HttpEventAuthorized]:
    events: list[HttpEventAuthorized] = []
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            parsed_url = urlparse(row.get("url") or "")
            host = (row.get("host") or parsed_url.netloc or "").strip().lower()
            path_value = row.get("path") or parsed_url.path or "/"
            events.append(
                HttpEventAuthorized(
                    timestamp=parse_timestamp(row["timestamp"]),
                    device=row.get("device") or "unknown",
                    method=(row.get("method") or "GET").upper(),
                    host=host,
                    path=path_value,
                    status_code=_int_or_none(row.get("status_code")),
                    bytes_in=_int_or_zero(row.get("bytes_in")),
                    bytes_out=_int_or_zero(row.get("bytes_out")),
                    user_agent=(row.get("user_agent") or "").strip() or None,
                    source=row.get("source") or "authorized_proxy",
                )
            )
    return events
