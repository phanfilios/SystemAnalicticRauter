from __future__ import annotations

from datetime import datetime

import psutil

from system_analytic_router.models import ConnectionSnapshot


def _addr_text(addr: object) -> tuple[str | None, int | None]:
    if not addr:
        return None, None
    ip = getattr(addr, "ip", None)
    port = getattr(addr, "port", None)
    if ip is None and isinstance(addr, tuple) and len(addr) >= 2:
        ip = addr[0]
        port = addr[1]
    return str(ip) if ip else None, int(port) if port is not None else None


def collect_connections(timestamp: datetime) -> list[ConnectionSnapshot]:
    snapshots: list[ConnectionSnapshot] = []
    for conn in psutil.net_connections(kind="inet"):
        local_ip, local_port = _addr_text(conn.laddr)
        remote_ip, remote_port = _addr_text(conn.raddr)
        process_name = None
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                process_name = None
        snapshots.append(
            ConnectionSnapshot(
                timestamp=timestamp,
                protocol=str(conn.type),
                local_address=local_ip or "",
                local_port=local_port or 0,
                remote_address=remote_ip,
                remote_port=remote_port,
                status=conn.status,
                pid=conn.pid,
                process_name=process_name,
            )
        )
    return snapshots
