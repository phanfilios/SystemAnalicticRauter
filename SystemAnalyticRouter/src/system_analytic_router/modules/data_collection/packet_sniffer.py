from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from system_analytic_router.models import Alert, utc_now


def sniff_packet_metadata(
    interface: str | None,
    seconds: int,
    on_alert: Callable[[Alert], None],
) -> None:
    """Optional packet metadata capture.

    This requires scapy plus a local packet capture driver such as Npcap on
    Windows. It records metadata only and must be used only on interfaces and
    networks the operator is allowed to monitor.
    """
    try:
        from scapy.all import IP, TCP, UDP, sniff
    except ImportError as exc:
        raise RuntimeError("Packet sniffing requires optional dependency: scapy") from exc

    def handle(packet: object) -> None:
        if IP not in packet:
            return
        proto = "ip"
        dst_port = None
        if TCP in packet:
            proto = "tcp"
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            proto = "udp"
            dst_port = int(packet[UDP].dport)

        on_alert(
            Alert(
                timestamp=utc_now(),
                severity="info",
                category="packet_metadata",
                interface=interface,
                message=f"{proto} {packet[IP].src} -> {packet[IP].dst}:{dst_port or ''}",
            )
        )

    sniff(iface=interface, timeout=seconds, prn=handle, store=False)
