"""A BPF capture filter per finding — for re-capturing the flow live.

The Wireshark display filter a finding already carries (`tcp.stream eq 16`,
`frame.number in {...}`) selects packets AFTER a capture, using indices that
exist only once the whole file has been read. A BPF capture filter is a
different thing for a different moment: it runs in the kernel, BEFORE a packet
is kept, and so can only speak of what is on the wire at that instant —
addresses, protocol, ports. Stream and frame numbers cannot be translated
into it, and pretending otherwise would hand the operator a filter that does
not compile.

So this does not translate the display filter; it rebuilds the selector from
the finding's CHANNEL — the initiator and responder addresses, the transport,
the port — which is precisely the part a capture filter can express. The
result is the filter you hand to `dumpcap -f`, to `tcpdump`, or straight back
to this tool: `semantiq.py live eth0 --filter '<bpf>'` to watch just the
flagged flow continue in real time.

A finding whose channel has no packet-level addresses (a HAR finding, say)
yields no BPF, and that is COUNTED, not dropped: an operator who sees fewer
filters than findings must be told the capture filter could not name those
flows, not left to assume they were covered.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from core.model import Finding

__all__ = ["bpf_for_finding", "write_bpf"]

#: DNS-family service ports, so a DNS finding's filter is tight (udp port 53)
#: rather than "all UDP between these two", which a bare proto term would give.
_DNS_PORT = {"mdns": 5353, "llmnr": 5355}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def bpf_for_finding(finding: Finding) -> Optional[str]:
    """A libpcap capture-filter expression for a finding's flow, or None.

    Built from the channel, never from the display filter: a capture filter
    cannot express a TCP stream index or a frame number, so those findings
    are matched by their endpoints and transport instead — the most specific
    thing that survives into kernel-time filtering.
    """
    channel = finding.channel
    hosts: List[str] = []
    for entity in (channel.initiator, channel.responder):
        if entity and _is_ip(entity.value) and entity.value not in hosts:
            hosts.append(entity.value)

    proto = (channel.dims.get("proto") or "").lower()
    if proto not in ("tcp", "udp", "icmp"):
        proto = ""

    port = channel.dims.get("dport")
    port = int(port) if port and str(port).isdigit() else None

    # DNS keys on zone, not a port, so the port is implied by the service.
    if channel.domain == "dns" and port is None:
        proto = proto or "udp"
        port = _DNS_PORT.get(str(channel.dims.get("service", "")), 53)

    if proto and port is not None:
        transport = f"{proto} port {port}"
    elif proto:
        transport = proto
    elif port is not None:
        transport = f"port {port}"
    else:
        transport = ""

    # Require at least one address: a transport-only filter ("tcp") would
    # capture the whole link, which is the opposite of "re-capture THIS
    # flow". A finding with no packet-level address (a HAR finding) yields
    # nothing, and the caller counts that.
    if not hosts:
        return None
    parts = [f"host {h}" for h in hosts]
    if transport:
        parts.append(transport)
    return " and ".join(parts)


def write_bpf(path: Path, findings: Sequence[Finding]) -> Tuple[int, int]:
    """Write one BPF filter per finding, plus a combined OR of them all.

    Returns (written, skipped). Deduplicated: several findings on one channel
    share a filter and it is emitted once. The combined expression at the top
    is the "re-capture everything flagged at once" filter — parenthesised per
    clause so the ORs do not bind loosely across the ANDs inside each.
    """
    lines = [
        "# tid-semantiQ — BPF capture filters, one per finding.",
        "# Use with:  dumpcap -f '<filter>'   tcpdump '<filter>'   "
        "semantiq.py live <iface> --filter '<filter>'",
        "#",
        "# These match a finding's FLOW by address/port — not the exact",
        "# packets (a capture filter cannot see a TCP stream or frame index).",
        "",
    ]

    seen = set()
    unique: List[str] = []
    produced = 0
    skipped = 0
    for finding in findings:
        expr = bpf_for_finding(finding)
        if expr is None:
            skipped += 1
            continue
        produced += 1
        lines.append(f"# [{finding.severity.name}] {finding.title} "
                     f"({finding.confidence:.2f})  {finding.rule_id}")
        lines.append(expr)
        lines.append("")
        if expr not in seen:
            seen.add(expr)
            unique.append(expr)

    if unique:
        combined = " or ".join(f"({expr})" for expr in unique)
        lines.append("# combined — every flagged flow at once:")
        lines.append(combined)
        lines.append("")

    path.write_text("\n".join(lines))
    return produced, skipped
