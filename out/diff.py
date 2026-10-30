"""Two captures, compared: what changed is the meaning.

A single capture answers "what is happening"; two captures answer "what is
DIFFERENT" — which is usually the question an operator actually has. A new
endpoint, a new originating host, a new DNS zone, a new TLS client stack, a
channel whose volume multiplied: each is invisible inside one file and
obvious between two.

The comparison is asymmetric by design and says so: the first capture is the
REFERENCE, the second is the one under examination, and "new" always means
"in the second, absent from the first". Both files are read through the
identical pipeline as `read` — same parsers, same scoring — because a diff
computed by a second implementation would diff the implementations.

WHAT THIS IS NOT. It is not the rarity baseline. The baseline is a
statistical history of many hosts over time, feeding a confidence number;
this is a literal set comparison between two specific files, feeding a
reader. A destination can be unremarkable to the baseline and still be the
one new thing between yesterday's capture and today's — and that is exactly
the case this exists for.

Volume comparisons are gated twice (a ratio AND an absolute floor) because
each gate alone lies: a 10x jump from 40 bytes is noise, and a 60 MB rise on
an already-huge channel can hide under a small ratio.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, NamedTuple, Sequence, Set, Tuple

from core.model import Finding, Series

__all__ = ["CaptureProfile", "profile", "render_diff"]

#: Volume-shift gates: BOTH must hold before a channel is reported as
#: grown or shrunk. See module docstring for why two.
_SHIFT_RATIO = 8.0
_SHIFT_FLOOR_BYTES = 100 * 1024


class CaptureProfile(NamedTuple):
    """Everything about one capture the diff compares."""
    name: str
    endpoints: Dict[str, Dict[str, Any]]   # addr -> {names, bytes, obs}
    hosts: Set[str]                        # originating addresses
    zones: Counter                         # dns zone -> lookups
    tls_prints: Set[str]
    transports: Counter                    # "tcp/443" -> exchanges
    findings: Dict[Tuple[str, str], Finding]   # (rule_id, channel key)


def profile(name: str, series: Sequence[Series],
            findings: Sequence[Finding] = ()) -> CaptureProfile:
    endpoints: Dict[str, Dict[str, Any]] = {}
    hosts: Set[str] = set()
    zones: Counter = Counter()
    prints: Set[str] = set()
    transports: Counter = Counter()

    for one in series:
        channel = one.channel
        if channel.initiator:
            hosts.add(channel.initiator.value)
        zone = channel.dims.get("zone")
        if zone:
            zones[str(zone)] += one.count
        proto = channel.dims.get("proto") or channel.domain
        port = channel.dims.get("dport")
        transports[f"{proto}/{port}" if port else str(proto)] += one.count

        responder = channel.responder
        if not responder:
            continue
        entry = endpoints.setdefault(responder.value, {
            "names": set(), "bytes": 0, "obs": 0,
        })
        entry["bytes"] += one.bytes_egress + one.bytes_ingress
        entry["obs"] += one.count
        sni = channel.dims.get("sni")
        if sni:
            entry["names"].add(str(sni))
        for obs in one:
            fingerprint = obs.attrs.get("tls_fingerprint")
            if fingerprint:
                prints.add(str(fingerprint))
            qname = obs.attrs.get("qname")
            addresses = obs.attrs.get("resolved_ips")
            if qname and addresses:
                for address in str(addresses).split():
                    if address in endpoints:
                        endpoints[address]["names"].add(str(qname))

    keyed = {(f.rule_id, str(f.channel.key)): f for f in findings}
    return CaptureProfile(
        name=name, endpoints=endpoints, hosts=hosts, zones=zones,
        tls_prints=prints, transports=transports, findings=keyed,
    )


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def _rule(title: str) -> List[str]:
    return ["", f"── {title} " + "─" * max(0, 68 - len(title))]


def _bytes(count: float) -> str:
    for unit, scale in (("GB", 1 << 30), ("MB", 1 << 20), ("kB", 1 << 10)):
        if count >= scale:
            return f"{count / scale:.1f} {unit}"
    return f"{count:.0f} B"


def _wrap(text: str, width: int = 70, indent: str = "  ") -> List[str]:
    words = text.split()
    lines: List[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent + word
        else:
            current = f"{current} {word}" if current.strip() else indent + word
    if current.strip():
        lines.append(current.rstrip())
    return lines


def _endpoint_row(address: str, entry: Dict[str, Any]) -> str:
    names = ", ".join(sorted(entry["names"])[:3]) if entry["names"] else ""
    label = f"  {names}" if names else ""
    return (f"     {_bytes(entry['bytes']):>9}  {entry['obs']:>7,} exch  "
            f"{address}{label}")


def render_diff(reference: CaptureProfile, current: CaptureProfile,
                top_n: int = 12) -> str:
    out: List[str] = []
    out += _rule("CAPTURE DIFF")
    out += _wrap(
        f"{current.name} compared against {reference.name} as the "
        f"reference. \"New\" means present here and absent there — a literal "
        "comparison of these two files, not a rarity judgement; a "
        "destination can be ordinary in general and still be the one new "
        "thing between these captures."
    )
    out.append("")
    out.append(f"  reference    {reference.name}: "
               f"{len(reference.hosts):,} host(s), "
               f"{len(reference.endpoints):,} endpoint(s), "
               f"{len(reference.zones):,} zone(s)")
    out.append(f"  compared     {current.name}: "
               f"{len(current.hosts):,} host(s), "
               f"{len(current.endpoints):,} endpoint(s), "
               f"{len(current.zones):,} zone(s)")

    # -- actors first: a new ORIGINATOR is a new device or new software ----
    new_hosts = sorted(current.hosts - reference.hosts)
    gone_hosts = sorted(reference.hosts - current.hosts)
    if new_hosts:
        out += _rule("NEW ORIGINATING HOSTS")
        out += _wrap(
            "Addresses that ORIGINATED traffic here and originated nothing "
            "in the reference. A new originator is a new actor — a device "
            "that joined, or software that started speaking."
        )
        for host in new_hosts[:top_n]:
            out.append(f"     {host}")
        if len(new_hosts) > top_n:
            out.append(f"     … {len(new_hosts) - top_n:,} more")

    new_endpoints = {a: e for a, e in current.endpoints.items()
                     if a not in reference.endpoints}
    if new_endpoints:
        out += _rule("NEW ENDPOINTS")
        ranked = sorted(new_endpoints.items(), key=lambda kv: -kv[1]["bytes"])
        for address, entry in ranked[:top_n]:
            out.append(_endpoint_row(address, entry))
        if len(ranked) > top_n:
            out.append(f"     … {len(ranked) - top_n:,} more")

    gone_endpoints = {a: e for a, e in reference.endpoints.items()
                      if a not in current.endpoints}
    if gone_endpoints:
        out += _rule("NO LONGER CONTACTED")
        ranked = sorted(gone_endpoints.items(), key=lambda kv: -kv[1]["bytes"])
        for address, entry in ranked[:top_n]:
            out.append(_endpoint_row(address, entry))
        if len(ranked) > top_n:
            out.append(f"     … {len(ranked) - top_n:,} more")

    new_zones = [(z, c) for z, c in current.zones.most_common()
                 if z not in reference.zones]
    if new_zones:
        out += _rule("NEW DNS ZONES")
        for zone, count in new_zones[:top_n]:
            out.append(f"     {count:>7,} lookup(s)  {zone}")
        if len(new_zones) > top_n:
            out.append(f"     … {len(new_zones) - top_n:,} more")

    new_prints = sorted(current.tls_prints - reference.tls_prints)
    if new_prints:
        out += _rule("NEW TLS CLIENT STACKS")
        out += _wrap(
            "Handshake fingerprints seen here and never in the reference — "
            "TLS-speaking software that was not previously observed. The "
            "standing caveat applies: a fingerprint identifies the library, "
            "not intent."
        )
        for fingerprint in new_prints[:top_n]:
            out.append(f"     {fingerprint}")

    # -- volume shifts on endpoints present in both ------------------------
    shifts: List[Tuple[float, str, int, int]] = []
    for address, entry in current.endpoints.items():
        before = reference.endpoints.get(address)
        if before is None:
            continue
        now_b, then_b = entry["bytes"], before["bytes"]
        delta = abs(now_b - then_b)
        if delta < _SHIFT_FLOOR_BYTES:
            continue
        ratio = (now_b / then_b) if then_b else float("inf")
        if ratio >= _SHIFT_RATIO or (ratio > 0 and ratio <= 1 / _SHIFT_RATIO):
            shifts.append((delta, address, then_b, now_b))
    if shifts:
        out += _rule("VOLUME SHIFTS")
        out += _wrap(
            f"Endpoints present in both captures whose traffic multiplied "
            f"by {_SHIFT_RATIO:g}x or more in either direction, and moved at "
            f"least {_bytes(_SHIFT_FLOOR_BYTES)}. Both gates are required: a "
            "big ratio on tiny numbers is noise, and a big move on a huge "
            "channel can hide under a small ratio."
        )
        for delta, address, then_b, now_b in sorted(shifts, reverse=True)[:top_n]:
            arrow = "grew" if now_b > then_b else "shrank"
            names = current.endpoints[address]["names"]
            label = ("  " + ", ".join(sorted(names)[:2])) if names else ""
            out.append(f"     {address}{label}")
            out.append(f"        {arrow}: {_bytes(then_b)} → {_bytes(now_b)}")

    # -- findings ----------------------------------------------------------
    appeared = [f for key, f in current.findings.items()
                if key not in reference.findings]
    resolved = [f for key, f in reference.findings.items()
                if key not in current.findings]
    if appeared:
        out += _rule("FINDINGS THAT APPEARED")
        for finding in sorted(appeared, key=lambda f: -f.confidence)[:top_n]:
            out.append(f"     [{finding.severity.name:<8}] {finding.title}  "
                       f"(confidence {finding.confidence:.2f})")
            out.append(f"        {finding.rule_id}")
    if resolved:
        out += _rule("FINDINGS NO LONGER PRESENT")
        out += _wrap(
            "Fired on the reference capture and not on this one. Absence of "
            "evidence here, not evidence of absence: the behaviour may have "
            "stopped, or simply not recurred during this capture."
        )
        for finding in sorted(resolved, key=lambda f: -f.confidence)[:top_n]:
            out.append(f"     [{finding.severity.name:<8}] {finding.title}")
            out.append(f"        {finding.rule_id}")

    if len(out) <= 11:   # header block only — nothing differed
        out.append("")
        out += _wrap(
            "No new hosts, endpoints, zones, client stacks, qualifying "
            "volume shifts, or finding changes between these captures."
        )
    return "\n".join(out)
