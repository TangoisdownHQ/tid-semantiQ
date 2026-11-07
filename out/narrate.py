"""Narrate what was observed — not only what broke a rule.

WHY THIS EXISTS, and what it corrects. The tool was built findings-first: it
reports rule violations and otherwise says nothing. Run against twenty
minutes of real browsing it printed `0 findings` while holding 2,056 channels
of measurements — every cadence, every byte count, every SNI, every DNS zone
— and then threw all of it away. "Nothing matched my rules" is not an
interpretation of a capture. It is a refusal to give one.

So this is the observation report: everything the analysis measured, whether
or not a rule fired. It is computed, not generated — no model is involved,
every number traces to a primitive or an attribute, and nothing here can say
something the capture did not contain.

DOMAIN-AGNOSTIC BY CONSTRUCTION. The per-protocol sections are driven by
which `attrs` are actually present rather than by a list of protocols, so a
Modbus or MAVLink capture narrates through the same code as an HTTP one. A
section with nothing to say prints nothing.

VOLUME IS BOUNDED, and bounded honestly. A capture with 2,000 channels cannot
print 2,000 rows, so each section shows a ranked head and states the total it
was drawn from. A truncated list that does not say it was truncated reads as
a complete one.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from core.model import Direction, Evidence, Finding, Series

__all__ = ["narrate", "TOP_N"]

#: Rows per ranked section. Enough to see a pattern, few enough to read.
TOP_N = 12


def _rule(title: str) -> List[str]:
    return ["", f"── {title} " + "─" * max(0, 68 - len(title))]


def _bytes(count: float) -> str:
    for unit, scale in (("GB", 1 << 30), ("MB", 1 << 20), ("kB", 1 << 10)):
        if count >= scale:
            return f"{count / scale:.1f} {unit}"
    return f"{count:.0f} B"


def _duration(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} h"
    if seconds >= 60:
        return f"{seconds / 60:.1f} min"
    return f"{seconds:.1f} s"


def _when(ts: float) -> str:
    if not ts:
        return "unknown"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


#: Dims that identify the transport rather than the behaviour. Excluded from
#: a channel's printed identity because "proto=udp dport=53" on every DNS row
#: crowds out the part that differs.
_TRANSPORT_DIMS = frozenset({"proto", "dport", "host", "sni"})


def _names(series: Sequence[Series]) -> Dict[str, str]:
    """Map IP → the best name observed for it.

    THE REASON THIS IS NEEDED. Every ranked section used to print bare IPs,
    while the TLS section three screens above knew that 192.31.237.84 is
    www.ridemcts.com. The tool held the name and showed the number, which
    makes the reader do a join by hand across a report they are scrolling.

    TWO SOURCES, and the order matters. SNI names the address the client
    *intended* to reach; a DNS answer names what the resolver *said* the
    address was. SNI wins where both exist, because it is what the client
    asserted on the wire to that address rather than an association inferred
    across two different exchanges. DNS answers cover everything else —
    without them, an endpoint could only be named if it happened to speak
    TLS, which in a real capture left most of 117 addresses as bare numbers
    in a report whose job is to say what is going on.

    Where several names share an address (a CDN front), the most-observed
    one wins and the rest stay visible in the dossier — this is a label for
    reading, not an assertion that the address serves only that name.
    """
    sni, resolved = _name_sources(series)
    # Lowest priority: the name a device gave ITSELF over DHCP. It labels
    # LAN hosts that nothing ever resolves — exactly the addresses the other
    # two sources leave as bare numbers — but it is self-reported, so any
    # name the network actually asserted (DNS) or a client asserted to the
    # address (SNI) overrides it.
    names: Dict[str, str] = dict(_dhcp_names(series))
    names.update({
        address: counter.most_common(1)[0][0]
        for address, counter in resolved.items() if counter
    })
    names.update({
        address: counter.most_common(1)[0][0]
        for address, counter in sni.items() if counter
    })
    return names


def _dhcp_names(series: Sequence[Series]) -> Dict[str, str]:
    """Address → the hostname a device claimed for it in DHCP option 12.

    Keyed on `dhcp_addr` — the address the DHCP exchange was ABOUT (yiaddr
    on an assignment, the requested address on a request) — never on the
    packet's source, which for an unconfigured client is 0.0.0.0.
    """
    claimed: Dict[str, Counter] = defaultdict(Counter)
    for one in series:
        for obs in one:
            name = obs.attrs.get("dhcp_hostname")
            addr = obs.attrs.get("dhcp_addr")
            if name and addr:
                claimed[str(addr)][str(name)] += 1
    return {address: counter.most_common(1)[0][0]
            for address, counter in claimed.items() if counter}


def _name_sources(
    series: Sequence[Series],
) -> Tuple[Dict[str, Counter], Dict[str, Counter]]:
    """(names asserted via SNI, names a resolver returned), per address.

    Kept separate rather than merged because the dossier reports them
    separately: "the client asked this address for shop.test" and "the
    resolver said shop.test is at this address" are different observations,
    and a mismatch between them is worth being able to see.
    """
    sni: Dict[str, Counter] = defaultdict(Counter)
    resolved: Dict[str, Counter] = defaultdict(Counter)

    for one in series:
        responder = one.channel.responder
        if not responder:
            continue

        # SNI ONLY, NOT THE HTTP HOST HEADER. `Host:` is a claim by the
        # client about where it WANTED to go, and through a proxy it names a
        # third party rather than the server reading it. On a real capture
        # one request — `GET / Host: www.yahoo.com` sent to an infected
        # machine acting as an open proxy — was enough to label the busiest
        # host in the file "www.yahoo.com", and every section that prints a
        # name then repeated it.
        #
        # SNI is kept because it is at least addressed TO the server that
        # completed the handshake. A `Host` header is addressed to whoever
        # happens to read it.
        name = one.channel.dims.get("sni")
        if name:
            sni[responder.value][name] += one.count

        # A response carries the name it was asked about and the addresses
        # the resolver returned for it, so the pairing is within one message
        # rather than guessed across a flow.
        for obs in one:
            addresses = obs.attrs.get("resolved_ips")
            qname = obs.attrs.get("qname")
            if not addresses or not qname:
                continue
            for address in str(addresses).split():
                resolved[address][str(qname)] += 1

    return sni, resolved


def _identity(channel, names: Optional[Mapping[str, str]] = None) -> str:
    """What distinguishes this channel, for a one-line row.

    Prints the dims that carry the behaviour (zone, qtype, msgid, fc) rather
    than the ones that carry the transport. Without this, every DNS row in
    every ranked section read `192.168.122.228 → 192.168.122.1` and the five
    top-cadence channels were indistinguishable from one another.
    """
    marks = [
        f"{key}={value}" for key, value in sorted(channel.dims.items())
        if key not in _TRANSPORT_DIMS
    ]
    name = channel.dims.get("host") or channel.dims.get("sni") or ""
    if not name and names and channel.responder:
        name = names.get(channel.responder.value, "")

    if channel.initiator and channel.responder:
        pair = f"{channel.initiator.value} → {channel.responder.value}"
    elif channel.responder:
        pair = channel.responder.value
    else:
        pair = channel.domain

    detail = " ".join(marks)
    return "  ".join(part for part in (pair, name, detail) if part)


def _host(series: Series, names: Optional[Mapping[str, str]] = None) -> str:
    return _identity(series.channel, names)


# --------------------------------------------------------------------------


def narrate(
    series: Sequence[Series],
    evidences: Sequence[Evidence],
    findings: Sequence[Finding] = (),
    stats: Optional[Mapping[str, Any]] = None,
    redactor=None,
    source_name: str = "",
    top_n: int = TOP_N,
    trace: int = 0,
    glossary: bool = False,
    enricher=None,
) -> str:
    """A full account of the capture, computed from what was measured."""
    if redactor is None:
        from core.redact import redact_secrets
        redactor = redact_secrets

    # Materialise first. Every section below walks `series` independently,
    # so a generator — which is exactly what `group_into_series` returns —
    # would feed the first section and leave the rest to narrate an empty
    # capture. That failure mode is silent: the report still renders, just
    # without most of what was observed.
    series = list(series)
    evidences = list(evidences)

    by_key = {e.channel.key: e for e in evidences}
    names = _names(series)
    lines: List[str] = []

    # One line first of all: what kind of capture is this? A reader who
    # stops after the first sentence should still have the gist.
    lines += _verdict(series, stats, names)
    # Prose next. The tables are the evidence for it and a reader who stops
    # after the first screen should still have been told what the capture is.
    lines += _interpretation(series, by_key, stats, top_n)
    lines += _overview(series, stats, source_name)
    # Early, because it qualifies everything below it: a reader should know
    # the record is suspect before reading measurements computed from it.
    lines += _capture_integrity(stats)
    lines += _neighbor_conflicts(stats)
    lines += _wireless(stats)
    lines += _encrypted_dns(series)
    lines += _timeline(series, top_n)
    lines += _connections(stats, names, top_n)
    lines += _endpoints(series, names, top_n)
    lines += _protocol_detail(series, top_n)
    # Dossiers after the aggregate tables: the tables are how something gets
    # noticed, these are how it gets followed up.
    # Hosts before endpoints: "what did this host do" is the question a
    # reader has first, and on a multi-host capture it had no section.
    host_macs = (stats or {}).get("host_macs") or {}
    os_fp = (stats or {}).get("os_fingerprints") or {}
    lines += _host_detail(series, names, by_key, top_n, enricher, host_macs, os_fp)
    lines += _endpoint_detail(series, names, by_key, top_n, enricher, os_fp)
    lines += _zone_detail(series, by_key, top_n)
    # Per-exchange detail last among the measurement sections: it is the
    # longest output and the most specific, so it follows the aggregates
    # that tell a reader which channel to look at.
    lines += _behaviour(series, by_key, names, top_n)
    lines += _trace(series, names, trace)
    lines += _content(evidences, redactor, top_n)
    lines += _not_assessed(series, by_key)
    # The glossary reads the report that was just built and defines only the
    # terms that appeared in it, so it must be assembled last — and from the
    # body alone, never from itself, or the definitions would trigger each
    # other and every term would always print.
    if glossary:
        from out.glossary import glossary_section
        lines += glossary_section("\n".join(lines))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------


def _overview(series, stats, source_name) -> List[str]:
    out = _rule("CAPTURE")
    starts = [s.start for s in series if s.start is not None]
    ends = [s.end for s in series if s.end is not None]
    first, last = (min(starts), max(ends)) if starts else (0.0, 0.0)

    if source_name:
        out.append(f"  file        {source_name}")
    if stats:
        frames = int(stats.get("frames") or 0)
        decoded = int(stats.get("decoded") or 0)
        if frames:
            share = 100.0 * decoded / frames
            out.append(f"  frames      {frames:,} read, {decoded:,} decoded "
                       f"({share:.1f}%)")
            if decoded < frames:
                # Undecoded frames are usually ARP or a non-IP ethertype, not
                # a defect — but an unexplained gap is worth seeing.
                out.append(f"              {frames - decoded:,} not IP/TCP/UDP "
                           "(ARP, link-local, or an unhandled ethertype)")
        mix = [
            f"{int(stats[k]):,} {k}" for k in ("tcp", "udp", "dns", "http")
            if stats.get(k)
        ]
        if mix:
            out.append(f"  transport   {' · '.join(mix)}")

    observations = sum(s.count for s in series)
    out.append(f"  observed    {observations:,} exchanges on "
               f"{len(series):,} channels")
    if first:
        out.append(f"  spanning    {_duration(last - first)}   "
                   f"{_when(first)} → {_when(last)}")

    domains = Counter(s.channel.domain for s in series)
    out.append("  domains     " + " · ".join(
        f"{name} {count:,}" for name, count in domains.most_common()
    ))

    initiators = {
        s.channel.initiator.value for s in series if s.channel.initiator
    }
    responders = {
        s.channel.responder.value for s in series if s.channel.responder
    }
    out.append(f"  endpoints   {len(initiators):,} initiator(s), "
               f"{len(responders):,} responder(s)")
    return out


def _endpoints(series, names, top_n) -> List[str]:
    """Who talked to whom, by volume. The first question anyone asks."""
    totals: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"out": 0, "in": 0, "obs": 0, "first": None, "last": None,
                 "series": None}
    )
    for one in series:
        if not (one.channel.initiator and one.channel.responder):
            continue
        key = f"{one.channel.initiator.value}→{one.channel.responder.value}"
        entry = totals[key]
        entry["peer"] = one.channel.responder.value
        entry["out"] += one.bytes_egress
        entry["in"] += one.bytes_ingress
        entry["obs"] += one.count
        entry["series"] = entry["series"] or one
        if one.start is not None:
            entry["first"] = (one.start if entry["first"] is None
                              else min(entry["first"], one.start))
        if one.end is not None:
            entry["last"] = (one.end if entry["last"] is None
                             else max(entry["last"], one.end))

    if not totals:
        return []

    ranked = sorted(
        totals.items(), key=lambda kv: kv[1]["out"] + kv[1]["in"], reverse=True
    )
    out = _rule(f"CONVERSATIONS  (top {min(top_n, len(ranked))} of "
                f"{len(ranked):,} by volume)")
    for key, entry in ranked[:top_n]:
        span = ((entry["last"] or 0) - (entry["first"] or 0))
        name = names.get(entry.get("peer", ""), "")
        label = f"{key}  {name}".rstrip()
        if len(label) > 58:
            label = label[:57] + "…"
        out.append(
            f"  {label:<58} {_bytes(entry['out']):>9} out  "
            f"{_bytes(entry['in']):>9} in  "
            f"{entry['obs']:>5} exch  {_duration(span):>8}"
        )
    hidden = len(ranked) - top_n
    if hidden > 0:
        quiet = sum(e["out"] + e["in"] for _k, e in ranked[top_n:])
        out.append(f"  … {hidden:,} further conversation(s) totalling "
                   f"{_bytes(quiet)}")
    return out


def _measured(addr_series, by_key) -> str:
    """The primitive scores for a set of series, as one compact line.

    Reported per entity rather than only in the global rankings, because a
    ranking answers "which channel was most periodic" and a dossier answers
    "what do I know about THIS host" — and the second is the question
    someone triaging an address actually has.
    """
    best: Dict[str, float] = {}
    for one in addr_series:
        evidence = by_key.get(one.channel.key)
        if evidence is None:
            continue
        for result in evidence.results:
            if result.name == "_scoring":
                continue
            best[result.name] = max(best.get(result.name, 0.0), result.score)
    if not best:
        return ""
    ranked = sorted(best.items(), key=lambda kv: -kv[1])
    return " · ".join(f"{name} {score:.2f}" for name, score in ranked[:6])




def _scope(address: str) -> str:
    """Accurate wording for what kind of address this is.

    Imported lazily so `out/` keeps no import-time dependency on `capture/`;
    the narrator consumes the model, and this is the one address-semantics
    question it cannot answer from the model alone.
    """
    try:
        from capture.decode import scope_of
    except ImportError:          # pragma: no cover
        return ""
    return scope_of(address)


def _addresses_itself(target: str, address: str,
                       known: Optional[str] = None) -> bool:
    """Is this Host header just naming the server it was sent to?

    `Host: 127.0.0.1:18080` delivered to 127.0.0.1 is a client addressing
    the machine it connected to — completely ordinary, and not proxying.
    The first live capture on loopback reported fourteen such requests as
    "addressed to other names", because the comparison was against the
    address's resolved NAME and a bare `IP:port` never matches one.

    The port is stripped before comparing: a Host header carries the port
    when it is non-default, and `127.0.0.1:18080` and `127.0.0.1` are the
    same host.
    """
    bare = target.rsplit(":", 1)[0] if ":" in target else target
    # An IPv6 literal in a Host header is bracketed, so the rsplit above is
    # safe for it too — "[::1]:8080" -> "[::1]".
    bare = bare.strip("[]")
    return bare in (address, known) or target in (address, known)


def _os_line(os_fp, address) -> Optional[str]:
    """A one-line passive OS reading for an address, or None.

    Shared by the host and endpoint dossiers. The inference is shown, not
    just the verdict: the arriving TTL, the initial it implies, the hop
    distance, and the MSS — so a reader can check the reasoning. A shape the
    classifier does not recognise still prints its raw signals rather than a
    guess.
    """
    sig = (os_fp or {}).get(address)
    if not sig:
        return None
    from capture.osfp import classify
    family = classify(sig)
    detail = []
    if sig.get("initial_ttl") and sig.get("hops") is not None:
        detail.append(f"TTL {sig['ttl']}→{sig['initial_ttl']}, "
                      f"~{sig['hops']} hop(s)")
    elif sig.get("ttl"):
        detail.append(f"TTL {sig['ttl']}")
    if sig.get("mss"):
        detail.append(f"MSS {sig['mss']}")
    tail = ("  ·  " + " · ".join(detail)) if detail else ""
    if family:
        return f"{family}{tail}"
    return f"unrecognised stack{tail}" if detail else None


def _host_detail(series, names, by_key, top_n, enricher=None,
                 host_macs=None, os_fp=None) -> List[str]:
    """One block per originating host: everything IT did.

    THE GAP THIS FILLS. Every other dossier is organised by the address that
    was REACHED, which answers "what is 203.0.113.9" and cannot answer "what
    did this host do". On a single-host capture the two collapse and the
    omission is invisible; on a capture with eight originating hosts —
    which is what exposed it — the first question anyone asks has no section
    to answer it.

    So this is the per-actor view: who it talked to, what protocols it
    spoke, what it looked up and whether that worked, when it was active,
    and what shapes its traffic took. Ordered by volume, because the busiest
    host is where a reader starts.
    """
    hosts: Dict[str, Dict[str, Any]] = {}

    # Requests each address RECEIVED, and the name they were addressed to.
    # Collected separately from the originator view because the interesting
    # case is a host being SENT requests for somewhere else.
    received: Dict[str, Counter] = defaultdict(Counter)
    for one in series:
        if one.channel.domain != "http" or not one.channel.responder:
            continue
        target = one.channel.dims.get("host")
        if target:
            received[one.channel.responder.value][str(target)] += one.count

    for one in series:
        initiator = one.channel.initiator
        if not initiator:
            continue
        who = initiator.value
        entry = hosts.get(who)
        if entry is None:
            entry = hosts[who] = {
                "out": 0, "in": 0, "obs": 0, "channels": 0,
                "first": None, "last": None, "series": [],
                "peers": Counter(), "domains": Counter(),
                "zones": Counter(), "rcodes": Counter(),
                "transports": Counter(), "sni": Counter(),
                "addressed_to": Counter(), "served": 0,
                "private": initiator.labels.get("private"),
                # Distinct ClientHello shapes this host presented, keyed by
                # fingerprint: (grease, alpn, ciphers, exts) -> channel count.
                "tls_clients": {},
            }
        entry["out"] += one.bytes_egress
        entry["in"] += one.bytes_ingress
        entry["obs"] += one.count
        entry["channels"] += 1
        entry["series"].append(one)
        entry["domains"][one.channel.domain] += one.count
        if one.channel.responder:
            entry["peers"][one.channel.responder.value] += one.count
        zone = one.channel.dims.get("zone")
        if zone:
            entry["zones"][str(zone)] += one.count
        name = one.channel.dims.get("sni") or one.channel.dims.get("host")
        if name:
            entry["sni"][str(name)] += one.count
        proto = one.channel.dims.get("proto") or one.channel.domain
        port = one.channel.dims.get("dport")
        entry["transports"][f"{proto}/{port}" if port else str(proto)] += one.count
        if one.start is not None:
            entry["first"] = (one.start if entry["first"] is None
                              else min(entry["first"], one.start))
        if one.end is not None:
            entry["last"] = (one.end if entry["last"] is None
                             else max(entry["last"], one.end))
        counted_client = False
        for obs in one:
            code = obs.attrs.get("rcode_name")
            if code:
                entry["rcodes"][str(code)] += 1
            # One ClientHello shape per channel, not per burst — every burst
            # on a TLS flow repeats the same handshake facts, and counting
            # each would weight a chatty channel as many clients.
            if not counted_client and obs.attrs.get("tls_client_grease") is not None:
                print_id = str(obs.attrs.get("tls_fingerprint", ""))
                shape = entry["tls_clients"].setdefault(print_id, {
                    "grease": obs.attrs["tls_client_grease"] == "1",
                    "alpn": tuple(
                        str(obs.attrs.get("tls_client_alpn", "")).split(",")
                    ) if obs.attrs.get("tls_client_alpn") else (),
                    "ciphers": int(obs.attrs.get("tls_client_ciphers", 0) or 0),
                    "exts": int(obs.attrs.get("tls_client_exts", 0) or 0),
                    "channels": 0,
                })
                shape["channels"] += 1
                counted_client = True

    if not hosts:
        return []

    ranked = sorted(hosts.items(), key=lambda kv: -(kv[1]["out"] + kv[1]["in"]))
    out = _rule(f"HOST DETAIL  (top {min(top_n, len(ranked))} of "
                f"{len(ranked):,} originating host(s))")

    for who, entry in ranked[:top_n]:
        out.append("")
        label = names.get(who, "")
        out.append(f"  {who}" + (f"  {label}" if label else ""))

        scope = _scope(who)
        if scope:
            out.append(f"    {'scope':<12} {scope}")

        # Device vendor from the host's own source MAC — only ever recorded
        # for a LAN address (the capture layer refuses public ones, whose
        # source MAC is the gateway's). The MAC itself is shown so the
        # reading can be checked; a randomised or locally-administered MAC
        # yields no vendor and is reported as the privacy measure it is.
        mac = (host_macs or {}).get(who)
        if mac:
            vendor = enricher.lookup_mac(mac) if (
                enricher is not None and enricher.loaded) else None
            if vendor:
                out.append(f"    {'device':<12} {vendor}  ({mac})")
            elif mac.split(":")[0] and int(mac.split(":")[0], 16) & 0x02:
                out.append(f"    {'device':<12} {mac} — randomised "
                           "(locally-administered MAC, names no vendor)")

        os_reading = _os_line(os_fp, who)
        if os_reading:
            out.append(f"    {'stack':<12} {os_reading}")

        out.append(
            f"    {'volume':<12} {_bytes(entry['out'])} sent, "
            f"{_bytes(entry['in'])} received over {entry['obs']:,} exchanges"
        )
        out.append(f"    {'reached':<12} "
                   f"{_plural(len(entry['peers']), 'address', 'addresses')} "
                   f"on {_plural(entry['channels'], 'channel')}")
        busiest = ", ".join(
            f"{(names.get(peer) or peer)} ({count:,})"
            for peer, count in entry["peers"].most_common(4)
        )
        if busiest:
            out.append(f"    {'busiest':<12} {busiest}")
        if entry["first"]:
            out.append(
                f"    {'active':<12} {_when(entry['first'])} → "
                f"{_when(entry['last'])}  "
                f"({_duration((entry['last'] or 0) - entry['first'])})"
            )
        out.append(f"    {'protocols':<12} " + " · ".join(
            f"{name} {count:,}" for name, count in entry["domains"].most_common()
        ))
        out.append(f"    {'transport':<12} " + " · ".join(
            f"{label} ({count:,})"
            for label, count in entry["transports"].most_common(5)
        ))
        if entry["sni"]:
            shown = ", ".join(f"{value}" for value, _c
                              in entry["sni"].most_common(5))
            more = (f", +{len(entry['sni']) - 5:,} more"
                    if len(entry["sni"]) > 5 else "")
            out.append(f"    {'named hosts':<12} "
                       f"{len(entry['sni']):,} distinct: {shown}{more}")

        # What TLS client software the host's handshakes are consistent
        # with — a reading of the ClientHello's shape (GREASE, ALPN, list
        # lengths), never of intent. Several distinct shapes from one host
        # is itself informative: a browser plus a separate library stack is
        # two pieces of software talking.
        if entry["tls_clients"]:
            from capture.tlsfp import classify_client
            ranked_fp = sorted(entry["tls_clients"].items(),
                               key=lambda kv: -kv[1]["channels"])
            label = "tls client"
            for print_id, shape in ranked_fp[:3]:
                profile = classify_client(
                    uses_grease=shape["grease"], alpn=shape["alpn"],
                    cipher_count=shape["ciphers"], ext_count=shape["exts"],
                )
                out.append(
                    f"    {label:<12} {profile.family}"
                )
                out.append(
                    f"    {'':<12}   {print_id or 'no print'} on "
                    f"{_plural(shape['channels'], 'channel')}: "
                    + "; ".join(profile.signals)
                )
                label = ""
            if len(ranked_fp) > 3:
                out.append(f"    {'':<12} +{len(ranked_fp) - 3} more "
                           "distinct handshake shape(s)")
            if len(ranked_fp) > 1:
                out.append(
                    f"    {'':<12} {len(ranked_fp)} distinct TLS stacks "
                    "from one host — more than one piece of software is "
                    "originating TLS here"
                )
        if entry["zones"]:
            out.append(f"    {'dns zones':<12} "
                       f"{len(entry['zones']):,} distinct; busiest " + ", ".join(
                           f"{value} ({count:,})" for value, count
                           in entry["zones"].most_common(3)
                       ))
        if entry["rcodes"]:
            answered = sum(entry["rcodes"].values())
            ok = entry["rcodes"].get("NOERROR", 0)
            out.append(
                f"    {'dns outcome':<12} {ok:,} of {answered:,} lookups "
                f"resolved ({100.0 * ok / answered:.0f}%)"
                + ("; " + " · ".join(
                    f"{code} {count:,}" for code, count
                    in entry["rcodes"].most_common(3) if code != "NOERROR"
                ) if answered > ok else "")
            )

        # Requests sent TO this host, addressed to somewhere else. A
        # server reading a Host header naming a third-party site is being
        # asked to fetch on the client's behalf — which is what an open
        # proxy does, and what a proxy probe looks for. Described rather
        # than judged: a reverse proxy and a CDN edge look identical here.
        inbound = received.get(who) or Counter()
        elsewhere = {
            target: count for target, count in inbound.items()
            if not _addresses_itself(target, who, names.get(who))
        }
        if elsewhere:
            listed = ", ".join(f"{target} ({count:,})" for target, count
                               in sorted(elsewhere.items(),
                                         key=lambda kv: -kv[1])[:4])
            out.append(
                f"    {'served':<12} received "
                f"{sum(elsewhere.values()):,} HTTP request(s) addressed to "
                f"{_plural(len(elsewhere), 'other name')}: {listed}"
            )
            out.append(
                f"    {'':<12} a host asked to fetch names that are not "
                f"its own is acting as a proxy — deliberately (a reverse "
                f"proxy, a CDN edge) or not (an open proxy, or a probe "
                f"testing for one)"
            )

        # The shapes this host's traffic took, which is the part that says
        # what it was DOING rather than merely who it spoke to.
        shapes: Counter = Counter()
        for one in entry["series"]:
            if one.count < 4:
                continue
            verdict, _facts = _shape(one)
            if verdict:
                shapes[verdict.split(" — ")[0]] += 1
        if shapes:
            out.append(f"    {'activity':<12} " + " · ".join(
                f"{kind} ({count})" for kind, count in shapes.most_common(4)
            ))

        line = _measured(entry["series"], by_key)
        if line:
            out.append(f"    {'measured':<12} {line}")

    hidden = len(ranked) - top_n
    if hidden > 0:
        out.append("")
        out.append(f"  … {hidden:,} further originating host(s) "
                   f"(raise --top)")

    # The caveat prints once per section, not per reading — it is the same
    # sentence every time, and repetition would train the reader to skip it.
    if any(e["tls_clients"] for _w, e in ranked[:top_n]):
        from capture.tlsfp import CAVEAT
        out.append("")
        out += _wrap(CAVEAT, indent="  ")
    return out


def _endpoint_detail(series, names, by_key, top_n, enricher=None,
                     os_fp=None) -> List[str]:
    """One block per endpoint: address, names, transport, volume, measurements.

    WHY SEPARATE BLOCKS. Everything else in this report is organised by
    QUESTION — who sent the most, what was most periodic — which is the
    right shape for noticing something and the wrong shape for following up
    on it. Having noticed 192.31.237.84, an analyst then wants every fact
    the capture holds about that one address, and assembling it from six
    ranked tables by hand is work the tool should have done.

    Facts only, and each one labelled with what it was counted from. Where
    an address served several names, all of them are listed with their
    exchange counts rather than the single winning label used elsewhere: a
    CDN address genuinely serves many names and collapsing that is a loss.
    """
    _sni, resolved = _name_sources(series)
    peers: Dict[str, Dict[str, Any]] = {}
    for one in series:
        channel = one.channel
        if not channel.responder:
            continue
        address = channel.responder.value
        entry = peers.get(address)
        if entry is None:
            entry = peers[address] = {
                "out": 0, "in": 0, "obs": 0, "channels": 0,
                "first": None, "last": None, "series": [],
                "names": Counter(), "transports": Counter(),
                "versions": Counter(), "cert": None,
                "cert_absence": set(), "records": {}, "alpn": set(),
                # Per-TCP-stream app-data record maxes, so the request
                # estimate can SUM across the endpoint's connections rather
                # than report only the busiest one. HTTP/2 opens many.
                "out_by_stream": {}, "in_by_stream": {},
                "prints": Counter(), "from": Counter(), "domains": Counter(),
                "qtypes": Counter(), "rcodes": Counter(), "zones": Counter(),
                "private": channel.responder.labels.get("private"),
            }
        entry["out"] += one.bytes_egress
        entry["in"] += one.bytes_ingress
        entry["obs"] += one.count
        entry["channels"] += 1
        entry["series"].append(one)
        entry["domains"][channel.domain] += one.count
        if channel.initiator:
            entry["from"][channel.initiator.value] += one.count
        for key, bucket in (("zone", "zones"), ("qtype", "qtypes")):
            value = channel.dims.get(key)
            if value:
                entry[bucket][str(value)] += one.count

        # Paired per channel, NOT as a cross product of protocols against
        # ports. Crossing them claimed `udp/67` for a DNS resolver whose
        # only dport-carrying channel was DHCP, which read as "all 26,404
        # exchanges were DHCP" — a confident statement about the wrong
        # protocol. Channels with no dport dim (DNS keys on zone instead)
        # contribute the protocol alone rather than borrowing another
        # channel's port.
        proto = channel.dims.get("proto") or channel.domain
        port = channel.dims.get("dport")
        entry["transports"][f"{proto}/{port}" if port else str(proto)] += one.count
        if one.start is not None:
            entry["first"] = (one.start if entry["first"] is None
                              else min(entry["first"], one.start))
        if one.end is not None:
            entry["last"] = (one.end if entry["last"] is None
                             else max(entry["last"], one.end))
        for obs in one:
            for attr, bucket in (("sni", "names"), ("host", "names"),
                                 ("tls_fingerprint", "prints"),
                                 ("tls_version", "versions"),
                                 ("rcode_name", "rcodes")):
                value = obs.attrs.get(attr)
                if value:
                    entry[bucket][str(value)] += 1
            # First certificate wins: one address serving several names can
            # present several, and the dossier reports a representative one
            # rather than implying it saw only this.
            if entry["cert"] is None and obs.attrs.get("cert_subject"):
                entry["cert"] = {
                    key: obs.attrs[key] for key in (
                        "cert_subject", "cert_issuer", "cert_not_before",
                        "cert_not_after", "cert_sans", "cert_self_signed",
                        "cert_covers_sni",
                    ) if obs.attrs.get(key)
                }
            # Flow-level running totals, so the largest value seen on
            # the channel is the flow's final count rather than a sum over
            # bursts that would multiply it.
            for key, value in obs.attrs.items():
                if key.startswith("tls_rec_"):
                    try:
                        entry["records"][key] = max(
                            int(entry["records"].get(key, 0)), int(value)
                        )
                    except (TypeError, ValueError):
                        entry["records"][key] = value
            visible = obs.attrs.get("cert_visible")
            if visible and visible != "visible":
                entry["cert_absence"].add(str(visible))
            alpn = obs.attrs.get("tls_client_alpn")
            if alpn:
                entry["alpn"].update(a.strip() for a in str(alpn).split(","))
            # Per-connection record totals (each flow's cumulative count,
            # keyed on its TCP stream), for a per-endpoint request estimate.
            stream = obs.locus.stream if obs.locus else None
            if stream is not None:
                for attr, bucket in (("tls_rec_out", "out_by_stream"),
                                     ("tls_rec_in", "in_by_stream")):
                    val = obs.attrs.get(attr)
                    if val:
                        entry[bucket][stream] = max(
                            entry[bucket].get(stream, 0), int(val))

    if not peers:
        return []

    ranked = sorted(peers.items(), key=lambda kv: -(kv[1]["out"] + kv[1]["in"]))
    out = _rule(f"ENDPOINT DETAIL  (top {min(top_n, len(ranked))} of "
                f"{len(ranked):,} by volume)")
    if enricher is not None and enricher.loaded:
        out += _wrap(
            "Network attribution from local datasets ("
            + enricher.describe()
            + "), resolved offline — no lookup leaves this machine, and the "
            "answer is as current as the files.",
        )

    for address, entry in ranked[:top_n]:
        out.append("")
        out.append(f"  {address}")

        if entry["names"]:
            first = True
            for name, count in entry["names"].most_common(6):
                label = "names" if first else ""
                out.append(f"    {label:<12} {name}  ({count:,} exchanges)")
                first = False
            if len(entry["names"]) > 6:
                out.append(f"    {'':<12} … {len(entry['names']) - 6:,} "
                           f"further name(s) on this address")
        elif names.get(address):
            out.append(f"    {'names':<12} {names[address]}")

        # Separate from `names` above, which is what the client asserted via
        # SNI. This is what a resolver said, which is a different claim and
        # occasionally a conflicting one.
        from_dns = resolved.get(address)
        if from_dns:
            out.append(f"    {'resolved as':<12} " + ", ".join(
                f"{name} ({count:,} answer(s))"
                for name, count in from_dns.most_common(4)
            ) + (f", +{len(from_dns) - 4:,} more"
                 if len(from_dns) > 4 else ""))
        elif not entry["names"] and address not in (names or {}):
            out.append(f"    {'resolved as':<12} no DNS answer in this "
                       f"capture pointed at this address")

        scope = _scope(address)
        if scope:
            out.append(f"    {'scope':<12} {scope}")

        os_reading = _os_line(os_fp, address)
        if os_reading:
            out.append(f"    {'stack':<12} {os_reading}")

        # Offline enrichment: who announces this address, and which cloud
        # it sits in. The wording is deliberate — an ASN names who announces
        # the ROUTE, and a cloud range names the LANDLORD, not the tenant.
        # "in AWS us-east-1" is a fact; "is Amazon" would be an attribution
        # the data cannot support.
        if enricher is not None and enricher.loaded:
            hit = enricher.lookup(address)
            if hit is not None:
                if hit.asn is not None:
                    country = f" ({hit.country})" if hit.country else ""
                    out.append(f"    {'announced by':<12} AS{hit.asn} "
                               f"{hit.as_name or ''}{country}".rstrip())
                if hit.provider:
                    place = f" {hit.region}" if hit.region else ""
                    service = f", {hit.service}" if hit.service else ""
                    out.append(f"    {'cloud':<12} in {hit.provider}"
                               f"{place}{service} — the range's landlord, "
                               "not necessarily who runs the endpoint")

        callers = ", ".join(
            f"{who} ({count:,})" for who, count in entry["from"].most_common(4)
        )
        if callers:
            out.append(f"    {'reached by':<12} {callers}")

        if entry["transports"]:
            out.append(f"    {'transport':<12} " + " · ".join(
                f"{label} ({count:,})"
                for label, count in entry["transports"].most_common(5)
            ))

        out.append(
            f"    {'volume':<12} {_bytes(entry['out'])} out, "
            f"{_bytes(entry['in'])} in over {entry['obs']:,} exchanges "
            f"on {_plural(entry['channels'], 'channel')}"
        )
        if entry["first"]:
            out.append(
                f"    {'active':<12} {_when(entry['first'])} → "
                f"{_when(entry['last'])}  "
                f"({_duration((entry['last'] or 0) - entry['first'])})"
            )
        out.append(f"    {'protocols':<12} " + " · ".join(
            f"{name} {count:,}" for name, count in entry["domains"].most_common()
        ))

        if entry["versions"]:
            out.append(f"    {'tls':<12} " + " · ".join(
                f"{value} ({count:,})"
                for value, count in entry["versions"].most_common(4)
            ))
        if entry["records"]:
            shape = entry["records"]
            for label, heading in (("out", "sent"), ("in", "received")):
                count = shape.get(f"tls_rec_{label}")
                if not count:
                    continue
                full = int(shape.get(f"tls_rec_{label}_full", 0))
                small = int(shape.get(f"tls_rec_{label}_small", 0))
                total = max(1, int(count))
                out.append(
                    f"    {'records ' + heading:<12} {int(count):,} TLS "
                    f"record(s), mean {shape.get(f'tls_rec_{label}_mean', '?')}B, "
                    f"max {int(shape.get(f'tls_rec_{label}_max', 0)):,}B"
                )
                # Shares, because the counts alone do not say which shape
                # dominates: 40 full records out of 10,000 is not a bulk
                # transfer and 40 out of 45 is.
                out.append(
                    f"    {'':<12} {100.0 * full / total:.0f}% full "
                    f"(bulk), {100.0 * small / total:.0f}% tiny "
                    f"(interactive or control)"
                )
            # HTTP/2 request-count estimate: how many requests the multiplexed
            # connection carried, inferred from outbound record framing with
            # no decryption. Only where ALPN negotiated h2 and only as a
            # labelled estimate with its caveat.
            from out.http2infer import estimate_requests
            total_out = sum(entry["out_by_stream"].values())
            total_in = sum(entry["in_by_stream"].values())
            conns = len(entry["out_by_stream"])
            est = estimate_requests(entry["alpn"], total_out, total_in)
            if est:
                across = (f" across {_plural(conns, 'connection')}"
                          if conns > 1 else "")
                out.append(f"    {'requests':<12} ≈ {est['requests_proxy']:,} "
                           f"(HTTP/2 estimate{across}, from {est['basis']})")
                out += _wrap(est["caveat"], indent="                 ")
        if entry["prints"]:
            out.append(f"    {'tls print':<12} " + " · ".join(
                f"{value} ({count:,})"
                for value, count in entry["prints"].most_common(3)
            ))
        if entry["cert"]:
            cert = entry["cert"]
            subject = cert.get("cert_subject", "")
            issuer = cert.get("cert_issuer", "")
            if subject:
                out.append(f"    {'certificate':<12} subject {subject}")
            if issuer:
                marker = " (self-signed)" if cert.get("cert_self_signed") else ""
                out.append(f"    {'':<12} issuer  {issuer}{marker}")
            if cert.get("cert_not_before") or cert.get("cert_not_after"):
                out.append(f"    {'':<12} valid   "
                           f"{cert.get('cert_not_before', '?')} → "
                           f"{cert.get('cert_not_after', '?')}")
            if cert.get("cert_sans"):
                sans = str(cert["cert_sans"]).split()
                shown = ", ".join(sans[:6])
                more = (f", +{len(sans) - 6:,} more" if len(sans) > 6 else "")
                out.append(f"    {'':<12} names   {shown}{more}")
            # Stated explicitly in both directions. A silent absence here
            # would read as "fine", and a mismatch is the single most useful
            # thing a certificate can tell you.
            covers = cert.get("cert_covers_sni")
            if covers == "0":
                out.append(f"    {'':<12} MISMATCH — does not cover the "
                           f"requested name")
            elif covers == "1":
                out.append(f"    {'':<12} covers the requested name")
        elif entry["cert_absence"]:
            out.append(f"    {'certificate':<12} "
                       + " · ".join(sorted(entry["cert_absence"])))
        if entry["qtypes"]:
            out.append(f"    {'dns qtypes':<12} " + " · ".join(
                f"{value} {count:,}"
                for value, count in entry["qtypes"].most_common(6)
            ))
        if entry["zones"]:
            out.append(f"    {'dns zones':<12} "
                       f"{len(entry['zones']):,} distinct; busiest " + ", ".join(
                           f"{value} ({count:,})"
                           for value, count in entry["zones"].most_common(3)
                       ))
        if entry["rcodes"]:
            answered = sum(entry["rcodes"].values())
            ok = entry["rcodes"].get("NOERROR", 0)
            out.append(
                f"    {'dns outcome':<12} {ok:,} of {answered:,} resolved; "
                + " · ".join(f"{code} {count:,}" for code, count
                             in entry["rcodes"].most_common(4)
                             if code != "NOERROR")
            )
        line = _measured(entry["series"], by_key)
        if line:
            out.append(f"    {'measured':<12} {line}")

    hidden = len(ranked) - top_n
    if hidden > 0:
        out.append("")
        out.append(f"  … {hidden:,} further endpoint(s) not detailed "
                   f"(raise --top, or see --out json for all of them)")
    return out


def _zone_detail(series, by_key, top_n) -> List[str]:
    """One block per DNS zone: the names asked for, and what came back.

    The zone is the unit the DNS channel is keyed on, so it is the unit at
    which "what was asked, and did it work" can be answered exactly. A
    capture where one zone resolves cleanly and another returns NXDOMAIN on
    every lookup is two different stories, and the aggregate rcode table
    cannot tell them apart.
    """
    from core.suffixes import default_list
    psl = default_list()

    zones: Dict[str, Dict[str, Any]] = {}
    for one in series:
        if one.channel.domain != "dns":
            continue
        zone = one.channel.dims.get("zone")
        if not zone:
            continue
        entry = zones.get(zone)
        if entry is None:
            entry = zones[zone] = {
                "names": Counter(), "qtypes": Counter(), "rcodes": Counter(),
                "obs": 0, "queries": 0, "first": None, "last": None,
                "from": Counter(), "via": Counter(), "series": [],
                "lengths": [], "addresses": Counter(), "cnames": Counter(),
                "ttls": [],
            }
        entry["obs"] += one.count
        entry["series"].append(one)
        if one.channel.initiator:
            entry["from"][one.channel.initiator.value] += one.count
        if one.channel.responder:
            entry["via"][one.channel.responder.value] += one.count
        if one.start is not None:
            entry["first"] = (one.start if entry["first"] is None
                              else min(entry["first"], one.start))
        if one.end is not None:
            entry["last"] = (one.end if entry["last"] is None
                             else max(entry["last"], one.end))
        for obs in one:
            name = obs.attrs.get("qname")
            code = obs.attrs.get("rcode_name")
            if code:
                entry["rcodes"][str(code)] += 1
            elif name:
                entry["queries"] += 1
            if name:
                entry["names"][str(name)] += 1
                entry["lengths"].append(len(str(name)))
            qtype = obs.attrs.get("qtype")
            if qtype:
                entry["qtypes"][str(qtype)] += 1

            for address in str(obs.attrs.get("resolved_ips", "")).split():
                entry["addresses"][address] += 1
            target = obs.attrs.get("cname_target")
            if target:
                entry["cnames"][str(target)] += 1
            ttl = obs.attrs.get("ttl_min")
            if ttl is not None and str(ttl).isdigit():
                entry["ttls"].append(int(ttl))

    if not zones:
        return []

    ranked = sorted(zones.items(), key=lambda kv: -kv[1]["obs"])
    out = _rule(f"DNS ZONE DETAIL  (top {min(top_n, len(ranked))} of "
                f"{len(ranked):,} by lookups)")

    for zone, entry in ranked[:top_n]:
        out.append("")
        out.append(f"  {zone}")

        if not psl.is_delegated(zone):
            # Stated per zone as well as in the prose, because this is the
            # single fact that explains the whole block beneath it.
            out.append(f"    {'root zone':<12} "
                       f".{zone.rsplit('.', 1)[-1]} is not a delegated "
                       f"top-level domain — these lookups could not resolve")

        askers = ", ".join(f"{who} ({count:,})"
                           for who, count in entry["from"].most_common(3))
        resolvers = ", ".join(f"{who} ({count:,})"
                              for who, count in entry["via"].most_common(3))
        if askers:
            out.append(f"    {'queried by':<12} {askers}")
        if resolvers:
            out.append(f"    {'resolver':<12} {resolvers}")

        out.append(f"    {'lookups':<12} {entry['queries']:,} queries, "
                   f"{len(entry['names']):,} distinct name(s)")
        for name, count in entry["names"].most_common(6):
            out.append(f"    {'':<12}   {count:>7,}  {name}")
        if len(entry["names"]) > 6:
            out.append(f"    {'':<12}   … {len(entry['names']) - 6:,} more")

        if entry["lengths"]:
            ordered = sorted(entry["lengths"])
            out.append(f"    {'name length':<12} median "
                       f"{ordered[len(ordered) // 2]}, max {ordered[-1]} chars")
        if entry["qtypes"]:
            out.append(f"    {'qtypes':<12} " + " · ".join(
                f"{value} {count:,}"
                for value, count in entry["qtypes"].most_common(8)
            ))
        if entry["addresses"]:
            out.append(f"    {'resolved to':<12} "
                       f"{_plural(len(entry['addresses']), 'address', 'addresses')}"
                       f": " + ", ".join(
                           f"{value} ({count:,})" for value, count
                           in entry["addresses"].most_common(5)
                       ) + (f", +{len(entry['addresses']) - 5:,} more"
                            if len(entry["addresses"]) > 5 else ""))
        if entry["cnames"]:
            out.append(f"    {'via cname':<12} " + ", ".join(
                f"{value} ({count:,})" for value, count
                in entry["cnames"].most_common(3)
            ))
        if entry["ttls"]:
            ordered = sorted(entry["ttls"])
            # A very low TTL across many addresses is the shape of fast-flux
            # hosting. Reported, not judged: short TTLs are also just how
            # load balancers and CDNs work.
            out.append(f"    {'ttl':<12} median {ordered[len(ordered) // 2]}s, "
                       f"lowest {ordered[0]}s, highest {ordered[-1]}s")
        if entry["rcodes"]:
            answered = sum(entry["rcodes"].values())
            ok = entry["rcodes"].get("NOERROR", 0)
            share = 100.0 * ok / answered
            out.append(
                f"    {'outcome':<12} {ok:,} of {answered:,} answered "
                f"lookups resolved ({share:.1f}%): " + " · ".join(
                    f"{code} {count:,}" for code, count
                    in entry["rcodes"].most_common(5)
                )
            )
            unanswered = entry["queries"] - answered
            if unanswered > 0:
                # Distinct from a failure: nothing came back at all, so the
                # resolver's opinion is unknown rather than negative.
                out.append(f"    {'unanswered':<12} {unanswered:,} "
                           f"quer{'y' if unanswered == 1 else 'ies'} drew no "
                           f"response in this capture")
        else:
            out.append(f"    {'outcome':<12} no responses observed — "
                       f"this capture does not show whether these resolved")

        if entry["first"]:
            out.append(
                f"    {'active':<12} {_when(entry['first'])} → "
                f"{_when(entry['last'])}  "
                f"({_duration((entry['last'] or 0) - entry['first'])})"
            )
        line = _measured(entry["series"], by_key)
        if line:
            out.append(f"    {'measured':<12} {line}")

    hidden = len(ranked) - top_n
    if hidden > 0:
        quiet = sum(e["obs"] for _z, e in ranked[top_n:])
        out.append("")
        out.append(f"  … {hidden:,} further zone(s) totalling {quiet:,} "
                   f"lookups (raise --top, or see --out json)")
    return out


def _protocol_detail(series, top_n) -> List[str]:
    """Per-protocol detail, driven by which attributes exist.

    Keyed on attributes rather than on a protocol list, so a new domain
    narrates without touching this function.
    """
    out: List[str] = []
    counters: Dict[str, Counter] = defaultdict(Counter)
    numeric: Dict[str, List[float]] = defaultdict(list)

    for one in series:
        for obs in one:
            for attr, bucket in (
                ("qname", "dns.name"), ("qtype", "dns.qtype"),
                ("zone", "dns.zone"), ("rcode_name", "dns.rcode"),
                ("sni", "tls.sni"), ("tls_fingerprint", "tls.fingerprint"),
                ("tls_version", "tls.version"), ("cert_visible", "tls.cert"),
                ("cert_issuer", "tls.issuer"), ("cert_subject", "tls.subject"),
                ("host", "http.host"), ("path", "http.path"),
                ("method", "http.method"), ("status", "http.status"),
                ("fc_name", "ics.function"), ("unit", "ics.unit"),
                ("link_dst", "dnp3.address"),
                ("msg_name", "mavlink.message"), ("sysid", "mavlink.system"),
                ("ssh_client", "ssh.client"), ("ssh_server", "ssh.server"),
                ("ntp_mode", "ntp.mode"), ("ntp_stratum", "ntp.stratum"),
                ("dhcp_type", "dhcp.message"),
                ("dhcp_hostname", "dhcp.hostname"),
                ("dns_service", "dns.service"),
                ("quic_version", "quic.version"),
                ("quic_packet", "quic.packet"),
            ):
                value = obs.attrs.get(attr)
                if value:
                    counters[bucket][str(value)] += 1
            if "qname" in obs.attrs:
                numeric["dns.name_length"].append(len(str(obs.attrs["qname"])))
            if "elapsed_s" in obs.attrs:
                numeric["latency_ms"].append(
                    float(obs.attrs["elapsed_s"]) * 1000.0
                )
        zone = one.channel.dims.get("zone")
        if zone:
            counters["dns.zone"][zone] += one.count

    groups = (
        ("DNS", ["dns.zone", "dns.rcode", "dns.qtype", "dns.name"]),
        ("TLS", ["tls.version", "tls.cert", "tls.sni", "tls.issuer",
                 "tls.subject", "tls.fingerprint"]),
        ("HTTP", ["http.host", "http.method", "http.status", "http.path"]),
        ("INDUSTRIAL", ["ics.function", "ics.unit", "dnp3.address"]),
        ("MAVLINK", ["mavlink.message", "mavlink.system"]),
        # The cleartext service announcements: what software spoke SSH, who
        # asked whom for time, what devices called themselves on DHCP, and
        # which LAN naming systems (mDNS/LLMNR) were gossiping.
        ("SERVICES", ["ssh.client", "ssh.server", "ntp.mode", "ntp.stratum",
                      "dhcp.message", "dhcp.hostname", "dns.service"]),
        ("QUIC", ["quic.version", "quic.packet"]),
    )
    for title, buckets in groups:
        present = [b for b in buckets if counters.get(b)]
        if not present:
            continue
        out += _rule(title)
        for bucket in present:
            counter = counters[bucket]
            total = sum(counter.values())
            label = bucket.split(".", 1)[1]
            out.append(f"  {label:<14} {total:,} observed, "
                       f"{len(counter):,} distinct")
            for value, count in counter.most_common(min(top_n, 8)):
                shown = value if len(value) <= 54 else value[:51] + "…"
                out.append(f"                 {count:>7,}  {shown}")
            if len(counter) > 8:
                out.append(f"                 … {len(counter) - 8:,} more")
        if title == "DNS" and numeric.get("dns.name_length"):
            lengths = sorted(numeric["dns.name_length"])
            out.append(
                f"  name length    median {lengths[len(lengths) // 2]}, "
                f"max {lengths[-1]} characters"
            )
        # Stated as one headline number as well as a breakdown, because the
        # breakdown buries it: on the capture that prompted this, the rcode
        # table read "11,859 NXDOMAIN / 1,338 NOERROR" and left the reader to
        # divide. The share is the fact worth reading.
        if title == "DNS" and counters.get("dns.rcode"):
            codes = counters["dns.rcode"]
            answered = sum(codes.values())
            ok = codes.get("NOERROR", 0)
            out.append(
                f"  resolution     {ok:,} of {answered:,} answered lookups "
                f"resolved ({100.0 * ok / answered:.1f}%); "
                f"{answered - ok:,} failed"
            )
        if numeric.get("latency_ms") and title in ("HTTP", "INDUSTRIAL"):
            values = sorted(numeric["latency_ms"])
            out.append(
                f"  latency        median {values[len(values) // 2]:.1f} ms, "
                f"p95 {values[int(len(values) * 0.95)]:.1f} ms, "
                f"max {values[-1]:.1f} ms"
            )
    return out


def _behaviour(series, by_key, names, top_n) -> List[str]:
    """What the primitives measured, ranked — the heart of the report.

    These are the numbers the findings-only output discarded. A cadence that
    scored 0.77 against a 0.65 gate but failed the rarity conjunction is
    exactly what an operator wants to see, and it used to be invisible.
    """
    out: List[str] = []

    rankings = (
        ("most regular cadence", "periodicity",
         ("period_s", "{:.1f}s period"), ("interval_mad_s", "MAD {:.1f}s"),
         ("observations", "{:.0f} exchanges")),
        ("most one-sided transfer", "asymmetry",
         ("asymmetry", "{:+.2f}"), ("egress_bytes", "{:.0f}B out"),
         ("ingress_bytes", "{:.0f}B in")),
        ("burstiest", "burstiness",
         ("burstiness", "{:+.2f}"),
         ("coefficient_of_variation", "CoV {:.2f}"), None),
        ("highest name/parameter cardinality", "fanout.qname",
         ("unique_values", "{:.0f} unique"),
         ("unique_fraction", "{:.0%} unique"), None),
        ("rarest channel", "rarity",
         ("prevalence", "{:.1%} of hosts"), ("novel", "novel={:.0f}"),
         ("historical_observations", "{:.0f} prior")),
    )

    for title, primitive, *specs in rankings:
        scored: List[Tuple[float, Series, Any]] = []
        for one in series:
            evidence = by_key.get(one.channel.key)
            if evidence is None:
                continue
            result = evidence.by_name(primitive)
            if result is None:
                continue
            scored.append((result.score, one, result))
        if not scored:
            continue
        scored.sort(key=lambda item: item[0], reverse=True)

        out += _rule(f"{title.upper()}  ({len(scored):,} channel(s) measurable)")
        for score, one, result in scored[:min(top_n, 5)]:
            bits = []
            for spec in specs:
                if not spec:
                    continue
                key, template = spec
                value = result.features.get(key)
                if value is not None:
                    bits.append(template.format(value))
            # Outside the spec loop. Indented into it, this printed one row
            # per feature — the same channel three times with progressively
            # more numbers, which reads as three separate channels that
            # happen to share a score.
            #
            # Two spaces before the numbers, not one: a long identity
            # overflows the column and a single space let the name run
            # into them.
            out.append(
                f"  {score:.2f}  {_host(one, names):<52}  {'  '.join(bits)}"
            )
        if len(scored) > 5:
            out.append(f"  … {len(scored) - 5:,} more measured")
    return out


def _content(evidences, redactor, top_n) -> List[str]:
    """Per-message facts the inspectors read, with secrets masked."""
    grouped: Dict[str, List[Tuple[Any, Any]]] = defaultdict(list)
    for evidence in evidences:
        for inspection in evidence.inspections:
            grouped[inspection.name].append((evidence, inspection))
    if not grouped:
        return []

    out = _rule("CONTENT OBSERVED")
    for name in sorted(grouped):
        entries = sorted(grouped[name], key=lambda p: p[1].score, reverse=True)
        occurrences = sum(i.occurrences for _e, i in entries)
        out.append(f"  {name}   {len(entries)} channel(s), "
                   f"{occurrences} occurrence(s)")
        for evidence, inspection in entries[:3]:
            host = (
                evidence.channel.dims.get("host")
                or (evidence.channel.responder.value
                    if evidence.channel.responder else evidence.channel.domain)
            )
            out.append(f"     {inspection.score:.2f}  {host}")
            for key, value in redactor(
                inspection.facts, inspection.secret_facts
            ).items():
                text = str(value)
                if len(text) > 72:
                    text = text[:69] + "…"
                out.append(f"            {key:<24} {text}")
        if len(entries) > 3:
            out.append(f"     … {len(entries) - 3} further channel(s)")
    return out


#: Human wording for each TCP outcome, and whether it counts as a failure.
#: `reset` is deliberately NOT a failure: aborting a working connection is
#: ordinary at the end of many sessions and says nothing about reachability.
_OUTCOMES = (
    ("closed", "completed and closed cleanly", False),
    ("open", "still open at end of capture", False),
    ("reset", "established, then reset", False),
    ("refused", "refused — reset without ever being answered", True),
    ("unanswered", "never answered — no reply to the opening SYN", True),
    ("mid_stream", "already in progress when the capture started", False),
)


def _connections(stats, names, top_n) -> List[str]:
    """TCP connection outcomes.

    This section exists because the report was making a claim it had not
    measured. It said "name resolution, not connectivity, is the dominant
    failure in this capture" — true, as it turned out, but asserted from DNS
    evidence alone with nothing at all known about whether connections
    succeeded. A refused connection carries no application data, so every
    earlier analysis path was blind to it by construction.
    """
    connections = (stats or {}).get("connections") or {}
    counts = connections.get("counts") or {}
    icmp = (stats or {}).get("icmp_errors") or {}

    # Either source is reason enough for this section. Gating on TCP alone
    # hid every ICMP error in a capture that had no TCP flows at all — a
    # UDP-only or ping-only capture, where the errors are the entire story.
    if not counts and not (icmp.get("groups") or []):
        return []

    total = sum(counts.values())
    header = (f"CONNECTIONS  ({total:,} TCP flow(s))" if total
              else "CONNECTIONS")
    out = _rule(header)
    for key, wording, _bad in _OUTCOMES:
        count = counts.get(key)
        if not count:
            continue
        share = 100.0 * count / total
        out.append(f"  {count:>7,}  ({share:>5.1f}%)  {wording}")

    unknown = {k: v for k, v in counts.items()
               if k not in {key for key, _w, _b in _OUTCOMES}}
    for key, count in sorted(unknown.items()):
        out.append(f"  {count:>7,}  {'':>8}  {key}")

    # ICMP errors sit here rather than in a section of their own, because an
    # error is not a fact about the router that sent it — it is the reason a
    # connection above failed. Printed next to the outcome it explains, an
    # operator reads one story; printed separately, they have to join two
    # tables by address to find out why anything happened.
    errors = (stats or {}).get("icmp_errors") or {}
    groups = errors.get("groups") or []
    if groups:
        out.append("")
        out.append(f"  {errors.get('total', 0):,} ICMP error(s) received, "
                   f"explaining attempts to:")
        for group in groups[:top_n]:
            about = str(group.get("about", "?"))
            name = (names or {}).get(about, "")
            port = group.get("dport")
            where = f"{about}:{port}" if port else about
            label = f"{where}  {name}".rstrip()
            reporters = ", ".join(group.get("reporters") or [])
            out.append(f"    {int(group.get('count', 0)):>5,} x  {label}")
            out.append(f"    {'':>5}     {group.get('reason', '')}"
                       + (f", reported by {reporters}" if reporters else ""))
        if len(groups) > top_n:
            out.append(f"    … {len(groups) - top_n:,} further destination(s)")

    failed = connections.get("failed") or {}
    for key, wording, _bad in _OUTCOMES:
        peers = failed.get(key)
        if not peers:
            continue
        ranked = sorted(peers.items(), key=lambda kv: -kv[1])
        out.append("")
        out.append(f"  {wording}, by destination:")
        for address, count in ranked[:top_n]:
            name = (names or {}).get(address, "")
            label = f"{address}  {name}".rstrip()
            out.append(f"    {count:>5,} attempt(s)  {label}")
        if len(ranked) > top_n:
            out.append(f"    … {len(ranked) - top_n:,} further destination(s)")
    return out


#: Exchanges printed per traced channel. Enough to see the pattern repeat;
#: a conversation whose shape is not apparent in 30 exchanges will not
#: become apparent in 300 rows of terminal output.
_TRACE_ROWS = 30


def _shape(series: Series) -> Tuple[str, List[str]]:
    """What kind of activity this channel's shape is consistent with.

    THE HARDEST THING THE TOOL CLAIMS, and the reason this is phrased as
    "consistent with" rather than "is". On an encrypted channel the content
    is gone, but the SHAPE is not: who speaks first, how the sizes are
    distributed between directions, whether the two sides alternate, and how
    regular the gaps are. Those four together separate a web fetch from a
    bulk download from an interactive session from a poller — and they stay
    readable through encryption because framing is not encrypted.

    WHAT THIS IS NOT. It does not identify an application, and the phrasing
    never says it does. Several activities share any given shape, and an
    implementation that wants to look like something else can pad and pace
    itself to do so. So the verdict is a shape, the measurements behind it
    are printed next to it, and the alternatives are named rather than
    suppressed.

    Every branch is a measured ratio. Nothing here is a model's opinion.
    """
    out_sizes = [o.size for o in series if o.direction is Direction.EGRESS]
    in_sizes = [o.size for o in series if o.direction is Direction.INGRESS]
    if not out_sizes and not in_sizes:
        return "", []

    facts: List[str] = []
    total_out = sum(out_sizes)
    total_in = sum(in_sizes)
    total = total_out + total_in or 1

    # How often direction changes. A strict request/response exchange
    # alternates on nearly every step; a download barely alternates at all.
    directions = [o.direction for o in series]
    flips = sum(1 for a, b in zip(directions, directions[1:]) if a is not b)
    alternation = flips / max(1, len(directions) - 1)

    intervals = series.intervals()
    regular = ""
    if len(intervals) >= 5:
        ordered = sorted(intervals)
        middle = ordered[len(ordered) // 2]
        if middle > 0:
            spread = sum(abs(i - middle) for i in intervals) / len(intervals)
            ratio = spread / middle
            regular = ("evenly paced" if ratio < 0.25
                       else "irregularly paced" if ratio > 1.0
                       else "loosely paced")
            facts.append(f"interval median {middle:.2f}s, {regular}")

    facts.append(f"alternation {alternation:.0%}")
    facts.append(f"volume {100.0 * total_in / total:.0f}% inbound")
    if out_sizes:
        facts.append(f"out median {sorted(out_sizes)[len(out_sizes) // 2]}B")
    if in_sizes:
        facts.append(f"in median {sorted(in_sizes)[len(in_sizes) // 2]}B")

    inbound_share = total_in / total
    big_in = max(in_sizes) if in_sizes else 0
    small_both = (
        (max(out_sizes) if out_sizes else 0) < 1500 and big_in < 1500
    )

    # ALTERNATION FIRST, then volume share. Turn-taking is what separates
    # a fetch from a stream, and it does so regardless of how lopsided the
    # bytes are: an ordinary page load is 90-96% inbound by volume AND
    # strictly alternating, so testing volume first classified every web
    # fetch as a bulk transfer. Volume share then picks between bulk and
    # mixed for the channels that are NOT taking turns.
    #
    # The converse error is just as easy: a download whose first four
    # exchanges are a TLS handshake measures ~45% alternation, which is why
    # the turn-taking threshold sits at 0.5 rather than lower.
    if alternation >= 0.5 and inbound_share > 0.6 and not small_both:
        verdict = ("request/response fetch — small requests, larger "
                   "replies, taking turns. The shape of ordinary web or "
                   "API traffic")
    elif inbound_share > 0.9:
        verdict = ("bulk transfer inbound — one side asked, the other "
                   "streamed. Also the shape of a download, a video "
                   "segment, or a large API response")
    elif small_both and regular == "evenly paced":
        verdict = ("regular small exchanges — polling, a keepalive, or a "
                   "heartbeat. Also the shape of a beacon, which is why "
                   "cadence alone is never treated as a finding")
    elif small_both and alternation > 0.5:
        verdict = ("small two-way exchanges at uneven intervals — "
                   "interactive or message-driven. The shape of a shell, a "
                   "chat protocol, or an event stream")
    elif 0.35 < inbound_share < 0.65 and alternation > 0.8 and not small_both:
        # Found by running against a real capture the classifier had never
        # seen: 84 MB each way, 99% alternation, every size an exact
        # multiple of 1414 bytes. Symmetric bulk in fixed MTU-sized units
        # is encapsulation — the previous rules had no branch for it and
        # reported "mixed", which is the least useful thing it could say
        # about the single most structured channel in the file.
        verdict = ("symmetric bulk both ways, closely interleaved — the "
                   "shape of a tunnel, a relay or a proxy carrying someone "
                   "else's traffic. Also how a VPN, a port forward or a "
                   "database replica looks")
        if _mtu_quantised(out_sizes + in_sizes):
            verdict += (". Sizes are near-exact multiples of a fixed unit, "
                        "which is what encapsulation at a fixed MTU produces")
    elif total_out > total_in * 2:
        verdict = ("outbound-heavy — this side sent more than it received. "
                   "The shape of an upload, a sync, or data leaving")
    else:
        verdict = "mixed — no single activity shape dominates"
    return verdict, facts



def _record_line(series: Series) -> str:
    """The channel's TLS record shape, as one line.

    Taken as the MAXIMUM of the running totals carried on the channel's
    observations rather than their sum: each burst is stamped with the
    flow's cumulative count at that moment, so summing would multiply the
    real figure by the number of bursts.
    """
    best: Dict[str, int] = {}
    for obs in series:
        for key, value in obs.attrs.items():
            if not key.startswith("tls_rec_"):
                continue
            try:
                best[key] = max(best.get(key, 0), int(value))
            except (TypeError, ValueError):
                continue
    if not best:
        return ""

    parts = []
    for label, heading in (("out", "sent"), ("in", "recv")):
        count = best.get(f"tls_rec_{label}", 0)
        if not count:
            continue
        full = best.get(f"tls_rec_{label}_full", 0)
        small = best.get(f"tls_rec_{label}_small", 0)
        parts.append(
            f"{heading} {count:,} records "
            f"(mean {best.get(f'tls_rec_{label}_mean', 0):,}B, "
            f"max {best.get(f'tls_rec_{label}_max', 0):,}B, "
            f"{100.0 * full / count:.0f}% full, "
            f"{100.0 * small / count:.0f}% tiny)"
        )
    return "TLS records: " + " · ".join(parts) if parts else ""



def _mtu_quantised(sizes: Sequence[int], tolerance: float = 0.9) -> bool:
    """Are these sizes mostly multiples of one small unit?

    Encapsulation at a fixed MTU produces exactly this: a tunnel with a
    1414-byte payload budget emits 1414, 2828, 4242, 5656 and nothing in
    between. Ordinary application traffic does not quantise that cleanly, so
    the property is a usable signal that bytes are being carried rather than
    generated.

    The unit is taken as the smallest observed size rather than guessed from
    a table of MTUs, because the budget depends on the encapsulation and
    there is no reason to assume a particular one.
    """
    usable = [s for s in sizes if s > 64]
    if len(usable) < 8:
        return False
    unit = min(usable)
    if unit < 256:
        return False
    fitting = sum(1 for s in usable if abs(s % unit) <= 2 or
                  abs(unit - (s % unit)) <= 2)
    return fitting / len(usable) >= tolerance


def _trace(series, names, top_n: int, rows: int = _TRACE_ROWS) -> List[str]:
    """Exchange-by-exchange detail for the busiest channels.

    WHY PER-EXCHANGE. Every other section aggregates, and aggregation is
    what hides the thing someone most wants when asking "what is this
    conversation DOING". A channel that moved 5 MB in 1,300 exchanges could
    be one large download or thirteen hundred small fetches, and the totals
    are identical. The sequence is not.

    Readable on encrypted channels, which is the point: size and direction
    and timing survive encryption, so the trace of a TLS conversation is
    just as informative about its shape as the trace of a cleartext one.
    """
    ranked = sorted(
        (one for one in series if one.count >= 2),
        key=lambda one: -(one.bytes_egress + one.bytes_ingress),
    )
    if not ranked or top_n <= 0:
        return []

    out = _rule(f"EXCHANGE TRACE  (top {min(top_n, len(ranked))} of "
                f"{len(ranked):,} channels by volume)")

    for one in ranked[:top_n]:
        out.append("")
        out.append(f"  {_host(one, names)}")
        verdict, facts = _shape(one)
        if verdict:
            out += _wrap(f"shape: {verdict}", width=74, indent="    ")
        if facts:
            out.append(f"    ({' · '.join(facts)})")

        encrypted = any(o.attrs.get("encrypted") for o in one)
        out.append(f"    {one.count:,} exchanges, "
                   f"{_bytes(one.bytes_egress)} out / "
                   f"{_bytes(one.bytes_ingress)} in"
                   + ("  — encrypted, so sizes and timing are all that is "
                      "readable" if encrypted else ""))
        records = _record_line(one)
        if records:
            out.append(f"    {records}")

        first = one.start or 0.0
        previous = first
        out.append("")
        for index, obs in enumerate(one):
            if index >= rows:
                break
            gap = obs.ts - previous
            previous = obs.ts
            arrow = "→" if obs.direction is Direction.EGRESS else "←"
            # The gap column is the inter-arrival time, which is what makes
            # a burst visible as a burst rather than as a list of rows.
            marker = _size_bar(obs.size)
            detail = _trace_detail(obs)
            out.append(
                f"    +{obs.ts - first:8.3f}s  {gap:7.3f}s  {arrow} "
                f"{obs.size:>7,}B  {marker:<10} {detail}"
            )
        if one.count > rows:
            out.append(f"    … {one.count - rows:,} further exchange(s)")
    return out


#: Size buckets for the trace's bar column, in bytes. A visual column is
#: what makes a shape legible at a glance; the number beside it is the fact.
_SIZE_STEPS = (64, 256, 1024, 4096, 16384)


def _size_bar(size: int) -> str:
    filled = sum(1 for step in _SIZE_STEPS if size >= step)
    return "▇" * filled if filled else "▁"


def _trace_detail(obs) -> str:
    """The most identifying attribute on one exchange, if any.

    Chosen by protocol rather than dumped wholesale: a trace row is read in
    sequence, so one short label per row keeps the shape visible. On an
    encrypted channel this is usually empty, which is itself the honest
    answer.
    """
    attrs = obs.attrs
    for key in ("qname", "rcode_name", "method", "status", "fc_name",
                "msg_name", "icmp_name"):
        value = attrs.get(key)
        if value:
            text = str(value)
            return text if len(text) <= 42 else text[:39] + "…"
    # Record counts are deliberately NOT shown per row. They are flow-level
    # running totals, and printing one beside a single exchange reads as
    # "this burst carried 2 records" when the burst carried 138 kB and the
    # 2 is a cumulative count. The channel's record shape is reported once
    # in its header instead, where the number means what it says.
    return ""


#: Timeline buckets. Twelve rows covers a capture of any length at a glance
#: without becoming a chart nobody reads in a terminal.
_BINS = 12


#: Protocol domain -> the plain word for it in the one-line verdict.
_DOMAIN_WORD = {
    "net": "TCP/TLS", "dns": "DNS", "http": "HTTP",
    "modbus": "Modbus", "dnp3": "DNP3", "mavlink": "MAVLink", "icmp": "ICMP",
}


def _verdict(series, stats, names) -> List[str]:
    """One plain-English sentence classifying the whole capture.

    Synthesised from the same measured values the sections below report —
    originators, destinations, protocol mix, encryption, span — so the gist
    at the top cannot say anything the detail contradicts. A reader who stops
    after this line still knows what they are looking at.
    """
    stats = stats or {}
    if not series and not (stats.get("wireless")):
        return []

    inits = {s.channel.initiator.value for s in series if s.channel.initiator}
    resps = {s.channel.responder.value for s in series if s.channel.responder}
    starts = [s.start for s in series if s.start is not None]
    ends = [s.end for s in series if s.end is not None]
    span = (max(ends) - min(starts)) if starts and ends else 0.0

    domains: Counter = Counter()
    total = enc = 0
    tls13 = False
    for one in series:
        domains[one.channel.domain] += one.count
        for obs in one:
            total += 1
            if obs.attrs.get("encrypted"):
                enc += 1
            if str(obs.attrs.get("tls_version", "")).startswith("TLS 1.3"):
                tls13 = True

    out = _rule("AT A GLANCE")

    # Wi-Fi monitor capture: the management-frame view, if that is what
    # dominates (little or no IP, but access points / probes seen).
    wifi = stats.get("wireless") or {}
    if wifi and total == 0:
        aps = len(wifi.get("aps") or {})
        probes = len(wifi.get("probes") or {})
        deauth = (wifi.get("deauths") or {}).get("total", 0)
        bits = []
        if aps:
            bits.append(_plural(aps, "access point"))
        if probes:
            bits.append(f"{_plural(probes, 'client')} probing")
        if deauth:
            bits.append(f"{deauth:,} deauth/disassoc frame(s)")
        sentence = ("A Wi-Fi monitor-mode capture" + _span_clause(span)
                    + ": " + ", ".join(bits) + ".")
        out += _wrap(sentence)
        return out

    # Who originated it.
    if len(inits) == 1:
        actor = "a host-side capture: one host"
    elif inits:
        actor = f"a capture of {_plural(len(inits), 'originating host')}"
    else:
        actor = "a capture"

    # Where to, named where the tool could name it.
    dest_count = len(resps)
    if dest_count == 1 and resps:
        only = next(iter(resps))
        dest = f" reaching one destination ({names.get(only, only)})"
    elif dest_count:
        dest = f" reaching {_plural(dest_count, 'destination')}"
    else:
        dest = ""

    # Protocol mix + encryption, the two facts that set expectations for the
    # rest of the report.
    proto = ""
    if domains:
        top = domains.most_common(1)[0][0]
        proto = ", mostly " + _DOMAIN_WORD.get(top, top)
    crypt = ""
    if total:
        frac = enc / total
        if frac >= 0.995:
            crypt = ("; all of it encrypted (TLS 1.3)" if tls13
                     else "; all of it encrypted")
        elif frac > 0:
            crypt = f"; {frac:.0%} encrypted"
        else:
            crypt = "; cleartext"

    out += _wrap(f"This is {actor}{dest}{_span_clause(span)}{proto}{crypt}.")
    return out


def _span_clause(span: float) -> str:
    return f" over {_duration(span)}" if span else ""


def _capture_integrity(stats) -> List[str]:
    """Artefacts of the capture apparatus, and what each one corrupts.

    Printed only when an artefact exists — a clean capture needs no section
    saying so, and the counters behind this are always computed, so silence
    here means "checked, nothing found" rather than "never looked".
    """
    integrity = (stats or {}).get("integrity") or {}
    if not integrity:
        return []

    out = _rule("CAPTURE ARTEFACTS")
    out += _wrap(
        "Facts about the capture file itself, not about the traffic. Each "
        "one limits what some measurement below can be trusted to mean.",
    )
    frames = integrity.get("frames", 0)

    # First, because it qualifies the entire report: if the file is still
    # being written, everything below is a snapshot that will change.
    if integrity.get("growing_bytes"):
        out.append("")
        out.append(f"  still writing  the file grew "
                   f"{_bytes(integrity['growing_bytes'])} while it was being "
                   "read")
        out += _wrap(
            "a capture is being appended to this file right now, so this "
            "analysis is a PARTIAL snapshot — counts and findings will "
            "change as more is written, and two runs will disagree. Re-read "
            "it once the capture has stopped.",
            indent="                 ",
        )
    elif integrity.get("last_written_s") is not None:
        out.append("")
        out.append(f"  recently written  last modified "
                   f"{integrity['last_written_s']:g}s before it was read")
        out += _wrap(
            "the file may still be in progress; if so this is a partial "
            "view. If the capture has stopped, this is nothing.",
            indent="                 ",
        )

    if integrity.get("truncated"):
        count = integrity["truncated"]
        missing = integrity.get("truncated_missing", 0)
        out.append("")
        out.append(f"  truncated    {count:,} of {frames:,} frames hold fewer "
                   "bytes than their IP header claims")
        out += _wrap(
            f"about {_bytes(missing)} of payload was never captured — a "
            "snaplen cut frames short. Payload-dependent parsing (TLS "
            "handshakes, HTTP, DNS answers) saw only the front of those "
            "messages; timing and volume figures use the claimed lengths "
            "and are unaffected.",
            indent="               ",
        )
    if integrity.get("duplicates"):
        count = integrity["duplicates"]
        out.append("")
        out.append(f"  duplicated   {count:,} of {frames:,} frames are "
                   "byte-identical to a frame just before them")
        out += _wrap(
            "the signature of a SPAN port or bonded interface delivering "
            "the same packet twice — a TCP retransmit differs in its IP "
            "header, so byte-identical copies are the capture apparatus, "
            "not the network. Volume and exchange counts are inflated by "
            "roughly this many frames.",
            indent="               ",
        )
    if integrity.get("backwards"):
        out.append("")
        out.append(f"  clock        {integrity['backwards']:,} frames carry "
                   "a timestamp earlier than the frame before them "
                   f"(largest step back "
                   f"{_duration(integrity.get('max_regression_s', 0.0))})")
        out += _wrap(
            "intervals measured across these are wrong, and cadence, "
            "jitter and latency are all interval measurements. Common "
            "causes: merged captures, a clock adjusted mid-capture, or "
            "multi-queue reordering.",
            indent="               ",
        )
    if integrity.get("gaps"):
        at = integrity.get("largest_gap_at")
        out.append("")
        out.append(f"  gaps         {integrity['gaps']:,} silent span(s) "
                   f"longer than a minute; largest "
                   f"{_duration(integrity.get('largest_gap_s', 0.0))}"
                   + (f" beginning {_when(at)}" if at else ""))
        out += _wrap(
            "the capture stopped and resumed — a sleeping machine, a "
            "rotated file, a disconnected interface. A cadence that spans "
            "a gap is an artefact of the gap, not a behaviour.",
            indent="               ",
        )
    return out


def _encrypted_dns(series) -> List[str]:
    """Hosts resolving names over DoH / DoT — the DNS this capture cannot see.

    Printed only when a known encrypted-DNS resolver was contacted. The point
    is honesty: without this, a host doing all its lookups over DoH would make
    the report read 'no DNS seen', when in truth the resolution happened and
    is simply unreadable here.
    """
    from core.doh import classify_encrypted_dns
    # initiator -> {(provider, protocol): (basis, exchanges)}
    found: Dict[str, Dict[Tuple[str, str], Tuple[str, int]]] = {}
    for one in series:
        channel = one.channel
        if channel.domain != "net" or not channel.responder:
            continue
        hit = classify_encrypted_dns(
            channel.dims.get("sni", "") or "",
            channel.responder.value,
            channel.dims.get("dport"))
        if hit is None:
            continue
        provider, proto, basis = hit
        who = channel.initiator.value if channel.initiator else "?"
        bucket = found.setdefault(who, {})
        prev = bucket.get((provider, proto))
        bucket[(provider, proto)] = (basis, (prev[1] if prev else 0) + one.count)

    if not found:
        return []

    out = _rule("ENCRYPTED DNS (DoH / DoT)")
    out += _wrap(
        "Name resolution this capture cannot read: these hosts reached a "
        "known encrypted-DNS resolver, so their lookups happened inside "
        "HTTPS (DoH) or TLS (DoT) rather than in the clear. The names "
        "resolved are not visible here — and a host moving its DNS to DoH "
        "is also how modern malware hides its lookups from monitoring.",
    )
    for who, providers in found.items():
        out.append("")
        out.append(f"  {who}")
        for (provider, proto), (basis, exch) in sorted(
                providers.items(), key=lambda kv: -kv[1][1]):
            out.append(f"     {proto} to {provider}  "
                       f"({basis}, {exch:,} exchange(s))")
    return out


def _wireless(stats) -> List[str]:
    """Wi-Fi management-frame intelligence, from a monitor-mode capture.

    Printed only when management frames were seen. The networks in the air,
    the networks devices are looking for (which fingerprints them), and the
    deauthentication count — the last with the standing caveat that normal
    disconnects deauth too, so a flood is a lead, not a verdict.
    """
    wifi = (stats or {}).get("wireless") or {}
    if not wifi:
        return []

    out = _rule("WIRELESS (802.11 management)")
    out += _wrap(
        "Read from the clear-text management frames of a monitor-mode "
        "capture — no payload was decrypted. On a protected network this is "
        "where the meaning is.",
    )

    aps = wifi.get("aps") or {}
    if aps:
        out.append("")
        out.append(f"  access points  {len(aps)} seen")
        for bssid, ap in sorted(aps.items(),
                                key=lambda kv: -kv[1].get("beacons", 0))[:8]:
            ssid = ap.get("ssid") or "<no SSID tag>"
            out.append(f"     {bssid}  {ssid}  ({ap.get('beacons', 0):,} beacon(s))")

    probes = wifi.get("probes") or {}
    if probes:
        out.append("")
        out.append(f"  probe requests {len(probes)} client(s) looking for "
                   "networks — each named network is one the device has "
                   "joined before")
        for client, ssids in sorted(probes.items(),
                                    key=lambda kv: -sum(kv[1].values()))[:8]:
            wanted = ", ".join(name for name, _c in
                               Counter(ssids).most_common(6))
            out.append(f"     {client}  →  {wanted}")

    deauths = wifi.get("deauths") or {}
    if deauths.get("total"):
        out.append("")
        out.append(f"  deauth / disassoc  {deauths['total']:,} frame(s)")
        for (src, dst), count in deauths.get("pairs", [])[:5]:
            out.append(f"     {count:>6,}  {src} → {dst}")
        out += _wrap(
            "a few of these are normal — a roam, a shutdown. A flood is the "
            "classic Wi-Fi denial-of-service, and the opening move of an "
            "evil-twin or handshake-capture attack. The count is a lead to "
            "confirm against its rate and targets, not a verdict.",
            indent="                 ",
        )
    return out


def _neighbor_conflicts(stats) -> List[str]:
    """Addresses that resolved to more than one MAC — the ARP-spoof signal.

    Printed only when a conflict exists; the pairings themselves silently
    improve device naming and need no section. A conflict is reported with
    its competing claims, never as a verdict: the legitimate causes are real
    and common.
    """
    neighbors = (stats or {}).get("neighbors") or {}
    conflicts = neighbors.get("conflicts") or []
    if not conflicts:
        return []

    out = _rule("ADDRESS / HARDWARE CONFLICTS")
    out += _wrap(
        "An IP that resolved to more than one hardware address during the "
        "capture. This is the shape of ARP cache poisoning — a host answering "
        "for an address that is not its own, to sit in the middle of its "
        "traffic. It is also what a DHCP reassignment, a replaced network "
        "card, or a router-redundancy protocol (VRRP/HSRP) produces, so it is "
        "something to confirm, not a verdict.",
    )
    for conflict in conflicts[:8]:
        out.append("")
        out.append(f"  {conflict['ip']} claimed by "
                   f"{len(conflict['claims'])} hardware addresses:")
        for mac, source, first_ts, _last, count in conflict["claims"]:
            when = f" from {_when(first_ts)}" if first_ts else ""
            out.append(f"     {mac}  ({source}, {count:,} time(s){when})")
    return out


def _timeline(series, top_n) -> List[str]:
    """What happened when.

    Every other section in this report is an aggregate over the whole
    capture, which flattens the one thing a reader of a packet file most
    wants: the order events happened in. A host that was idle for fifteen
    minutes and then opened forty connections in ten seconds produces the
    same totals as one that trickled steadily, and those are not the same
    capture.

    Each bucket reports volume, how many destinations were active, and how
    many of those were seen for the FIRST time in that bucket — the last
    column being the one that marks a change in behaviour rather than a
    change in rate.
    """
    stamped = [one for one in series if one.start is not None]
    if not stamped:
        return []
    first = min(one.start for one in stamped)
    last = max((one.end if one.end is not None else one.start)
               for one in stamped)
    span = last - first
    if span <= 0:
        return []

    width = span / _BINS
    exchanges = [0] * _BINS
    volume = [0.0] * _BINS
    peers: List[set] = [set() for _ in range(_BINS)]

    for one in stamped:
        peer = one.channel.responder.value if one.channel.responder else "?"
        per_obs = (one.bytes_egress + one.bytes_ingress) / max(1, one.count)
        for obs in one:
            index = min(_BINS - 1, int((obs.ts - first) / width))
            exchanges[index] += 1
            volume[index] += per_obs
            peers[index].add(peer)

    out = _rule(f"TIMELINE  ({_duration(width)} per row)")
    peak = max(exchanges) or 1
    seen: set = set()
    for index in range(_BINS):
        offset = _duration(index * width)
        bar = "█" * max(0, round(20 * exchanges[index] / peak))
        fresh = len(peers[index] - seen)
        seen |= peers[index]
        out.append(
            f"  +{offset:>8}  {bar:<20} {exchanges[index]:>6,} exch  "
            f"{_bytes(volume[index]):>9}  {len(peers[index]):>3} peers"
            + (f"  {fresh:>3} new" if fresh else "")
        )
    return out


def _interpretation(series, by_key, stats, top_n) -> List[str]:
    """Plain sentences about what the capture shows.

    THE POINT OF THE WHOLE REPORT. Everything above is a table, and a table
    is not an interpretation — it is the raw material for one. This section
    says what the tables mean, in sentences, with the number that justifies
    each claim inline.

    Every sentence here is assembled from measured values by ordinary code.
    No model writes any of it, which is a deliberate constraint rather than
    a missing feature: a sentence generated from the numbers cannot drift
    from them, and `Narrative.verify_against()` exists for the day a model
    is allowed to add commentary on top. Statements are about shape, not
    cause — "this is the shape of a search-suffix list" rather than "this is
    a misconfiguration" — because the capture evidences the first and not
    the second.
    """
    from core.suffixes import default_list

    said: List[str] = []

    # -- who is in the capture at all
    initiators = Counter()
    responders = set()
    for one in series:
        if one.channel.initiator:
            initiators[one.channel.initiator.value] += one.count
        if one.channel.responder:
            responders.add(one.channel.responder.value)

    if len(initiators) == 1:
        who = next(iter(initiators))
        said.append(
            f"A single host, {who}, originated every exchange in this "
            f"capture, reaching "
            f"{_plural(len(responders), 'distinct address', 'distinct addresses')}"
            f". This is a host-side capture, so nothing here describes "
            f"traffic between other parties on the network."
        )
    elif initiators:
        leader, count = initiators.most_common(1)[0]
        total = sum(initiators.values())
        said.append(
            f"{_plural(len(initiators), 'host')} originated traffic to "
            f"{_plural(len(responders), 'destination')}. {leader} is the "
            f"busiest, accounting for {100.0 * count / total:.0f}% of "
            f"exchanges."
        )

    # -- encryption, because it bounds what any of the rest can say
    clear = encrypted = 0
    for one in series:
        for obs in one:
            if obs.attrs.get("encrypted"):
                encrypted += 1
            else:
                clear += 1
    if encrypted or clear:
        total = encrypted + clear
        said.append(
            f"{100.0 * encrypted / total:.0f}% of exchanges "
            f"({encrypted:,} of {total:,}) were encrypted. For those, this "
            f"report describes timing, volume and direction only — the "
            f"content was never available to it, and no claim here depends "
            f"on having read it."
        )

    # -- what the servers negotiated, and what they presented
    versions: Counter = Counter()
    mismatched: Dict[str, str] = {}
    self_signed: Dict[str, str] = {}
    for one in series:
        peer = one.channel.responder.value if one.channel.responder else "?"
        for obs in one:
            version = obs.attrs.get("tls_version")
            if version:
                versions[str(version)] += 1
            if obs.attrs.get("cert_covers_sni") == "0":
                mismatched[peer] = str(obs.attrs.get("sni", ""))
            if obs.attrs.get("cert_self_signed"):
                self_signed[peer] = str(obs.attrs.get("cert_subject", ""))

    if versions:
        total = sum(versions.values())
        listed = " · ".join(f"{name} {count:,}"
                            for name, count in versions.most_common())
        # Pre-1.2 is the line worth drawing: 1.0 and 1.1 are deprecated and
        # a server still negotiating them is a fact about that server, not
        # about the client that reached it.
        weak = sum(count for name, count in versions.items()
                   if name in ("SSL 3.0", "TLS 1.0", "TLS 1.1"))
        sentence = (
            f"TLS versions negotiated across {total:,} exchanges: {listed}."
        )
        if weak:
            sentence += (
                f" {weak:,} of those used a deprecated version (TLS 1.1 or "
                f"older), which is a property of the server that accepted "
                f"them."
            )
        said.append(sentence)

    if mismatched:
        listed = ", ".join(
            f"{peer} (asked for {name})" if name else peer
            for peer, name in list(mismatched.items())[:5]
        )
        said.append(
            f"{_plural(len(mismatched), 'server')} presented a certificate "
            f"that does not cover the name the client asked for: {listed}. "
            f"A normal client would refuse these, so either something "
            f"accepted a certificate it should not have, or the connection "
            f"failed after the handshake — which this report cannot "
            f"distinguish without reading the encrypted bytes."
        )

    if self_signed:
        listed = ", ".join(
            f"{peer} ({subject})" if subject else peer
            for peer, subject in list(self_signed.items())[:5]
        )
        said.append(
            f"{_plural(len(self_signed), 'server')} presented a self-signed "
            f"certificate: {listed}. Ordinary on internal infrastructure and "
            f"on appliances; also what a hastily configured listener "
            f"presents. The certificate alone does not separate those."
        )

    # -- DNS resolution, and the undelegated-TLD explanation for it
    psl = default_list()
    answered = Counter()
    queried: Counter = Counter()
    undelegated: Counter = Counter()
    for one in series:
        if one.channel.domain != "dns":
            continue
        for obs in one:
            code = obs.attrs.get("rcode_name")
            if code:
                answered[str(code)] += 1
            name = obs.attrs.get("qname")
            if name and not obs.attrs.get("rcode_name"):
                queried[str(name)] += 1
                if not psl.is_delegated(str(name)):
                    undelegated[str(name).rsplit(".", 1)[-1]] += 1

    if answered:
        total = sum(answered.values())
        failed = total - answered.get("NOERROR", 0)
        if failed:
            share = 100.0 * failed / total
            worst = [f"{code} {count:,}" for code, count
                     in answered.most_common() if code != "NOERROR"]
            said.append(
                f"{share:.0f}% of answered DNS lookups failed "
                f"({failed:,} of {total:,}: {', '.join(worst[:4])}). "
                f"Name resolution, not connectivity, is the dominant "
                f"failure in this capture."
            )
        if undelegated:
            bad_tlds = sum(undelegated.values())
            listed = ", ".join(
                f".{tld}" for tld, _n in undelegated.most_common(8)
            )
            verb = "does not" if len(undelegated) == 1 else "do not"
            said.append(
                f"{bad_tlds:,} of {sum(queried.values()):,} queries asked "
                f"for names under "
                f"{_plural(len(undelegated), 'top-level domain')} that "
                f"{verb} exist in the root zone ({listed}). Those lookups "
                f"could not have succeeded regardless of the network. A "
                f"single name repeatedly re-queried under a series of "
                f"short, invalid suffixes is the shape of a resolver "
                f"appending a search-domain list to an unqualified name; it "
                f"is also the shape of a generated-name lookup loop, and "
                f"this capture alone does not separate the two."
            )

    # -- connection outcomes, so the DNS claim above is comparative rather
    #    than asserted against an unmeasured alternative
    counts = ((stats or {}).get("connections") or {}).get("counts") or {}
    if counts:
        total = sum(counts.values())
        refused = counts.get("refused", 0)
        unanswered = counts.get("unanswered", 0)
        broken = refused + unanswered
        if broken:
            said.append(
                f"{broken:,} of {_plural(total, 'TCP connection')} did not "
                f"establish ({refused:,} refused, {unanswered:,} unanswered). "
                f"Connections that did establish: "
                f"{total - broken:,}."
            )
        else:
            said.append(
                f"All {_plural(total, 'TCP connection')} that opened in this "
                f"capture were answered — no refusals and no unanswered SYNs. "
                f"Whatever else is wrong here, reachability is not."
            )

    # -- ICMP errors, which name the reason rather than only the symptom
    icmp_errors = (stats or {}).get("icmp_errors") or {}
    error_groups = icmp_errors.get("groups") or []
    if error_groups:
        reasons: Counter = Counter()
        for group in error_groups:
            reasons[str(group.get("reason", "?"))] += int(group.get("count", 0))
        listed = " · ".join(f"{reason} ({count:,})"
                            for reason, count in reasons.most_common(4))
        said.append(
            f"The network returned {icmp_errors.get('total', 0):,} ICMP "
            f"error(s) about traffic this host sent, covering "
            f"{_plural(len(error_groups), 'destination')}: {listed}. These "
            f"name the reason an attempt failed, which the TCP flags alone "
            f"cannot: a connection that was filtered and one that simply "
            f"went unanswered look identical without them."
        )

    # -- contacted without ever having been looked up
    sni_names, resolved_names = _name_sources(series)
    contacted: Dict[str, int] = {}
    private: set = set()
    for one in series:
        responder = one.channel.responder
        # Only count channels that carry traffic to a peer. A DNS channel's
        # responder is the resolver, which is reached by definition and would
        # otherwise appear as its own unresolved endpoint.
        if not responder or one.channel.domain == "dns":
            continue
        contacted[responder.value] = (
            contacted.get(responder.value, 0) + one.count
        )
        # Read from the entity label the parser already set, rather than
        # re-deriving it here: `out/` consumes the model and does not reach
        # back into the capture layer for address semantics.
        if responder.labels.get("private"):
            private.add(responder.value)

    # A LAN peer or gateway is expected to have no public name, so counting
    # it as "unresolved" would bury the finding under routine local traffic.
    unnamed = {
        address: count for address, count in contacted.items()
        if address not in resolved_names and address not in sni_names
        and address not in private
    }
    if contacted:
        if unnamed:
            busiest = sorted(unnamed.items(), key=lambda kv: -kv[1])[:5]
            listed = ", ".join(f"{address} ({count:,})"
                               for address, count in busiest)
            said.append(
                f"{len(unnamed):,} of "
                f"{_plural(len(contacted), 'contacted address', 'contacted addresses')} "
                f"{'was' if len(unnamed) == 1 else 'were'} reached without "
                f"this capture showing a name for them — "
                f"no DNS answer pointed at them and no TLS handshake named "
                f"them ({listed}). Reaching an address directly is ordinary "
                f"for cached lookups, hard-coded infrastructure and anything "
                f"resolved before the capture started; it is also how an "
                f"implant with a hard-coded address behaves. What separates "
                f"those is whether a lookup happened earlier, which a longer "
                f"capture would show and this one cannot."
            )
        elif len(private) >= len(contacted):
            # Every peer was on this machine or this LAN. Saying "all could
            # be named" here would be false — they were excluded from the
            # question, not answered by it.
            said.append(
                f"All {_plural(len(contacted), 'contacted address')} "
                f"{'was' if len(contacted) == 1 else 'were'} private or "
                f"loopback, so there is no public name to expect for any of "
                f"them."
            )
        else:
            said.append(
                f"Every one of the "
                f"{_plural(len(contacted) - len(private), 'public address')} "
                f"contacted could be named, from a DNS answer or a TLS "
                f"handshake. No traffic went to a public address this "
                f"capture cannot account for."
            )

    # -- the loudest measured behaviour, named
    cadence: List[Tuple[float, Series, Any]] = []
    for one in series:
        evidence = by_key.get(one.channel.key)
        result = evidence.by_name("periodicity") if evidence else None
        if result is not None and result.features.get("period_s"):
            cadence.append((result.score, one, result))
    if cadence:
        cadence.sort(key=lambda item: -item[0])
        score, one, result = cadence[0]
        said.append(
            f"The most regular channel in the capture scored "
            f"{score:.2f} for cadence: {_identity(one.channel)} at a "
            f"{result.features['period_s']:.1f}s period over "
            f"{result.features.get('observations', one.count):.0f} "
            f"exchanges. Regularity alone is not suspicious — polling, "
            f"keepalives and update checks are all regular — which is why "
            f"the beacon rules require it to coincide with an uncommon "
            f"destination."
        )

    # -- the largest transfer, named
    volumes: List[Tuple[float, Series]] = []
    for one in series:
        volumes.append((one.bytes_egress + one.bytes_ingress, one))
    if volumes:
        volumes.sort(key=lambda item: -item[0])
        size, one = volumes[0]
        names = _names(series)
        label = _identity(one.channel, names)
        said.append(
            f"The heaviest single channel moved {_bytes(size)} "
            f"({_bytes(one.bytes_egress)} out, {_bytes(one.bytes_ingress)} "
            f"in) over {one.count:,} exchanges: {label}."
        )

    if not said:
        return []

    out = _rule("WHAT THIS CAPTURE SHOWS")
    for paragraph in said:
        out.append("")
        out += _wrap(paragraph, width=70, indent="  ")
    return out


def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    """"1 distinct addresses" undermines a paragraph a reader is meant to
    trust. Cheap to fix, and the prose section is read as prose."""
    word = singular if count == 1 else (plural or singular + "s")
    return f"{count:,} {word}"


def _wrap(text: str, width: int = 70, indent: str = "  ") -> List[str]:
    """Greedy wrap. `textwrap` would do, but this keeps the indent explicit."""
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


def _not_assessed(series, by_key) -> List[str]:
    """What could NOT be measured, and why.

    The counterpart to everything above, and the part that makes a quiet
    report trustworthy. A channel with three observations cannot show a
    cadence; saying so is the difference between "nothing here" and "nothing
    measurable here", which are entirely different claims.
    """
    silent = 0
    too_short: Counter = Counter()
    for one in series:
        evidence = by_key.get(one.channel.key)
        measured = evidence is not None and (
            [r for r in evidence.results if r.name != "_scoring"]
            or evidence.inspections
        )
        if measured:
            continue
        silent += 1
        bucket = ("1 observation" if one.count == 1
                  else f"{one.count} observations" if one.count < 6
                  else "6+ observations")
        too_short[f"{one.channel.domain}, {bucket}"] += 1

    if not silent:
        return []

    out = _rule("NOT ASSESSED")
    out.append(f"  {silent:,} of {len(series):,} channels produced no "
               "measurement at all")
    for reason, count in too_short.most_common(8):
        out.append(f"     {count:>6,}  {reason}")
    out.append("")
    out.append("  A channel too small to measure is not a quiet channel — it is")
    out.append("  an unexamined one. Cadence needs six observations; cardinality")
    out.append("  needs enough values to count.")
    return out
