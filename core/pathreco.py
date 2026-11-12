"""Reconstruct the network path from the ICMP errors a traceroute leaves.

A traceroute sends probes with a rising TTL; each router that decrements the
TTL to zero answers with an ICMP "time exceeded in transit" that names itself
(the ICMP source) and quotes the probe that died (so the intended
destination, and the probe's port, are readable). Collect those and the path
falls out: the routers seen on the way to one destination, in order.

ORDERING, HONESTLY. Classic UDP traceroute increments the destination port
per probe, so the quoted port orders the hops exactly. When the ports do not
increase (an ICMP or TCP traceroute, or a tool that does not vary them) the
reconstruction falls back to the order the errors arrived — which is still
hop order for a sequential traceroute, but is an assumption, so the output
says which basis it used.

WHAT IT CANNOT KNOW. A hop that did not answer is a gap this cannot fill, and
it does not pretend to — it reports the routers that *answered*, in order,
not a guaranteed-contiguous path. A single time-exceeded is one router, not a
path; a path needs at least two distinct hops.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

__all__ = ["reconstruct"]

_EXCEEDED = "exceeded in transit"


def reconstruct(errors: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Paths toward each destination, from a list of ICMP-error records.

    Each record is the shape `PcapSource` collects: reported_by (the router),
    about (the quoted destination), dport (the quoted probe port), ts.
    """
    by_dest: Dict[str, List[Dict[str, Any]]] = {}
    for err in errors:
        reason = str(err.get("reason", ""))
        if not reason.endswith(_EXCEEDED):
            continue
        dest = err.get("about")
        router = err.get("reported_by")
        if not dest or dest == "?" or not router:
            continue
        by_dest.setdefault(dest, []).append(err)

    paths: List[Dict[str, Any]] = []
    for dest, hits in by_dest.items():
        dports = [h.get("dport") for h in hits]
        # Ports order the hops only if they actually vary (UDP traceroute).
        by_port = all(p is not None for p in dports) and len(set(dports)) > 1
        key = (lambda h: (h.get("dport", 0),)) if by_port \
            else (lambda h: (h.get("ts", 0.0),))
        ordered = sorted(hits, key=key)

        hops: List[str] = []
        for h in ordered:                       # distinct routers, in order
            router = h["reported_by"]
            if not hops or hops[-1] != router:
                hops.append(router)
        # dedup a router that recurs non-adjacently (probe retries) while
        # keeping first-seen order
        seen = set()
        deduped = [r for r in hops if not (r in seen or seen.add(r))]
        if len(deduped) >= 2:
            paths.append({
                "dest": dest,
                "hops": deduped,
                "ordered_by": "probe port" if by_port else "arrival order",
            })

    # Longest (most-revealing) path first.
    paths.sort(key=lambda p: -len(p["hops"]))
    return paths
