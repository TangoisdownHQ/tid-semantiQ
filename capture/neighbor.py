"""The LAN's address-to-hardware table, built from ARP and NDP.

ARP replies and IPv6 neighbour advertisements are the network stating, in the
clear, which IP is at which MAC. Collected across a capture they give two
things no other layer does:

  PAIRINGS. An authoritative IP<->MAC map for local hosts — better than the
  source MAC inferred from an IP packet, because ARP/NDP only ever concern
  on-link addresses, so there is no gateway-MAC confusion to guard against.
  These feed device-vendor naming directly.

  CONFLICTS. One IP that resolves to more than one MAC over the capture. That
  is the signature of ARP cache poisoning — an attacker answering ARP for a
  victim's address (often the gateway's) to put themselves in the middle.

HONESTY ABOUT A CONFLICT. One-IP-many-MAC is not proof of an attack. A DHCP
lease handed to a new device, a replaced NIC, and a first-hop redundancy
protocol (VRRP/HSRP/CARP) that floats a virtual IP between routers all
produce it legitimately. So a conflict is reported as something to look at,
with its competing claims and their timing laid out, and never as a verdict —
the same discipline as everywhere else in the tool.
"""

from __future__ import annotations

from typing import Dict, List, NamedTuple, Optional, Tuple

__all__ = ["NeighborTable", "NeighborConflict"]


class NeighborConflict(NamedTuple):
    ip: str
    #: (mac, source, first_ts, last_ts, count) per claimant, most-seen first.
    claims: List[Tuple[str, str, float, float, int]]


class _Claim:
    __slots__ = ("source", "first_ts", "last_ts", "count")

    def __init__(self, source: str, ts: float) -> None:
        self.source = source
        self.first_ts = ts
        self.last_ts = ts
        self.count = 1

    def seen(self, source: str, ts: float) -> None:
        self.count += 1
        self.last_ts = max(self.last_ts, ts)
        self.first_ts = min(self.first_ts, ts)
        # A stronger source upgrades the label (arp/ndp over inferred).
        if _RANK.get(source, 0) > _RANK.get(self.source, 0):
            self.source = source


#: Trust order for the provenance of a pairing. ARP and NDP assert it
#: outright; an inferred source MAC is a weaker guess kept only as a fallback.
_RANK = {"inferred": 0, "ndp": 1, "arp": 2}


class NeighborTable:
    def __init__(self) -> None:
        # ip -> {mac -> _Claim}
        self._table: Dict[str, Dict[str, _Claim]] = {}

    def observe(self, ip: str, mac: str, source: str = "arp",
                ts: float = 0.0) -> None:
        """Record that `ip` was seen at `mac`. Idempotent per (ip, mac)."""
        if not ip or not mac or mac == "00:00:00:00:00:00":
            return
        macs = self._table.setdefault(ip, {})
        claim = macs.get(mac)
        if claim is None:
            macs[mac] = _Claim(source, ts)
        else:
            claim.seen(source, ts)

    def pairings(self) -> Dict[str, str]:
        """ip -> its most-asserted MAC. The most-seen claim wins, so a brief
        spoof does not overwrite the rightful owner in the naming path."""
        out: Dict[str, str] = {}
        for ip, macs in self._table.items():
            best = max(macs.items(), key=lambda kv: (kv[1].count, kv[1].last_ts))
            out[ip] = best[0]
        return out

    def conflicts(self) -> List[NeighborConflict]:
        """Addresses claimed by more than one MAC, most-contested first."""
        out: List[NeighborConflict] = []
        for ip, macs in self._table.items():
            if len(macs) < 2:
                continue
            claims = sorted(
                ((mac, c.source, c.first_ts, c.last_ts, c.count)
                 for mac, c in macs.items()),
                key=lambda r: -r[4],
            )
            out.append(NeighborConflict(ip=ip, claims=claims))
        out.sort(key=lambda c: -sum(claim[4] for claim in c.claims))
        return out

    def report(self) -> dict:
        """Capture-level summary for the stats dict; empty when nothing was
        seen, so a consumer tests truthiness rather than a count of zero."""
        pairings = self.pairings()
        if not pairings:
            return {}
        conflicts = self.conflicts()
        return {
            "pairings": pairings,
            "conflicts": [
                {"ip": c.ip, "claims": c.claims} for c in conflicts
            ],
        }
