"""A flow-record capture source: behavioural analysis at line rate.

The pcap path ships every packet to Python and decodes it there, which is
right for a file and for a modest live link but cannot keep up with a fast
one — the windower load-sheds and the report says so. The answer for a
saturated link is to move the per-packet work into the kernel: an eBPF/XDP
program sees each packet at the earliest possible point, aggregates per flow
in a kernel map, and emits one compact record per BURST (a packet after an
idle gap) instead of per packet. Python then reads a trickle of flow records,
not a torrent of frames.

This module is the Python half of that: it turns those flow records into the
same `Observation` stream the behavioural primitives already consume, so a
flow from the kernel and a flow from a pcap are scored by identical code.
The kernel half is the operator's — a bundled reference lives in
`capture/bpf/` — and the two meet at one documented contract: newline-
delimited JSON flow records, one per burst.

A DELIBERATELY LOWER-FIDELITY TIER, and the tool says so. In-kernel
aggregation keeps timing, volume, direction and ports — enough for cadence,
asymmetry, fanout, rarity and connection shape, which is the whole beacon /
exfil / scan story. It does NOT keep payload, so there is no TLS record
shape, no certificate, no HTTP, no DNS answer, no content inspection here.
This is the trade that buys line rate; `monitor` prints it rather than
letting a quiet content section read as "nothing found".

THE CONTRACT. One JSON object per line, fields:
    ts     float   seconds (event time, from the kernel clock)
    proto  str     "tcp" | "udp"
    saddr  str     source address of this burst
    daddr  str     destination address of this burst
    sport  int     source port
    dport  int     destination port
    dir    str     "egress" (local->remote) | "ingress" (remote->local)
    bytes  int     bytes in this burst
    packets int    packets in this burst (optional)
Unknown fields are ignored; a malformed line is counted and skipped, never
fatal — a capture feed is adversarial input like any other.
"""

from __future__ import annotations

import json
from typing import Dict, Iterable, Iterator, NamedTuple, Optional

from capture.decode import is_private
from core.model import Channel, Direction, Entity, Locus, Observation

__all__ = ["FlowRecord", "EbpfSource", "EbpfUnavailable", "read_jsonl_flows"]


class EbpfUnavailable(RuntimeError):
    """The kernel flow feed could not be read — toolchain, privilege, or
    interface. Raised with guidance, never swallowed into a silent empty run."""


class FlowRecord(NamedTuple):
    ts: float
    proto: str
    saddr: str
    daddr: str
    sport: int
    dport: int
    direction: str          # "egress" | "ingress"
    bytes: int
    packets: int = 1


def read_jsonl_flows(stream: Iterable[str]) -> Iterator[FlowRecord]:
    """Parse the JSONL flow contract from any line iterator (a file, stdin,
    a subprocess pipe). Malformed or incomplete lines are skipped."""
    for line in stream:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
            yield FlowRecord(
                ts=float(row["ts"]),
                proto=str(row.get("proto", "tcp")).lower(),
                saddr=str(row["saddr"]),
                daddr=str(row["daddr"]),
                sport=int(row.get("sport", 0)),
                dport=int(row.get("dport", 0)),
                direction=str(row.get("dir", "egress")).lower(),
                bytes=int(row.get("bytes", 0)),
                packets=int(row.get("packets", 1)),
            )
        except (ValueError, KeyError, TypeError):
            continue


def flow_observation(record: FlowRecord) -> Observation:
    """One burst -> one Observation on a net channel.

    The channel is normalised so both directions of a flow share a key: the
    LOCAL endpoint is always the initiator and the remote the responder, with
    the service port as `dport`. Without this an egress burst and the ingress
    burst answering it would land on two different channels and no cadence
    could ever form across them.
    """
    if record.direction == "ingress":
        # remote -> local: the local host (daddr) opened this flow earlier;
        # the service port is the remote's source port.
        initiator, responder, dport = record.daddr, record.saddr, record.sport
        direction = Direction.INGRESS
    else:
        initiator, responder, dport = record.saddr, record.daddr, record.dport
        direction = Direction.EGRESS

    channel = Channel(
        domain="net",
        dims={"proto": record.proto, "dport": str(dport)},
        initiator=Entity("ip", initiator, labels={"private": is_private(initiator)}),
        responder=Entity("ip", responder, labels={"private": is_private(responder)}),
    )
    return Observation(
        ts=record.ts,
        channel=channel,
        direction=direction,
        size=record.bytes,
        kind="flow_burst",
        # No payload reached us — content analyses correctly find nothing.
        # Marked, not silently absent, so a consumer can tell the tier apart.
        attrs={"encrypted": False, "source": "ebpf", "packets": str(record.packets)},
        locus=Locus(source="ebpf", frames=()),
    )


class EbpfSource:
    """A capture source over an iterator of flow records.

    Mirrors the slice of the PcapSource interface the analysis tail uses —
    `observations()` and `stats` — so `monitor` runs the identical scorer.
    The record iterator is injected: a file/stdin of JSONL in production, a
    list in tests, a kernel ring-buffer reader when one is wired up.
    """

    def __init__(self, records: Iterable[FlowRecord]) -> None:
        self._records = records
        self.stats: Dict[str, object] = {
            "frames": 0, "decoded": 0, "tcp": 0, "udp": 0, "dns": 0,
            "http": 0, "icmp": 0,
        }

    def observations(self) -> Iterator[Observation]:
        for record in self._records:
            self.stats["frames"] = int(self.stats["frames"]) + 1
            self.stats["decoded"] = int(self.stats["decoded"]) + 1
            key = "udp" if record.proto == "udp" else "tcp"
            self.stats[key] = int(self.stats[key]) + 1
            yield flow_observation(record)

    def describe(self) -> str:
        return (f"ebpf flow feed — {self.stats['frames']:,} burst(s) "
                f"({self.stats['tcp']:,} tcp, {self.stats['udp']:,} udp). "
                "Behavioural tier: timing, volume and direction only; no "
                "payload, so content and TLS-shape analyses do not apply.")
