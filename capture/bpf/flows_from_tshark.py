"""Reference flow producer: tshark fields -> the JSONL flow contract.

The `monitor` subcommand reads newline-delimited JSON flow records, one per
burst (see capture/bpf/README.md). The PRODUCTION producer of that feed is an
eBPF/XDP program aggregating in the kernel — but you do not need to build one
to try `monitor`, or to understand the contract. This bridge produces the
exact same records from tshark, by doing in userspace the burst aggregation
the kernel program would do in-kernel:

    tshark -i eth0 -l -T fields -e frame.time_epoch -e ip.src -e ip.dst \\
        -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport \\
        -e udp.dstport -e frame.len \\
      | python3 capture/bpf/flows_from_tshark.py --local 192.168.1.10 \\
      | python3 semantiq.py monitor --stream

It is a REFERENCE and a test harness, not the line-rate path: it still runs
tshark per packet, so it does not buy the throughput the kernel program does.
It buys the contract — the same records, so `monitor` behaves identically
whether the feed came from here or from XDP.

DIRECTION. A flow record is egress (local->remote) or ingress. Pass --local
with the capturing host's address(es) to label it exactly; without it, a
burst whose source is private and destination is not is called egress, which
is right for the common host-behind-NAT case and honest about being a guess.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from typing import Dict, Optional, Tuple

#: Close a burst after this idle gap on a flow — the userspace mirror of the
#: kernel program's per-flow timer. Matches the pcap burst-gap default.
_GAP_S = 1.0


def _is_private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


class _Burst:
    __slots__ = ("start_ts", "last_ts", "bytes", "packets", "sport", "dport")

    def __init__(self, ts: float, sport: int, dport: int, length: int) -> None:
        self.start_ts = ts
        self.last_ts = ts
        self.bytes = length
        self.packets = 1
        self.sport = sport
        self.dport = dport


def _direction(saddr: str, daddr: str, local: set) -> str:
    if local:
        if saddr in local:
            return "egress"
        if daddr in local:
            return "ingress"
    return "egress" if (_is_private(saddr) and not _is_private(daddr)) else "ingress"


def _emit(key, burst: _Burst, local: set) -> None:
    saddr, daddr, proto = key
    record = {
        "ts": round(burst.start_ts, 6),
        "proto": proto,
        "saddr": saddr, "daddr": daddr,
        "sport": burst.sport, "dport": burst.dport,
        "dir": _direction(saddr, daddr, local),
        "bytes": burst.bytes, "packets": burst.packets,
    }
    sys.stdout.write(json.dumps(record) + "\n")
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="append", default=[],
                        metavar="IP", help="the capturing host's address; "
                        "repeatable. Used to label flow direction exactly.")
    parser.add_argument("--gap", type=float, default=_GAP_S,
                        help=f"idle seconds that close a burst (default {_GAP_S})")
    args = parser.parse_args()
    local = set(args.local)

    open_bursts: Dict[Tuple[str, str, str], _Burst] = {}

    def flush_idle(now: float) -> None:
        for key in [k for k, b in open_bursts.items()
                    if now - b.last_ts > args.gap]:
            _emit(key, open_bursts.pop(key), local)

    for line in sys.stdin:
        fields = line.rstrip("\n").split("\t")
        if len(fields) < 9:
            continue
        try:
            ts = float(fields[0])
        except ValueError:
            continue
        saddr, daddr, ip_proto = fields[1], fields[2], fields[3]
        if not saddr or not daddr:
            continue
        proto = "tcp" if ip_proto == "6" else "udp" if ip_proto == "17" else ""
        if not proto:
            continue
        sport = int(fields[4] or fields[6] or 0)
        dport = int(fields[5] or fields[7] or 0)
        length = int(fields[8] or 0)

        flush_idle(ts)
        key = (saddr, daddr, proto)
        burst = open_bursts.get(key)
        if burst is None:
            open_bursts[key] = _Burst(ts, sport, dport, length)
        else:
            burst.last_ts = ts
            burst.bytes += length
            burst.packets += 1

    for key, burst in open_bursts.items():
        _emit(key, burst, local)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
