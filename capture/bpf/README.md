# The eBPF / flow-feed backend

`semantiq.py monitor` interprets a feed of **flow records** instead of
packets. It exists for a link too fast for per-packet capture: the per-packet
work moves into the kernel, which aggregates per flow and emits one compact
record per burst, and `monitor` runs the same behavioural scorer the pcap
path does on that trickle.

It is a **lower-fidelity tier, by design**. Flow records keep timing, volume,
direction and ports — enough for cadence, asymmetry, fanout, rarity and
connection shape, which is the whole beacon / exfil / scan story. They carry
**no payload**, so there is no TLS record shape, no certificate, no HTTP, no
DNS answer, no content inspection. `monitor` prints this rather than letting a
quiet content section read as "nothing found". For full fidelity on traffic
you can keep up with, use `read` / `live`.

## The contract

One JSON object per line, one per **burst** (a run of packets on a flow,
closed by an idle gap — not one per packet):

```json
{"ts": 1700000000.0, "proto": "tcp", "saddr": "10.0.0.5", "daddr": "203.0.113.9", "sport": 51514, "dport": 443, "dir": "egress", "bytes": 256, "packets": 1}
```

| field | type | meaning |
|---|---|---|
| `ts` | float | event time, seconds (the kernel clock, not wall-clock) |
| `proto` | str | `tcp` or `udp` |
| `saddr`/`daddr` | str | burst source / destination address |
| `sport`/`dport` | int | source / destination port |
| `dir` | str | `egress` (local→remote) or `ingress` |
| `bytes` | int | bytes in this burst |
| `packets` | int | packets in this burst (optional) |

**One record per burst is the requirement, not one per packet.** Per-packet
records would hand the cadence primitive packet-level intervals instead of
exchange-level ones and the analysis would be meaningless — the same reason
the pcap path assembles bursts before measuring. The aggregation belongs in
the kernel program; that is what buys the throughput.

A malformed or partial line is skipped and counted, never fatal.

## Try it now, without building anything

The bridge produces the exact contract from tshark, doing the burst
aggregation in userspace that the kernel program does in-kernel. It is a
reference and a test harness — it still runs tshark per packet, so it does
*not* buy throughput; it buys the identical records, so `monitor` behaves the
same whether the feed came from here or from XDP.

```bash
# live
tshark -i eth0 -l -T fields -e frame.time_epoch -e ip.src -e ip.dst \
    -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport \
    -e udp.dstport -e frame.len \
  | python3 capture/bpf/flows_from_tshark.py --local 192.168.1.10 \
  | python3 semantiq.py monitor --stream --baseline ~/.semantiq/home.db

# from a file, to see the tier on a capture you already have
tshark -r capture.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst \
    -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport \
    -e udp.dstport -e frame.len \
  | python3 capture/bpf/flows_from_tshark.py \
  | python3 semantiq.py monitor
```

## The production path: an eBPF/XDP kernel program

For line rate, the producer is a kernel program against this same contract —
so `monitor` does not change. The design:

1. **Attach** an XDP program on ingress and a tc/clsact program on egress (XDP
   alone sees only ingress). CO-RE + libbpf keeps one object portable across
   kernels.
2. **Parse** Ethernet → IP → TCP/UDP far enough for the 5-tuple and the IP
   length. Non-IP and fragments are counted and skipped.
3. **Aggregate** in a `BPF_MAP_TYPE_HASH` keyed by the 5-tuple, each value a
   `{start_ts, last_ts, bytes, packets, dport, dir}`. On each packet: if
   `now - last_ts > gap`, push the finished burst to a `BPF_MAP_TYPE_RINGBUF`
   and start a new one; otherwise accumulate. A sweep (a `BPF_MAP_TYPE_TIMER`
   or a userspace tick) flushes bursts idle past the gap.
4. **Emit** from a tiny userspace loop that reads the ringbuf and prints each
   record as one JSON line — the bytes `monitor` consumes.

This half is the operator's: it needs root (`CAP_BPF`/`CAP_NET_ADMIN`), a
current kernel, and a build toolchain, and it is **not exercised by this
repository's test suite** — the tested, load-bearing parts are the contract,
the `capture/ebpf.py` adapter, and `monitor` itself, so any conforming
producer (XDP, the bridge above, or your own) interoperates unchanged.

## Why not bundle a compiled program?

The same reason the tool vendors no binaries and keeps `core/` stdlib-only: a
kernel object is unportable across kernels and unverifiable without root and a
toolchain the tool does not assume. The contract is the stable thing; the
producer is pluggable.
