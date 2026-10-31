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

## The production path: the eBPF/XDP program (`flowmon`)

For line rate the producer is a kernel program against this same contract, so
`monitor` does not change. It is bundled here as source — `flowmon.bpf.c`
(the eBPF program), `flowmon.c` (the userspace loader), `flowmon.h` (the
shared record and its JSON formatter), and a `Makefile` — to compile on the
host you will run it on:

```bash
# Debian/Ubuntu: sudo apt install clang llvm libbpf-dev bpftool
# Arch:          sudo pacman -S clang llvm libbpf bpf
cd capture/bpf && make                 # builds ./flowmon

sudo ./flowmon eth0 | python3 ../../semantiq.py monitor --stream \
    --baseline ~/.semantiq/home.db
```

How it works:

1. **Two hooks, one object.** `SEC("xdp") flowmon_xdp` runs on **ingress** —
   the line-rate fast path, before the kernel even builds an `sk_buff`.
   `SEC("tc") flowmon_tc` runs on **egress**, because XDP cannot see egress
   and the outbound callback is the whole point of beacon detection. Both
   share the maps below.
2. **Parse** Ethernet → IPv4 → TCP/UDP far enough for the 5-tuple and the
   length. Non-IPv4 is skipped (IPv6 is a documented follow-on).
3. **Aggregate** in an LRU hash keyed by the 5-tuple + direction, each value
   `{first_ns, last_ns, bytes, packets}`. On each packet: if `now - last_ns`
   exceeds the gap, push the finished burst to a ring buffer and start a new
   one; otherwise accumulate.
4. **Emit** from the loader's ring-buffer loop, which renders each burst with
   `flow_event_to_json` (in `flowmon.h`) — the exact bytes `monitor` reads.

Neither the eBPF program nor the loader is exercised by the repository's test
suite: building them needs a BPF toolchain and running them needs root and a
current kernel, neither of which CI assumes. What **is** tested is the piece
that could silently break the feed — the record/JSON contract itself:
`make selftest` compiles `selftest.c` with an ordinary compiler and prints
sample records, and `tests/test_ebpf.py` runs it and checks they round-trip
through `read_jsonl_flows` into one channel key. So any conforming producer —
`flowmon`, the tshark bridge above, or your own — interoperates unchanged.

`XDP` note: XDP needs driver support for its fastest "native" mode; without
it the kernel runs the program in a slightly slower "generic" mode, still far
below per-packet userspace capture. `flowmon` never drops or alters a packet
(`XDP_PASS`/`TC_ACT_OK`) — it only measures.

## Why not bundle a compiled program?

The same reason the tool vendors no binaries and keeps `core/` stdlib-only: a
kernel object is unportable across kernels and unverifiable without root and a
toolchain the tool does not assume. The contract is the stable thing; the
producer is pluggable.
