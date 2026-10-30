#!/usr/bin/env python3
"""Synthesise pcaps for end-to-end testing.

NOT an evaluation harness. These are hand-built packet bytes exercising the
reader, the burst assembler, the primitives and the ruleset together — they
prove the pipeline runs, not that it detects anything. Real numbers require
real C2: Sliver or Havoc in a lab at 0/20/50/90% jitter, with a week of
genuine traffic as the false-positive denominator.

    python3 tools/make_test_pcap.py clean.pcap --profile clean
    python3 tools/make_test_pcap.py suspect.pcap --profile suspect
"""

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path
from typing import List, Tuple

LINKTYPE_ETHERNET = 1
BASE_TS = 1_700_000_000.0


# --------------------------------------------------------------------------
# packet construction
# --------------------------------------------------------------------------


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total, 0, 0, 64, proto, 0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    )
    return header + payload


def _tcp(sport: int, dport: int, flags: int, payload: bytes) -> bytes:
    header = struct.pack(
        ">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0
    )
    return header + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tls_client_hello(sni: str) -> bytes:
    """A minimal but structurally valid ClientHello carrying an SNI extension."""
    name = sni.encode()
    sni_ext = struct.pack(">HHHBH", 0x0000, len(name) + 5, len(name) + 3, 0, len(name)) + name
    extensions = sni_ext + struct.pack(">HH", 0x002B, 0)  # + supported_versions, empty

    body = (
        struct.pack(">H", 0x0303)
        + b"\x00" * 32                      # random
        + b"\x00"                           # session id length
        + struct.pack(">H", 4)              # cipher suites length
        + struct.pack(">HH", 0x1301, 0x1302)
        + b"\x01\x00"                       # compression methods
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _dns_query(qname: str, qtype: int = 1) -> bytes:
    labels = b"".join(
        bytes([len(part)]) + part.encode() for part in qname.split(".")
    ) + b"\x00"
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + labels + struct.pack(">HH", qtype, 1)


# --------------------------------------------------------------------------
# traffic profiles
# --------------------------------------------------------------------------


Frame = Tuple[float, bytes]


def _tcp_exchange(
    ts: float, src: str, dst: str, sport: int, dport: int,
    out_payload: bytes, in_payload: bytes, with_hello: bool = False,
) -> List[Frame]:
    """A complete small exchange: SYN, optional ClientHello, data, response."""
    frames: List[Frame] = [
        (ts, _eth(_ipv4(src, dst, 6, _tcp(sport, dport, 0x02, b"")))),
        (ts + 0.001, _eth(_ipv4(dst, src, 6, _tcp(dport, sport, 0x12, b"")))),
    ]
    offset = 0.002
    if with_hello:
        hello = _tls_client_hello("cdn.example.net" if dport == 443 else "svc.example.net")
        frames.append((ts + offset, _eth(_ipv4(src, dst, 6, _tcp(sport, dport, 0x18, hello)))))
        offset += 0.003
    frames.append((ts + offset, _eth(_ipv4(src, dst, 6, _tcp(sport, dport, 0x18, out_payload)))))
    frames.append((ts + offset + 0.02, _eth(_ipv4(dst, src, 6, _tcp(dport, sport, 0x18, in_payload)))))
    return frames


def profile_clean(rng: random.Random) -> List[Frame]:
    """Ordinary traffic from several hosts. Seeds a baseline so that common
    destinations become prevalent and the suspect ones do not."""
    frames: List[Frame] = []
    hosts = [f"10.0.0.{n}" for n in range(10, 40)]
    popular = ["93.184.216.34", "151.101.1.69", "140.82.112.4"]

    for host in hosts:
        for dst in popular:
            # Irregular, interactive-looking browsing.
            t = BASE_TS + rng.uniform(0, 600)
            for _ in range(8):
                t += rng.expovariate(1 / 4.0)
                frames += _tcp_exchange(
                    t, host, dst, rng.randint(40000, 60000), 443,
                    bytes(rng.randrange(256) for _ in range(rng.randint(200, 1800))),
                    bytes(rng.randrange(256) for _ in range(rng.randint(500, 4000))),
                    with_hello=True,
                )
        # An exact-interval poller on every host: the dominant false-positive
        # class, made prevalent on purpose so rarity can demote it.
        t = BASE_TS
        for _ in range(30):
            t += 300.0
            frames += _tcp_exchange(
                t, host, "10.0.0.1", 50000, 443, b"\x00" * 120, b"\x00" * 90
            )

    frames.sort(key=lambda f: f[0])
    return frames


def profile_suspect(rng: random.Random) -> List[Frame]:
    """One host exhibiting four behaviours at once."""
    frames: List[Frame] = []
    victim = "10.0.0.5"

    # 1. jittered beacon to an otherwise-unseen destination
    t = BASE_TS
    for _ in range(40):
        t += rng.uniform(48.0, 60.0)          # 60s period, 20% jitter
        frames += _tcp_exchange(
            t, victim, "203.0.113.9", 51000, 443,
            bytes(rng.randrange(256) for _ in range(rng.randint(180, 210))),
            bytes(rng.randrange(256) for _ in range(rng.randint(90, 110))),
            with_hello=True,
        )

    # 2. the same exact-interval poller the clean capture made prevalent
    t = BASE_TS
    for _ in range(30):
        t += 300.0
        frames += _tcp_exchange(
            t, victim, "10.0.0.1", 50000, 443, b"\x00" * 120, b"\x00" * 90
        )

    # 3. ordinary browsing to a popular destination
    t = BASE_TS
    for _ in range(20):
        t += rng.expovariate(1 / 5.0)
        frames += _tcp_exchange(
            t, victim, "93.184.216.34", rng.randint(40000, 60000), 443,
            bytes(rng.randrange(256) for _ in range(rng.randint(200, 2000))),
            bytes(rng.randrange(256) for _ in range(rng.randint(800, 9000))),
            with_hello=True,
        )

    # 4. DNS tunnelling: unique encoded label per query under one zone
    t = BASE_TS
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for index in range(140):
        t += rng.uniform(0.2, 0.6)
        label = "".join(rng.choice(alphabet) for _ in range(28))
        query = _dns_query(f"{label}.tun.example.org")
        frames.append(
            (t, _eth(_ipv4(victim, "10.0.0.53", 17, _udp(53000 + index % 100, 53, query))))
        )

    frames.sort(key=lambda f: f[0])
    return frames


# --------------------------------------------------------------------------


def write_pcap(path: Path, frames: List[Frame]) -> None:
    with path.open("wb") as handle:
        handle.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
        )
        for ts, data in frames:
            seconds = int(ts)
            handle.write(
                struct.pack("<IIII", seconds, int((ts - seconds) * 1_000_000),
                            len(data), len(data))
            )
            handle.write(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--profile", choices=("clean", "suspect"), default="suspect")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    frames = profile_clean(rng) if args.profile == "clean" else profile_suspect(rng)
    write_pcap(Path(args.output), frames)
    print(f"{args.output}: {len(frames)} frames, profile={args.profile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
