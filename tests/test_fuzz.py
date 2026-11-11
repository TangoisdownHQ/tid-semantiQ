"""Decoders are fuzzed: a crafted packet must return None, never raise.

The tool's premise is that a capture is adversarial input — "a crash on a
crafted packet is a denial of service against the analyst" (decode.py). This
feeds every decoder a flood of random bytes, truncations, and bit-flipped
valid frames and asserts none of them throws. A decoder is free to return
None or a value; the only forbidden outcome is an exception.

Deterministic (seeded) so a failure reproduces and CI is stable; the seed
and the exact offending input are printed when something does raise, so the
bug is handed over rather than just flagged.
"""

from __future__ import annotations

import random
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture import decode as D
from capture.integrity import IntegrityTracker
from capture.neighbor import NeighborTable
from capture.osfp import tcp_signature
from capture.pcapfile import (
    LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP,
    LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2, LINKTYPE_NULL, LINKTYPE_RAW,
    read_frames,
)
from capture.tlsinfo import RecordWalker, record_shape
from capture.wifi import WifiMonitor

SEED = 20261108
_LINKTYPES = (LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP,
              LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2, LINKTYPE_NULL, LINKTYPE_RAW)

# A few genuinely-valid frames to MUTATE — mutating a real structure reaches
# the deep length/offset arithmetic that pure noise rarely does.
_SEEDS = []


def _seed_samples():
    if _SEEDS:
        return _SEEDS
    # a TLS ClientHello record
    body = (struct.pack(">H", 0x0303) + b"\x11" * 32 + b"\x00"
            + struct.pack(">H", 2) + b"\xc0\x2f" + b"\x01\x00"
            + struct.pack(">H", 9) + struct.pack(">HH", 0x0000, 5)
            + b"\x00\x03\x00x.y")
    ch = b"\x16" + struct.pack(">HH", 0x0303, len(b"\x01") + 3 + len(body)) \
        + b"\x01" + len(body).to_bytes(3, "big") + body
    # a DNS query
    dns = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x03foo\x03com\x00" \
        + struct.pack(">HH", 1, 1)
    # an IPv4+TCP ethernet frame
    tcp = struct.pack(">HHIIBBHHH", 4444, 443, 0, 0, 5 << 4, 0x02, 64240, 0, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + tcp
    eth = b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip
    _SEEDS.extend([ch, dns, eth, tcp, ip])
    return _SEEDS


def _mutations(rng, sample, n):
    """n mutated copies of `sample`: bit flips and truncations."""
    out = []
    for _ in range(n):
        b = bytearray(sample)
        if b:
            for _ in range(rng.randint(1, 4)):
                i = rng.randrange(len(b))
                b[i] ^= 1 << rng.randrange(8)
            if rng.random() < 0.4:
                b = b[: rng.randrange(len(b) + 1)]
        out.append(bytes(b))
    return out


def _corpus(rng, per=600):
    """Random bytes of varied length, plus mutations of the valid seeds."""
    cases = [b""]
    for _ in range(per):
        cases.append(bytes(rng.randrange(256) for _ in range(rng.randint(0, 80))))
    for sample in _seed_samples():
        cases.extend(_mutations(rng, sample, 120))
    return cases


def _assert_no_raise(label, fn, cases):
    for case in cases:
        try:
            fn(case)
        except Exception as error:   # noqa: BLE001 — that is the whole point
            raise AssertionError(
                f"{label} raised {type(error).__name__} on {case!r} "
                f"(seed {SEED})") from error


# --------------------------------------------------------------------------
# the single-buffer decoders
# --------------------------------------------------------------------------


def test_payload_decoders_never_raise():
    rng = random.Random(SEED)
    cases = _corpus(rng)
    for label, fn in (
        ("decode_tcp", D.decode_tcp),
        ("decode_udp", D.decode_udp),
        ("client_hello", D.client_hello),
        ("dns_message", D.dns_message),
        ("ssh_banner", D.ssh_banner),
        ("ntp_info", D.ntp_info),
        ("dhcp_info", D.dhcp_info),
        ("quic_info", D.quic_info),
        ("record_shape", record_shape),
        ("WifiMonitor.observe", WifiMonitor().observe),
    ):
        _assert_no_raise(label, fn, cases)


def test_linktyped_decoders_never_raise():
    rng = random.Random(SEED + 1)
    cases = _corpus(rng)
    for linktype in _LINKTYPES:
        _assert_no_raise(f"decode_ip/{linktype}",
                         lambda b, lt=linktype: D.decode_ip(lt, b), cases)
        _assert_no_raise(f"arp_info/{linktype}",
                         lambda b, lt=linktype: D.arp_info(lt, b), cases)
        _assert_no_raise(f"dot11_frame/{linktype}",
                         lambda b, lt=linktype: D.dot11_frame(lt, b), cases)


def test_icmp_and_ndp_never_raise():
    rng = random.Random(SEED + 2)
    cases = _corpus(rng)
    for proto in (1, 58, 0, 255):
        _assert_no_raise(f"decode_icmp/{proto}",
                         lambda b, p=proto: D.decode_icmp(p, b), cases)
        _assert_no_raise(f"ndp_pairings/{proto}",
                         lambda b, p=proto: D.ndp_pairings(p, b, "fe80::1"),
                         cases)


def test_record_walker_never_desyncs_into_a_crash():
    rng = random.Random(SEED + 3)
    for case in _corpus(rng):
        walker = RecordWalker()
        try:
            # feed in a couple of slices, as a segmented stream would arrive
            walker.feed(case[: len(case) // 2])
            walker.feed(case[len(case) // 2:])
        except Exception as error:   # noqa: BLE001
            raise AssertionError(f"RecordWalker raised {error!r} on {case!r}")


def test_osfp_options_parser_never_raises():
    rng = random.Random(SEED + 4)
    for case in _corpus(rng):
        tcp_signature(rng.randint(0, 300), rng.randint(0, 70000), case)


def test_integrity_and_neighbor_never_raise():
    rng = random.Random(SEED + 5)
    tracker = IntegrityTracker()
    table = NeighborTable()
    for case in _corpus(rng):
        tracker.frame(rng.random() * 1e9, LINKTYPE_ETHERNET, case)
        # neighbour table takes already-parsed strings; fuzz the shapes it
        # might get from a hostile capture
        table.observe(case.decode("latin-1")[:32], "aa:bb:cc:dd:ee:ff")


# --------------------------------------------------------------------------
# the file reader on garbage
# --------------------------------------------------------------------------


def test_pcap_reader_never_raises_on_garbage_files():
    rng = random.Random(SEED + 6)
    with tempfile.TemporaryDirectory() as d:
        for i in range(60):
            path = Path(d) / f"g{i}.pcap"
            path.write_bytes(bytes(rng.randrange(256)
                                   for _ in range(rng.randint(0, 400))))
            try:
                list(read_frames(path))
            except ValueError:
                pass   # "not a pcap" is a declared, handled outcome
            except Exception as error:   # noqa: BLE001
                raise AssertionError(f"read_frames raised {error!r} on g{i}")


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
