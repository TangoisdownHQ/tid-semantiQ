"""QUIC — the envelope is readable, the rest is honest shape.

QUIC seals even its first packet's contents, so the only honest stdlib
claims are the long-header envelope (version, packet type) and the shape.
The tests pin the parser's plausibility gates — a short header alone must
never be called QUIC, because its two-bit signature matches random payloads
one time in four — plus the flow memory that keeps counting a connection's
short-header bulk as encrypted after its handshake proved it QUIC.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.base import group_into_series
from capture.decode import quic_info
from capture.pcap import PcapSource
from capture.pcapfile import LINKTYPE_ETHERNET
from out.narrate import narrate


def _quic_initial(version: int = 0x00000001, type_bits: int = 0) -> bytes:
    first = 0x80 | 0x40 | (type_bits << 4)
    # version, DCID len 8 + DCID, SCID len 0, then padding to a plausible size
    return (bytes([first]) + struct.pack(">I", version)
            + bytes([8]) + b"\x11" * 8 + bytes([0]) + b"\x00" * 60)


def _ip_udp(src, dst, sport, dport, payload) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
                     bytes(int(o) for o in src.split(".")),
                     bytes(int(o) for o in dst.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + udp


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def test_v1_initial_is_recognised():
    info = quic_info(_quic_initial())
    assert info is not None
    assert info.version == "v1 (RFC 9000)"
    assert info.packet == "initial"


def test_v1_packet_types_are_mapped():
    assert quic_info(_quic_initial(type_bits=2)).packet == "handshake"
    assert quic_info(_quic_initial(type_bits=3)).packet == "retry"


def test_version_negotiation_is_named():
    info = quic_info(_quic_initial(version=0))
    assert info.version == "negotiation"


def test_short_header_alone_is_never_quic():
    """A short header's signature is two bits; random data matches it one
    time in four, so the stateless parser must refuse it outright."""
    assert quic_info(b"\x40" + b"\x00" * 30) is None
    assert quic_info(b"\x7f" + b"\x00" * 30) is None


def test_missing_fixed_bit_is_rejected():
    broken = bytearray(_quic_initial())
    broken[0] &= ~0x40
    assert quic_info(bytes(broken)) is None


def test_unknown_version_needs_a_plausible_dcid_length():
    # Unknown version with DCID length 200 -> not QUIC, just bytes.
    first = 0x80 | 0x40
    bogus = (bytes([first]) + struct.pack(">I", 0x12345678)
             + bytes([200]) + b"\x00" * 40)
    assert quic_info(bogus) is None


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------


def _narrate(frames):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "t.pcap"
        with open(path, "wb") as handle:
            handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                     65535, LINKTYPE_ETHERNET))
            for index, frame in enumerate(frames):
                handle.write(struct.pack("<IIII", 1_700_000_000 + index,
                                         0, len(frame), len(frame)))
                handle.write(frame)
        source = PcapSource(path)
        series = list(group_into_series(source.observations()))
    return series, narrate(series, [], source_name="t.pcap")


def test_quic_channel_reaches_the_report_as_encrypted():
    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _ip_udp(client, server, 50000, 443, _quic_initial()),
        _ip_udp(server, client, 443, 50000, _quic_initial(type_bits=2)),
        # short-header bulk after the handshake: flow memory must keep
        # counting these as the encrypted traffic they are
        _ip_udp(client, server, 50000, 443, b"\x41" + b"\x00" * 1100),
        _ip_udp(server, client, 443, 50000, b"\x43" + b"\x00" * 1100),
    ]
    series, text = _narrate(frames)
    assert "QUIC" in text
    assert "v1 (RFC 9000)" in text
    quic_series = [s for s in series
                   if s.channel.dims.get("dport") == "443"
                   and s.channel.dims.get("proto") == "udp"]
    assert quic_series
    encrypted = [bool(o.attrs.get("encrypted")) for s in quic_series
                 for o in s]
    assert all(encrypted), encrypted   # short-header bulk included


def test_non_quic_udp_443_stays_cleartext():
    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _ip_udp(client, server, 50000, 443, b"\x41hello world"),
        _ip_udp(client, server, 50000, 443, b"\x41hello again"),
    ]
    series, text = _narrate(frames)
    assert "QUIC" not in text
    for one in series:
        for obs in one:
            assert not obs.attrs.get("encrypted")


def test_glossary_covers_quic():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in("the host spoke QUIC (HTTP/3)")}
    assert "QUIC / HTTP/3" in found


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
