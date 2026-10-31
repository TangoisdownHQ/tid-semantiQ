"""Passive OS fingerprinting from the TCP SYN — p0f's idea, kept honest.

The TTL is inferred (rounded up past the hops it crossed) and the family is
coarse; both must be exactly that, and the classifier must decline when the
signal is not decisive. The parser has to read TCP options (MSS, window
scale, SACK, timestamps, order) correctly, and the whole thing has to reach
the report from a real SYN through decode_tcp.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.decode import decode_ip, decode_tcp
from capture.osfp import classify, tcp_signature
from capture.pcapfile import LINKTYPE_ETHERNET


# MSS(4) NOP WScale(3) SACK-OK(2) ... a Linux-ish option layout
_LINUX_OPTS = (b"\x02\x04\x05\xb4"          # MSS 1460
               b"\x04\x02"                  # SACK permitted
               b"\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00"  # timestamps
               b"\x01"                      # NOP
               b"\x03\x03\x07")             # window scale 7
_WIN_OPTS = (b"\x02\x04\x05\xb4"            # MSS 1460
             b"\x01\x03\x03\x08"            # NOP, window scale 8
             b"\x01\x01\x04\x02")           # NOP NOP, SACK permitted (no TS)


# --------------------------------------------------------------------------
# signature + classify
# --------------------------------------------------------------------------


def test_initial_ttl_and_hops_are_inferred():
    sig = tcp_signature(ttl=54, window=64240, options=_LINUX_OPTS)
    assert sig["initial_ttl"] == 64 and sig["hops"] == 10
    sig2 = tcp_signature(ttl=120, window=65535, options=_WIN_OPTS)
    assert sig2["initial_ttl"] == 128 and sig2["hops"] == 8
    sig3 = tcp_signature(ttl=255, window=4128, options=b"\x02\x04\x02\x18")
    assert sig3["initial_ttl"] == 255 and sig3["hops"] == 0


def test_options_are_parsed():
    sig = tcp_signature(ttl=64, window=64240, options=_LINUX_OPTS)
    assert sig["mss"] == 1460
    assert sig["sack_ok"] is True and sig["timestamps"] is True
    assert sig["wscale"] == 7
    assert sig["layout"] == ["mss", "sackok", "ts", "nop", "ws"]


def test_classify_families():
    assert classify(tcp_signature(120, 65535, _WIN_OPTS)) == "Windows"
    linux = classify(tcp_signature(54, 64240, _LINUX_OPTS))
    assert "Linux" in linux and "64" in linux
    appliance = classify(tcp_signature(250, 4128, b""))
    assert "appliance" in appliance or "255" in appliance


def test_timestamps_off_at_ttl64_is_called_out():
    # a 64-family stack with timestamps off is worth noting, not called Linux
    sig = tcp_signature(ttl=64, window=64240, options=b"\x02\x04\x05\xb4")
    assert classify(sig) == ("a 64-TTL stack (Linux/macOS/BSD) "
                             "with timestamps off")


def test_classify_declines_without_a_known_ttl():
    # TTL above every common initial -> no inference
    assert classify(tcp_signature(ttl=300, window=0, options=b"")) is None


def test_malformed_options_do_not_crash():
    for opts in (b"\x02", b"\x02\x09", b"\xff\xff\xff", b"\x08\x02"):
        sig = tcp_signature(ttl=64, window=100, options=opts)
        assert isinstance(sig, dict)


# --------------------------------------------------------------------------
# decode exposes the fields
# --------------------------------------------------------------------------


def test_decode_tcp_exposes_window_and_options():
    syn = struct.pack(">HHIIBBHHH", 51000, 443, 0, 0, (10 << 4), 0x02,
                      64240, 0, 0) + _LINUX_OPTS
    seg = decode_tcp(syn)
    assert seg.syn and seg.window == 64240
    assert seg.options == _LINUX_OPTS


def test_decode_ip_exposes_ttl():
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 54, 6, 0,
                     bytes([10, 0, 0, 5]), bytes([10, 0, 0, 9]))
    ip += struct.pack(">HHIIBBHHH", 51000, 443, 0, 0, (5 << 4), 0x02,
                      64240, 0, 0)
    eth = b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip
    pkt = decode_ip(LINKTYPE_ETHERNET, eth)
    assert pkt is not None and pkt.ttl == 54


# --------------------------------------------------------------------------
# end to end: a SYN's fingerprint reaches the report
# --------------------------------------------------------------------------


def test_syn_fingerprint_reaches_host_detail():
    from capture.base import group_into_series
    from capture.pcap import PcapSource
    from out.narrate import narrate

    def _syn(src, dst, sport, dport, flags, ttl, opts=b"", payload=b""):
        off = 5 + (len(opts) // 4)
        tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, (off << 4),
                          flags, 64240, 0, 0) + opts + payload
        total = 20 + len(tcp)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, ttl, 6, 0,
                         bytes(int(o) for o in src.split(".")),
                         bytes(int(o) for o in dst.split(".")))
        return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + tcp

    frames = [
        _syn("10.0.0.5", "93.184.216.34", 51000, 443, 0x02, 64, _LINUX_OPTS),
        _syn("93.184.216.34", "10.0.0.5", 443, 51000, 0x12, 120, _WIN_OPTS),
        _syn("10.0.0.5", "93.184.216.34", 51000, 443, 0x10, 64, b"", b"data!"),
        _syn("93.184.216.34", "10.0.0.5", 443, 51000, 0x10, 120, b"", b"back!"),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.pcap"
        with open(path, "wb") as h:
            h.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                LINKTYPE_ETHERNET))
            for i, fr in enumerate(frames):
                h.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                    len(fr), len(fr)))
                h.write(fr)
        src = PcapSource(path)
        series = list(group_into_series(src.observations(), min_observations=2))
        text = narrate(series, [], stats=src.stats, source_name="t.pcap")
    assert "10.0.0.5" in src.stats["os_fingerprints"]
    assert src.stats["os_fingerprints"]["10.0.0.5"]["initial_ttl"] == 64
    flat = " ".join(text.split())
    assert "stack" in flat
    assert "Linux" in flat            # the host
    assert "Windows" in flat          # the server (SYN-ACK TTL 120)


def test_glossary_covers_osfp():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in("the SYN's TTL 54→64 implies 10 hops")}
    assert "passive OS fingerprint (TTL, SYN)" in found


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
