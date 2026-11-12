"""Traceroute path reconstruction from ICMP time-exceeded errors.

The reconstructor turns a pile of "time exceeded in transit" errors into the
ordered routers on the way to a destination. The properties that matter:
port order is used when the probe varied it (UDP traceroute), arrival order
otherwise; routers dedup; a single router is not a path; and the whole thing
must survive junk (it is fed capture-derived records). The end-to-end test
proves a reconstructed path reaches the NETWORK PATH report section.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.pcapfile import LINKTYPE_ETHERNET
from core.pathreco import reconstruct


def _err(router, dest, dport=None, ts=0.0, reason="TTL exceeded in transit"):
    return {"reported_by": router, "about": dest, "dport": dport,
            "ts": ts, "reason": reason}


def test_hops_ordered_by_probe_port():
    errors = [
        _err("10.0.0.1", "8.8.8.8", dport=33436, ts=5.0),   # out of ts order
        _err("10.0.0.2", "8.8.8.8", dport=33434, ts=1.0),
        _err("10.0.0.3", "8.8.8.8", dport=33435, ts=3.0),
    ]
    paths = reconstruct(errors)
    assert len(paths) == 1
    assert paths[0]["hops"] == ["10.0.0.2", "10.0.0.3", "10.0.0.1"]
    assert paths[0]["ordered_by"] == "probe port"


def test_falls_back_to_arrival_order_without_varying_ports():
    errors = [
        _err("10.0.0.1", "8.8.8.8", dport=33434, ts=1.0),
        _err("10.0.0.2", "8.8.8.8", dport=33434, ts=2.0),   # same port
        _err("10.0.0.3", "8.8.8.8", dport=33434, ts=3.0),
    ]
    paths = reconstruct(errors)
    assert paths[0]["hops"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert paths[0]["ordered_by"] == "arrival order"


def test_repeated_router_probes_dedup():
    errors = [
        _err("10.0.0.1", "d", dport=1, ts=1.0),
        _err("10.0.0.1", "d", dport=2, ts=2.0),   # same hop, 2nd probe
        _err("10.0.0.2", "d", dport=3, ts=3.0),
    ]
    assert reconstruct(errors)[0]["hops"] == ["10.0.0.1", "10.0.0.2"]


def test_single_router_is_not_a_path():
    assert reconstruct([_err("10.0.0.1", "d", dport=1)]) == []


def test_ipv6_hop_limit_exceeded_is_recognised():
    errors = [
        _err("fe80::1", "2001:db8::1", dport=1, ts=1.0,
             reason="hop limit exceeded in transit"),
        _err("fe80::2", "2001:db8::1", dport=2, ts=2.0,
             reason="hop limit exceeded in transit"),
    ]
    assert reconstruct(errors)[0]["hops"] == ["fe80::1", "fe80::2"]


def test_non_timeexceeded_errors_are_ignored():
    errors = [
        _err("10.0.0.1", "d", dport=1, reason="port unreachable"),
        _err("10.0.0.2", "d", dport=2, reason="host unreachable"),
    ]
    assert reconstruct(errors) == []


def test_two_destinations_give_two_paths_longest_first():
    errors = [
        _err("a1", "destA", dport=1, ts=1), _err("a2", "destA", dport=2, ts=2),
        _err("b1", "destB", dport=1, ts=1), _err("b2", "destB", dport=2, ts=2),
        _err("b3", "destB", dport=3, ts=3),
    ]
    paths = reconstruct(errors)
    assert [p["dest"] for p in paths] == ["destB", "destA"]   # longest first


def test_reconstruct_survives_garbage_records():
    junk = [{}, {"reason": None}, {"about": "?", "reported_by": None,
             "reason": "TTL exceeded in transit"},
            {"reason": "TTL exceeded in transit"}]
    assert reconstruct(junk) == []   # must not raise, must find no path


# --------------------------------------------------------------------------
# end to end: a synthetic traceroute capture narrates its path
# --------------------------------------------------------------------------


def _icmp_time_exceeded(router, src_host, dest, dport, ts_index):
    """An ICMPv4 time-exceeded from `router` quoting a UDP probe host->dest."""
    # the quoted packet: original IP (20) + UDP (8) header
    qudp = struct.pack(">HHHH", 40000, dport, 8, 0)
    qip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 1, 17, 0,
                      bytes(int(o) for o in src_host.split(".")),
                      bytes(int(o) for o in dest.split(".")))
    icmp = bytes([11, 0]) + b"\x00\x00" + b"\x00\x00\x00\x00" + qip + qudp
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0,
                     bytes(int(o) for o in router.split(".")),
                     bytes(int(o) for o in src_host.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + icmp


def test_traceroute_capture_reconstructs_the_path_in_the_report():
    from capture.base import group_into_series
    from capture.pcap import PcapSource
    from out.narrate import narrate

    src, dest = "10.0.0.5", "8.8.8.8"
    routers = ["10.0.0.1", "192.0.2.1", "198.51.100.1"]
    frames = [_icmp_time_exceeded(r, src, dest, 33434 + i, i)
              for i, r in enumerate(routers)]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "tr.pcap"
        with open(path, "wb") as h:
            h.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                LINKTYPE_ETHERNET))
            for i, fr in enumerate(frames):
                h.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                    len(fr), len(fr)))
                h.write(fr)
        source = PcapSource(path)
        series = list(group_into_series(source.observations(), min_observations=1))
        text = " ".join(narrate(series, [], stats=source.stats,
                                source_name="tr.pcap").split())
    assert source.stats["paths"], source.stats.get("paths")
    assert "NETWORK PATH" in text
    assert "10.0.0.1 → 192.0.2.1 → 198.51.100.1" in text
    assert "toward 8.8.8.8" in text


def test_glossary_covers_traceroute():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "ICMP time-exceeded reconstructs the traceroute network path")}
    assert "traceroute / network path (ICMP time-exceeded)" in found


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
