"""Capture integrity — honesty about the file, not the traffic.

The tracker's job is to notice what decoding silently tolerates: frames cut
short by a snaplen, SPAN-port duplicates, a clock that runs backwards, and
capture gaps. The tests pin each detector against built frames, the
distinctions that keep them honest (a retransmit is NOT a duplicate; zero
timestamps judge nothing), and the section's placement rule — printed only
when an artefact exists, early enough to qualify the measurements below it.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.base import group_into_series
from capture.integrity import IntegrityTracker
from capture.pcap import PcapSource
from capture.pcapfile import LINKTYPE_ETHERNET
from out.narrate import _capture_integrity, narrate


def _ip_udp(src, dst, sport, dport, payload, claim_extra: int = 0) -> bytes:
    """A UDP frame; `claim_extra` makes the IP header claim bytes that are
    not present, which is exactly what snaplen truncation looks like."""
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp) + claim_extra
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
                     bytes(int(o) for o in src.split(".")),
                     bytes(int(o) for o in dst.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + udp


def _feed(tracker, frames_with_ts):
    for ts, frame in frames_with_ts:
        tracker.frame(ts, LINKTYPE_ETHERNET, frame)


# --------------------------------------------------------------------------
# detectors
# --------------------------------------------------------------------------


def test_truncated_frames_are_counted_with_missing_bytes():
    tracker = IntegrityTracker()
    whole = _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222, b"x" * 20)
    cut = _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222, b"x" * 20,
                  claim_extra=500)
    _feed(tracker, [(1.0, whole), (2.0, cut)])
    report = tracker.report()
    assert report["truncated"] == 1
    assert report["truncated_missing"] == 500


def test_byte_identical_neighbours_are_duplicates():
    tracker = IntegrityTracker()
    frame = _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222, b"hello")
    _feed(tracker, [(1.0, frame), (1.000001, frame)])
    assert tracker.report()["duplicates"] == 1


def test_a_retransmit_differing_in_ip_header_is_not_a_duplicate():
    """The honesty line: a real TCP retransmit changes its IP id, so frames
    that differ anywhere are the network repeating itself, not the capture
    apparatus copying."""
    tracker = IntegrityTracker()
    a = _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222, b"hello")
    b = bytearray(a)
    b[18] ^= 0x01    # flip one bit of the IP id field
    _feed(tracker, [(1.0, a), (1.1, bytes(b))])
    assert "duplicates" not in tracker.report()


def test_backwards_clock_and_gap_are_separated():
    tracker = IntegrityTracker()
    frame = _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222, b"a")
    later = _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222, b"b")
    _feed(tracker, [
        (100.0, frame),
        (90.0, later),             # 10s backwards
        (95.0, frame + b"c"),
        (300.0, later + b"d"),     # 205s gap
    ])
    report = tracker.report()
    assert report["backwards"] == 1
    assert report["max_regression_s"] == 10.0
    assert report["gaps"] == 1
    assert report["largest_gap_s"] == 205.0


def test_zero_timestamps_judge_nothing():
    """A reader that cannot resolve a timestamp yields 0.0; treating that as
    time would manufacture a regression on every real frame after it."""
    tracker = IntegrityTracker()
    frame = _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222, b"a")
    _feed(tracker, [(0.0, frame), (100.0, frame + b"b"),
                    (0.0, frame + b"c"), (101.0, frame + b"d")])
    report = tracker.report()
    assert "backwards" not in report
    assert "gaps" not in report


def test_clean_capture_reports_empty():
    tracker = IntegrityTracker()
    _feed(tracker, [
        (float(i), _ip_udp("10.0.0.5", "10.0.0.1", 1111, 2222,
                           bytes([i]) * 10))
        for i in range(1, 6)
    ])
    assert tracker.report() == {}


# --------------------------------------------------------------------------
# the section
# --------------------------------------------------------------------------


def test_clean_capture_prints_no_section():
    assert _capture_integrity({"integrity": {}}) == []
    assert _capture_integrity({}) == []
    assert _capture_integrity(None) == []


def test_section_names_each_artefact_and_its_consequence():
    stats = {"integrity": {
        "frames": 1000, "truncated": 40, "truncated_missing": 52_000,
        "duplicates": 90, "backwards": 3, "max_regression_s": 2.0,
        "gaps": 1, "largest_gap_s": 420.0, "largest_gap_at": 1_700_000_000.0,
    }}
    text = " ".join("\n".join(_capture_integrity(stats)).split())
    assert "CAPTURE ARTEFACTS" in text
    assert "snaplen" in text
    assert "SPAN port" in text
    assert "cadence, jitter and latency" in text
    assert "stopped and resumed" in text
    # consequence wording, not just counts
    assert "saw only the front" in text


# --------------------------------------------------------------------------
# end to end: a truncated capture narrates its own defect
# --------------------------------------------------------------------------


def test_pcap_source_carries_integrity_into_the_narration():
    frames = [
        _ip_udp("10.0.0.5", "10.0.0.1", 40000, 9999, b"x" * 30,
                claim_extra=200),
        _ip_udp("10.0.0.5", "10.0.0.1", 40000, 9999, b"y" * 30,
                claim_extra=200),
    ]
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
        text = narrate(series, [], stats=source.stats, source_name="t.pcap")
    assert "CAPTURE ARTEFACTS" in text
    assert "2 of 2 frames" in text


def test_glossary_covers_capture_artefacts():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "a snaplen cut frames short; SPAN port duplicates")}
    assert "capture artefacts (snaplen, SPAN duplicates)" in found


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
