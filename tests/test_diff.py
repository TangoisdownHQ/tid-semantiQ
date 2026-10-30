"""The capture diff — what changed between two files IS the meaning.

The profile/render split is tested separately from the CLI. The properties
that matter: "new" is strictly asymmetric (second minus first); the volume
gate requires BOTH the ratio and the absolute floor; a finding that stopped
firing is reported with the absence-of-evidence hedge, not as "fixed"; and
two identical captures produce an explicit "nothing differed" statement
rather than an empty page the reader has to interpret.
"""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.model import (
    Channel, Direction, Entity, Evidence, Finding, Locus, Observation,
    Series, Severity,
)
from out.diff import CaptureProfile, profile, render_diff


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def _series(initiator: str, responder: str, dport: str = "443",
            sni: str = "", zone: str = "", count: int = 4,
            size: int = 500, fingerprint: str = "") -> Series:
    dims = {"proto": "udp" if zone else "tcp"}
    if zone:
        dims["zone"] = zone
    else:
        dims["dport"] = dport
    if sni:
        dims["sni"] = sni
    channel = Channel(
        domain="dns" if zone else "net", dims=dims,
        initiator=Entity("ip", initiator, labels={"private": True}),
        responder=Entity("ip", responder, labels={"private": False}),
    )
    attrs = {"encrypted": bool(sni)}
    if fingerprint:
        attrs["tls_fingerprint"] = fingerprint
    observations = [
        Observation(ts=1_700_000_000.0 + i, channel=channel,
                    direction=Direction.EGRESS, size=size,
                    kind="tcp_burst", attrs=dict(attrs),
                    locus=Locus(source="t.pcap", frames=(i + 1,)))
        for i in range(count)
    ]
    return Series(channel, observations)


def _finding(rule_id: str, responder: str, confidence: float = 0.8) -> Finding:
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", responder),
    )
    return Finding(
        rule_id=rule_id, title=f"t:{rule_id}", channel=channel,
        severity=Severity.HIGH, confidence=confidence,
        evidence=Evidence(channel=channel, series_count=0,
                          window=(0.0, 0.0), results=(), inspections=()),
    )


# --------------------------------------------------------------------------
# profile
# --------------------------------------------------------------------------


def test_profile_collects_the_comparable_facts():
    p = profile("a.pcap", [
        _series("10.0.0.5", "203.0.113.9", sni="shop.test",
                fingerprint="aaaa"),
        _series("10.0.0.5", "10.0.0.1", zone="shop.test"),
    ], [_finding("net.beacon", "203.0.113.9")])
    assert "203.0.113.9" in p.endpoints
    assert "shop.test" in p.endpoints["203.0.113.9"]["names"]
    assert p.hosts == {"10.0.0.5"}
    assert p.zones["shop.test"] == 4
    assert p.tls_prints == {"aaaa"}
    assert len(p.findings) == 1


# --------------------------------------------------------------------------
# diff semantics
# --------------------------------------------------------------------------


def test_new_is_strictly_second_minus_first():
    ref = profile("before", [_series("10.0.0.5", "203.0.113.9")])
    cur = profile("after", [
        _series("10.0.0.5", "203.0.113.9"),
        _series("10.0.0.6", "198.51.100.7"),
    ])
    text = render_diff(ref, cur)
    assert "NEW ORIGINATING HOSTS" in text
    assert "10.0.0.6" in text
    assert "NEW ENDPOINTS" in text
    assert "198.51.100.7" in text
    # the shared endpoint is not "new"
    new_block = text.split("NEW ENDPOINTS", 1)[1]
    assert "203.0.113.9" not in new_block.split("──")[0]


def test_vanished_endpoints_are_reported_separately():
    ref = profile("before", [
        _series("10.0.0.5", "203.0.113.9"),
        _series("10.0.0.5", "198.51.100.7"),
    ])
    cur = profile("after", [_series("10.0.0.5", "203.0.113.9")])
    text = render_diff(ref, cur)
    assert "NO LONGER CONTACTED" in text
    assert "198.51.100.7" in text


def test_volume_shift_requires_ratio_and_floor_together():
    # grew 10x but only ~20 kB moved -> below the floor, not reported
    small_ref = profile("b", [_series("h", "203.0.113.9", size=500, count=4)])
    small_cur = profile("a", [_series("h", "203.0.113.9", size=5000, count=4)])
    assert "VOLUME SHIFTS" not in render_diff(small_ref, small_cur)
    # grew 10x AND moved megabytes -> reported
    big_ref = profile("b", [_series("h", "203.0.113.9", size=50_000, count=4)])
    big_cur = profile("a", [_series("h", "203.0.113.9", size=500_000, count=4)])
    text = render_diff(big_ref, big_cur)
    assert "VOLUME SHIFTS" in text and "grew" in text
    # grew only 2x, huge absolute move -> ratio gate holds it back
    mild_ref = profile("b", [_series("h", "203.0.113.9", size=500_000, count=4)])
    mild_cur = profile("a", [_series("h", "203.0.113.9", size=1_000_000, count=4)])
    assert "VOLUME SHIFTS" not in render_diff(mild_ref, mild_cur)


def test_findings_appear_and_resolve_with_the_hedge():
    ref = profile("before", [], [_finding("net.beacon", "203.0.113.9")])
    cur = profile("after", [], [_finding("dns.tunnel", "10.0.0.1")])
    text = render_diff(ref, cur)
    assert "FINDINGS THAT APPEARED" in text
    assert "dns.tunnel" in text
    assert "FINDINGS NO LONGER PRESENT" in text
    assert "net.beacon" in text
    # the hedge: absence of evidence, not evidence of absence. Collapse
    # whitespace first — the phrase may wrap across lines.
    assert "Absence of evidence" in " ".join(text.split())


def test_identical_captures_say_so_explicitly():
    series = [_series("10.0.0.5", "203.0.113.9", sni="shop.test")]
    text = render_diff(profile("a", series), profile("b", series))
    assert "No new hosts" in text


def test_new_tls_stack_is_reported_with_the_caveat():
    ref = profile("b", [_series("h", "203.0.113.9", fingerprint="aaaa")])
    cur = profile("a", [_series("h", "203.0.113.9", fingerprint="bbbb")])
    text = render_diff(ref, cur)
    assert "NEW TLS CLIENT STACKS" in text
    assert "bbbb" in text
    assert "identifies the library" in text


# --------------------------------------------------------------------------
# CLI end to end, on two generated captures
# --------------------------------------------------------------------------


def test_cli_diff_normal_vs_suspect():
    import os
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    with tempfile.TemporaryDirectory() as d:
        normal = Path(d) / "clean.pcap"
        suspect = Path(d) / "suspect.pcap"
        for path, prof in ((normal, "clean"), (suspect, "suspect")):
            made = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "make_test_pcap.py"),
                 str(path), "--profile", prof],
                env=env, capture_output=True, text=True)
            assert path.exists(), made.stderr
        run = subprocess.run(
            [sys.executable, str(ROOT / "semantiq.py"), "diff",
             str(normal), str(suspect)],
            env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert "CAPTURE DIFF" in run.stdout
    # the two synthetic profiles differ, so something must be reported
    assert ("NEW ENDPOINTS" in run.stdout or "NEW DNS ZONES" in run.stdout
            or "FINDINGS THAT APPEARED" in run.stdout), run.stdout


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
