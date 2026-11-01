"""The one-line capture verdict — the gist, synthesised from the facts.

It must agree with the detail below it (it is built from the same series and
stats), classify the common shapes a reader first wants — host-side vs
multi-host, one destination vs many, encrypted vs not, Wi-Fi monitor — and
print first, so a reader who stops after one sentence still knows what they
are looking at.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.model import Channel, Direction, Entity, Locus, Observation, Series
from out.narrate import _verdict, narrate


def _net(host, dest, sni="shop.test", n=6, encrypted=True, tls13=True,
         t0=1_700_000_000.0, step=60.0):
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443", "sni": sni},
        initiator=Entity("ip", host, labels={"private": True}),
        responder=Entity("ip", dest, labels={"private": False}),
    )
    attrs = {"encrypted": encrypted}
    if tls13:
        attrs["tls_version"] = "TLS 1.3"
    obs = [Observation(ts=t0 + i * step, channel=channel,
                       direction=Direction.EGRESS, size=300, kind="tcp_burst",
                       attrs=dict(attrs), locus=Locus(source="t", frames=(i,)))
           for i in range(n)]
    return Series(channel, obs)


def _flat(series, stats=None):
    return " ".join("\n".join(_verdict(series, stats or {},
                                       {d: d for d in ()})).split())


# --------------------------------------------------------------------------


def test_host_side_single_destination_all_encrypted():
    text = " ".join("\n".join(
        _verdict([_net("10.0.0.5", "203.0.113.9")], {},
                 {"203.0.113.9": "shop.test"})).split())
    assert "host-side capture: one host" in text
    assert "one destination (shop.test)" in text
    assert "all of it encrypted (TLS 1.3)" in text
    assert "over 5.0 min" in text          # 6 obs, 60s apart = 5 min span


def test_multiple_hosts_and_destinations():
    series = [_net("10.0.0.5", "203.0.113.9"),
              _net("10.0.0.6", "198.51.100.7")]
    text = _flat(series)
    assert "2 originating hosts" in text
    assert "2 destinations" in text


def test_partial_encryption_reads_as_a_percentage():
    series = [_net("10.0.0.5", "203.0.113.9", n=6, encrypted=True, tls13=False),
              _net("10.0.0.5", "198.51.100.7", sni="", n=6, encrypted=False,
                   tls13=False)]
    text = _flat(series)
    assert "% encrypted" in text and "TLS 1.3" not in text


def test_wifi_monitor_capture_verdict():
    stats = {"wireless": {
        "aps": {"aa:bb:cc:00:00:01": {"ssid": "CorpWiFi", "beacons": 9}},
        "probes": {"de:ad:be:ef:00:01": {"HomeNet": 2}},
        "deauths": {"total": 40, "pairs": []},
        "frames": 60,
    }}
    text = " ".join("\n".join(_verdict([], stats, {})).split())
    assert "Wi-Fi monitor-mode capture" in text
    assert "1 access point" in text
    assert "1 client probing" in text
    assert "40 deauth/disassoc frame(s)" in text


def test_empty_capture_yields_no_verdict():
    assert _verdict([], {}, {}) == []
    assert _verdict([], {"wireless": {}}, {}) == []


def test_verdict_is_the_first_section_of_the_report():
    text = narrate([_net("10.0.0.5", "203.0.113.9")], [], source_name="t.pcap")
    # AT A GLANCE precedes WHAT THIS CAPTURE SHOWS
    assert "AT A GLANCE" in text
    assert text.index("AT A GLANCE") < text.index("WHAT THIS CAPTURE SHOWS")


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
