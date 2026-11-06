"""HTTP/2 request-count inference from TLS record framing, without keys.

The estimate is only honest if it is offered solely for h2 (where
multiplexing makes "how many requests" both ambiguous and answerable),
carries its caveat, and — the part that matters most — SUMS across the
endpoint's connections rather than reporting only the busiest one, since an
HTTP/2 client opens many. The end-to-end test builds two connections to one
endpoint and checks the total.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.model import Channel, Direction, Entity, Locus, Observation, Series
from out.http2infer import estimate_requests
from out.narrate import narrate


# --------------------------------------------------------------------------
# the inference
# --------------------------------------------------------------------------


def test_only_h2_gets_an_estimate():
    assert estimate_requests(["h2", "http/1.1"], 40) is not None
    assert estimate_requests(["http/1.1"], 40) is None   # HTTP/1.1: not h2
    assert estimate_requests([], 40) is None


def test_zero_records_is_no_estimate():
    assert estimate_requests(["h2"], 0) is None


def test_estimate_carries_its_basis_and_caveat():
    est = estimate_requests(["h2"], 270, 300)
    assert est["requests_proxy"] == 270
    assert "270 outbound application-data record" in est["basis"]
    assert "control frames" in est["caveat"] and "coalesc" in est["caveat"]


# --------------------------------------------------------------------------
# end to end: summed across the endpoint's connections
# --------------------------------------------------------------------------


def _tls_obs(stream, out_records, i, host="10.0.0.5", dest="203.0.113.9"):
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443", "sni": "shop.test"},
        initiator=Entity("ip", host, labels={"private": True}),
        responder=Entity("ip", dest, labels={"private": False}),
    )
    return channel, Observation(
        ts=1_700_000_000.0 + i, channel=channel, direction=Direction.EGRESS,
        size=200, kind="tcp_burst",
        attrs={"encrypted": True, "tls_version": "TLS 1.3",
               "tls_client_alpn": "h2,http/1.1",
               "tls_rec_out": str(out_records), "tls_rec_in": str(out_records)},
        locus=Locus(source="t", frames=(i,), stream=stream))


def test_endpoint_request_estimate_sums_connections():
    # two TCP streams to one endpoint: 10 and 20 outbound records -> 30 total
    obs = []
    channel = None
    for stream, recs in ((1, 10), (2, 20)):
        for i in range(2):   # >= min_observations
            channel, o = _tls_obs(stream, recs, stream * 10 + i)
            obs.append(o)
    series = [Series(channel, obs)]
    text = " ".join(narrate(series, [], source_name="t.pcap").split())
    assert "requests ≈ 30" in text
    assert "across 2 connections" in text
    assert "HTTP/2 estimate" in text


def test_http1_endpoint_gets_no_estimate():
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443", "sni": "x.test"},
        initiator=Entity("ip", "10.0.0.5", labels={"private": True}),
        responder=Entity("ip", "203.0.113.9", labels={"private": False}),
    )
    obs = [Observation(ts=1_700_000_000.0 + i, channel=channel,
                       direction=Direction.EGRESS, size=200, kind="tcp_burst",
                       attrs={"encrypted": True, "tls_client_alpn": "http/1.1",
                              "tls_rec_out": "5"},
                       locus=Locus(source="t", frames=(i,), stream=1))
           for i in range(3)]
    text = narrate([Series(channel, obs)], [], source_name="t.pcap")
    assert "requests" not in text or "HTTP/2 estimate" not in text


def test_glossary_covers_http2_estimate():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "the HTTP/2 estimate: h2 multiplexes many requests")}
    assert "HTTP/2 request estimate" in found


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
