"""`Series.group_by()` and the transaction/timing plumbing.

Groundwork for per-endpoint analysis, landed and tested on its own so the
data can be inspected before committing to the response-time oracle. See
docs/ADR-001-endpoint-grain.md for why this exists instead of endpoint-level
`Channel.dims`.

`test_keepalive_proves_stream_is_not_a_transaction_id` is the load-bearing
one: it is the entire justification for pairing via Wireshark's
`http.request_in` rather than by `tcp.stream`.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.har import HarSource
from core.model import (
    Channel,
    Direction,
    Entity,
    Locus,
    Observation,
    Series,
)
from tools.make_har import build_har
from tools.make_tls_pcap import (
    KEEPALIVE_EXCHANGES,
    build_frames,
    capture_keepalive_session,
    capture_session,
    write_pcap,
)

HAVE_TSHARK = shutil.which("tshark") is not None

CHANNEL = Channel(
    domain="http",
    dims={"scheme": "https", "host": "api.example.test"},
    initiator=Entity("ip", "10.0.0.5"),
    responder=Entity("ip", "203.0.113.9"),
)


def _obs(ts: float, **attrs) -> Observation:
    return Observation(
        ts=ts,
        channel=CHANNEL,
        direction=Direction.EGRESS,
        size=100,
        kind=attrs.pop("kind", "http_request"),
        attrs=attrs,
        locus=Locus("t.pcap", frames=(int(ts),), stream=0),
    )


# --------------------------------------------------------------------------
# group_by, in isolation
# --------------------------------------------------------------------------


def test_group_by_attribute_name():
    series = Series(CHANNEL, [
        _obs(1, path="/a"), _obs(2, path="/b"),
        _obs(3, path="/a"), _obs(4, path="/a"),
    ])
    groups = series.group_by("path")
    assert set(groups) == {"/a", "/b"}
    assert groups["/a"].count == 3
    assert groups["/b"].count == 1
    assert sum(g.count for g in groups.values()) == series.count


def test_group_by_callable():
    """A key function lets a group be derived rather than read — which is how
    the oracle will partition by outcome, since "valid user" is not an
    attribute anyone sets."""
    series = Series(CHANNEL, [
        _obs(1, status="200"), _obs(2, status="404"),
        _obs(3, status="201"), _obs(4, status="500"),
    ])
    groups = series.group_by(
        lambda o: "ok" if o.attrs.get("status", "").startswith("2") else "error"
    )
    assert groups["ok"].count == 2
    assert groups["error"].count == 2


def test_group_by_excludes_missing_keys_rather_than_bucketing_them():
    """A missing key means the question does not apply to that observation.
    Collecting them under a null group would invent a cohort out of unrelated
    messages — and then report statistics about it."""
    series = Series(CHANNEL, [
        _obs(1, path="/a"), _obs(2), _obs(3, path=""), _obs(4, path="/a"),
    ])
    groups = series.group_by("path")
    assert set(groups) == {"/a"}
    assert groups["/a"].count == 2
    assert sum(g.count for g in groups.values()) < series.count


def test_groups_keep_the_parent_channel():
    """Findings derived from a group must still attribute to the host. If a
    group carried its own channel we would be back to endpoint-level dims and
    the 12x finding multiplication measured in ADR-001."""
    series = Series(CHANNEL, [_obs(1, path="/a"), _obs(2, path="/b")])
    for group in series.group_by("path").values():
        assert group.channel is CHANNEL
        assert group.channel.dims == {"scheme": "https", "host": "api.example.test"}


def test_groups_are_time_ordered_and_support_the_series_api():
    series = Series(CHANNEL, [
        _obs(30, path="/a"), _obs(10, path="/a"), _obs(20, path="/a"),
    ])
    group = series.group_by("path")["/a"]
    assert group.timestamps() == (10.0, 20.0, 30.0)
    assert group.intervals() == (10.0, 10.0)
    assert group.duration == 20.0


def test_group_by_composes_with_filter():
    """Narrowing then grouping is the shape the oracle needs: responses only,
    grouped by endpoint."""
    series = Series(CHANNEL, [
        _obs(1, path="/a", kind="http_request"),
        _obs(2, path="/a", kind="http_response"),
        _obs(3, path="/b", kind="http_request"),
        _obs(4, path="/b", kind="http_response"),
    ])
    groups = series.filter(kind="http_response").group_by("path")
    assert set(groups) == {"/a", "/b"}
    assert all(g.count == 1 for g in groups.values())
    assert all(
        o.kind == "http_response" for g in groups.values() for o in g
    )


def test_group_by_on_empty_series():
    assert Series(CHANNEL, []).group_by("path") == {}


# --------------------------------------------------------------------------
# the plumbing
# --------------------------------------------------------------------------


def test_keepalive_proves_stream_is_not_a_transaction_id():
    """THE JUSTIFICATION for pairing via `http.request_in`.

    Three transactions over ONE TLS connection, so one `tcp.stream` carries
    six observations. Grouping by stream gives a single bucket in which no
    response can be matched to its request; grouping by `txn` gives three
    transactions with distinct timings.

    Any pairing scheme based on stream identity is silently wrong on every
    keep-alive connection, which is to say on almost all real traffic.
    """
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        pcap, keylog = tmp / "ka.pcap", tmp / "ka.keys"
        sessions = capture_keepalive_session(keylog)
        assert sessions, "keep-alive handshake produced no ciphertext"
        write_pcap(pcap, build_frames(sessions))

        series = list(group_into_series(
            TsharkSource(pcap, profile=HttpProfile(), keylog=keylog).observations(),
            min_observations=1,
        ))
        assert len(series) == 1, "keep-alive should yield one channel"
        one = series[0]

        assert one.count == 2 * len(KEEPALIVE_EXCHANGES)
        assert len(one.group_by("stream")) == 1          # the wrong unit
        assert len(one.group_by("txn")) == len(KEEPALIVE_EXCHANGES)

        # Every transaction must pair exactly one request to one response.
        for txn, sub in one.group_by("txn").items():
            kinds = sorted(o.kind for o in sub)
            assert kinds == ["http_request", "http_response"], (
                f"txn {txn} did not pair cleanly: {kinds}"
            )

        # And the paths must match within a transaction — the real test that
        # pairing is correct and not merely arithmetically tidy.
        for sub in one.group_by("txn").values():
            paths = {o.attrs.get("path") for o in sub}
            assert len(paths) == 1, f"a transaction spans two endpoints: {paths}"


def test_elapsed_is_present_and_plausible():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        pcap, keylog = tmp / "tls.pcap", tmp / "keys.log"
        write_pcap(pcap, build_frames(capture_session(keylog)))
        series = list(group_into_series(
            TsharkSource(pcap, profile=HttpProfile(), keylog=keylog).observations(),
            min_observations=1,
        ))
        responses = [
            o for s in series for o in s
            if o.kind == "http_response"
        ]
        assert responses
        for response in responses:
            elapsed = response.attrs.get("elapsed_s")
            assert elapsed is not None, "no elapsed_s on a paired response"
            assert 0 < elapsed < 60, f"implausible elapsed_s: {elapsed}"


def test_untimed_response_has_no_elapsed_rather_than_zero():
    """An entry with no usable timing must leave `elapsed_s` unset.

    Zero would read as "instantaneous" and poison any latency comparison.
    HAR's convention for an inapplicable phase is -1, not 0.
    """
    entries = build_har()["log"]["entries"]
    for entry in entries:
        entry["time"] = 0
        entry["timings"] = {"send": -1, "wait": -1, "receive": -1}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.har"
        path.write_text(json.dumps({"log": {"version": "1.2",
                                            "creator": {"name": "t", "version": "1"},
                                            "entries": entries}}))
        for obs in HarSource(path).observations():
            assert "elapsed_s" not in obs.attrs


def test_wait_is_preferred_over_total_time():
    """`timings.wait` is server think-time; total `time` folds in dns,
    connect, ssl, send and receive. Using total would bake connection setup
    into every first-request measurement — precisely the warm-up noise the
    latency analyzer excludes."""
    entries = build_har()["log"]["entries"]
    for entry in entries:
        entry["time"] = 500.0                                   # misleading
        entry["timings"] = {"send": 1.0, "wait": 25.0, "receive": 1.0,
                            "connect": 200.0, "ssl": 180.0}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.har"
        path.write_text(json.dumps({"log": {"version": "1.2",
                                            "creator": {"name": "t", "version": "1"},
                                            "entries": entries}}))
        responses = [
            o for o in HarSource(path).observations()
            if o.kind == "http_response"
        ]
        assert responses
        for obs in responses:
            assert obs.attrs["elapsed_s"] == 0.025, "did not prefer timings.wait"
            # connect/ssl > 0 means this entry paid setup cost.
            assert obs.attrs["connection_warm_up"] is True


def test_har_and_pcap_use_the_same_transaction_keys():
    """Both sources must expose `txn` and `elapsed_s`, or an analyzer would
    work on one input and silently do nothing on the other."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)

        har = tmp / "s.har"
        har.write_text(json.dumps(build_har()))
        har_series = list(group_into_series(
            HarSource(har).observations(), min_observations=1
        ))

        pcap, keylog = tmp / "tls.pcap", tmp / "keys.log"
        write_pcap(pcap, build_frames(capture_session(keylog)))
        pcap_series = list(group_into_series(
            TsharkSource(pcap, profile=HttpProfile(), keylog=keylog).observations(),
            min_observations=1,
        ))

        for label, series in (("har", har_series), ("pcap", pcap_series)):
            assert series, f"{label} produced nothing"
            for one in series:
                assert one.group_by("txn"), f"{label}: no txn groups"
            responses = [
                o for s in series for o in s if o.kind == "http_response"
            ]
            assert any("elapsed_s" in o.attrs for o in responses), (
                f"{label}: no elapsed_s on any response"
            )

        # Transaction counts must match between the two paths. The HAR
        # fixture adds one unanswered request, so pcap is the subset.
        har_txns = sum(len(s.group_by("txn")) for s in har_series)
        pcap_txns = sum(len(s.group_by("txn")) for s in pcap_series)
        assert har_txns >= pcap_txns


def test_endpoint_grouping_gives_per_endpoint_timing():
    """What the oracle will consume: responses for one endpoint, with times."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        pcap, keylog = tmp / "ka.pcap", tmp / "ka.keys"
        write_pcap(pcap, build_frames(capture_keepalive_session(keylog)))
        series = list(group_into_series(
            TsharkSource(pcap, profile=HttpProfile(), keylog=keylog).observations(),
            min_observations=1,
        ))
        groups = series[0].filter(kind="http_response").group_by("path")
        assert set(groups) == {"/ka/one", "/ka/two", "/ka/three"}
        for path, sub in groups.items():
            times = [o.attrs["elapsed_s"] for o in sub]
            assert len(times) == 1 and times[0] > 0, f"{path}: {times}"


def test_dead_path_fanout_is_gone():
    """`Fanout(attr="path")` was computed on every http run and referenced by
    no rule. Inventory answers path cardinality properly."""
    from core.primitives import stack_for

    assert "fanout.path" not in {p.name for p in stack_for("http")}


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
    print(f"\n{len(tests) - failed}/{len(tests)} passed"
          + ("" if HAVE_TSHARK else "   (tshark absent: capture tests skipped)"))
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
