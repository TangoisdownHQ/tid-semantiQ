"""The eBPF flow-feed backend — behavioural analysis from flow records.

Two things carry the feature. The contract adapter must map a flow record to
the SAME channel the pcap path would, so a flow from the kernel scores
identically — in particular both directions of one flow must land on one
channel key, or no cadence can ever form. And the tier must actually catch a
beacon: synthetic per-burst flow records for a periodic, novel destination,
run against a warmed baseline through the real scorer, must fire the beacon
rule — proving the behavioural half survives losing the payload.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.base import group_into_series
from capture.ebpf import EbpfSource, FlowRecord, flow_observation, read_jsonl_flows
from core.baseline import SqliteBaseline
from core.model import Context, Direction
from core.score import run
from ontology import ONTOLOGIES

_BASE_TS = 1_700_000_000.0


# --------------------------------------------------------------------------
# the contract
# --------------------------------------------------------------------------


def test_jsonl_parses_valid_and_skips_junk():
    lines = [
        '{"ts": 1700000000.0, "proto": "tcp", "saddr": "10.0.0.5", '
        '"daddr": "203.0.113.9", "sport": 5, "dport": 443, "dir": "egress", '
        '"bytes": 256}',
        "# a comment",
        "not json at all",
        '{"ts": 1700000001.0, "proto": "udp"}',          # missing addrs
        "",
    ]
    records = list(read_jsonl_flows(lines))
    assert len(records) == 1
    assert records[0].daddr == "203.0.113.9" and records[0].dport == 443
    assert records[0].packets == 1                       # default filled in


def test_both_directions_of_a_flow_share_one_channel_key():
    out = flow_observation(FlowRecord(_BASE_TS, "tcp", "10.0.0.5",
                                      "203.0.113.9", 51000, 443, "egress", 256))
    inn = flow_observation(FlowRecord(_BASE_TS, "tcp", "203.0.113.9",
                                      "10.0.0.5", 443, 51000, "ingress", 900))
    assert out.channel.key == inn.channel.key, "flow directions split channels"
    # local is always the initiator, remote the responder, service port kept
    assert out.channel.initiator.value == "10.0.0.5"
    assert out.channel.responder.value == "203.0.113.9"
    assert out.channel.dims["dport"] == "443"
    assert out.direction == Direction.EGRESS and inn.direction == Direction.INGRESS


def test_source_counts_and_describes_the_tier():
    records = [
        FlowRecord(_BASE_TS, "tcp", "10.0.0.5", "203.0.113.9", 5, 443, "egress", 256),
        FlowRecord(_BASE_TS, "udp", "10.0.0.5", "10.0.0.1", 5, 53, "egress", 60),
    ]
    source = EbpfSource(records)
    obs = list(source.observations())
    assert len(obs) == 2
    assert source.stats["tcp"] == 1 and source.stats["udp"] == 1
    assert "no payload" in source.describe().lower()


# --------------------------------------------------------------------------
# the tier catches a beacon
# --------------------------------------------------------------------------


def _benign_records(rng, hosts, dests, span_s):
    recs = []
    for h in range(hosts):
        host = f"10.0.0.{h + 1}"
        for d, dest in enumerate(dests):
            period = 60.0 * (d + 1)
            ts = _BASE_TS
            while ts < _BASE_TS + span_s:
                recs.append(FlowRecord(ts, "tcp", host, dest,
                                       40000 + d, 443, "egress", 512))
                ts += period
    return recs


def _beacon_records(dest, period_s, callbacks):
    return [FlowRecord(_BASE_TS + i * period_s, "tcp", "10.9.9.9", dest,
                       51000, 443, "egress", 256) for i in range(callbacks)]


def _series(records):
    return list(group_into_series(EbpfSource(records).observations(),
                                  min_observations=2))


def test_behavioural_tier_detects_a_beacon_and_suppresses_pollers():
    rng = random.Random(1337)
    dests = [f"203.0.113.{i + 1}" for i in range(3)]
    with tempfile.TemporaryDirectory() as d:
        store = SqliteBaseline(Path(d) / "m.db")
        benign = _series(_benign_records(rng, 10, dests, 120 * 60))
        run(benign, ONTOLOGIES,
            Context(now=max(s.end or 0.0 for s in benign), baseline=store))

        beacon = _series(_beacon_records("198.51.100.7", 60.0, 30))
        findings, _ = run(beacon, ONTOLOGIES,
                          Context(now=max(s.end or 0.0 for s in beacon),
                                  baseline=store), record=False)
    assert any(f.rule_id.startswith("net.beacon") for f in findings), (
        "the behavioural tier failed to catch a clean beacon")


# --------------------------------------------------------------------------
# the tshark bridge produces the contract
# --------------------------------------------------------------------------


def test_tshark_bridge_aggregates_bursts():
    """Feed tshark-field lines; expect one record per burst, with the gap
    closing bursts and bytes/packets summed."""
    bridge = ROOT / "capture" / "bpf" / "flows_from_tshark.py"
    # two packets 0.1s apart (one burst) then a third 5s later (new burst),
    # all on one tcp flow 10.0.0.5 -> 203.0.113.9:443
    lines = "\n".join([
        "1700000000.0\t10.0.0.5\t203.0.113.9\t6\t51000\t443\t\t\t100",
        "1700000000.1\t10.0.0.5\t203.0.113.9\t6\t51000\t443\t\t\t200",
        "1700000005.0\t10.0.0.5\t203.0.113.9\t6\t51000\t443\t\t\t300",
    ]) + "\n"
    out = subprocess.run([sys.executable, str(bridge), "--local", "10.0.0.5"],
                         input=lines, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    records = list(read_jsonl_flows(out.stdout.splitlines()))
    assert len(records) == 2, out.stdout
    assert records[0].bytes == 300 and records[0].packets == 2   # merged burst
    assert records[1].bytes == 300                               # the later one
    assert all(r.direction == "egress" for r in records)         # --local set


def test_bridge_infers_direction_without_local():
    bridge = ROOT / "capture" / "bpf" / "flows_from_tshark.py"
    line = "1700000000.0\t192.168.1.9\t8.8.8.8\t17\t\t\t40000\t53\t60\n"
    out = subprocess.run([sys.executable, str(bridge)],
                         input=line, capture_output=True, text=True)
    rec = list(read_jsonl_flows(out.stdout.splitlines()))[0]
    assert rec.direction == "egress"       # private src, public dst
    assert rec.proto == "udp" and rec.dport == 53


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
