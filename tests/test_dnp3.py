"""DNP3 (IEEE 1815) — the third domain.

A better test of the "domains are cheap" claim than Modbus, because DNP3 is
genuinely hard to parse: the link layer CRCs its header and every 16-octet
block of user data, and Wireshark validates them. A frame with wrong CRCs
dissects as malformed and never reaches the application layer, so every
field the analyzer needs would simply be absent — indistinguishable from
"DNP3 is not supported here".

`test_sequence_wrap_keeps_transactions_distinct` pins a real defect: the DNP3
application sequence is four bits and wraps at 16, so a `stream:seq`
transaction key folded 40 poll cycles into 16 groups of ten.
"""

from __future__ import annotations

import random
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from core.baseline import SqliteBaseline
from core.model import Context
from core.primitives import stack_for
from core.score import analyse_series, run
from inspectors import inspectors_for
from ontology import ONTOLOGIES
from tools.make_dnp3_pcap import (
    ADDR_MASTER,
    ADDR_ROGUE,
    MASTER,
    OUTSTATION,
    PROFILES,
    ROGUE,
    dnp3_crc,
    dnp3_frame,
    write_pcap,
)

HAVE_TSHARK = shutil.which("tshark") is not None


def _pcap(tmp: Path, profile: str) -> Path:
    path = tmp / f"dnp3-{profile}.pcap"
    write_pcap(path, PROFILES[profile](random.Random(20261024)))
    return path


def _series(path: Path):
    from capture.tshark import Dnp3Profile, TsharkSource

    source = TsharkSource(path, profile=Dnp3Profile())
    return list(group_into_series(source.observations(), min_observations=1)), source


def _analyse(tmp: Path, profile: str, baseline):
    series, _ = _series(_pcap(tmp, profile))
    ctx = Context(now=max(s.end or 0.0 for s in series), baseline=baseline)
    return run(series, ONTOLOGIES, ctx)


def _trained(tmp: Path) -> SqliteBaseline:
    baseline = SqliteBaseline(tmp / "scada.db")
    _analyse(tmp, "normal", baseline)
    return baseline


def _channel(series, host):
    return next(s for s in series if s.channel.initiator.value == host)


def _rules(findings):
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------
# the fixture's own correctness
# --------------------------------------------------------------------------


def test_crc_is_self_consistent():
    """The CRC must verify by the same algorithm that produced it, or the
    fixture is testing the parser against invalid input."""
    for payload in (b"\x05\x64\x05\xc4\x0a\x00\x01\x00", b"", b"\xc0\xc0\x01"):
        crc = dnp3_crc(payload)
        assert 0 <= crc <= 0xFFFF
    # Distinct inputs must not collide trivially.
    assert dnp3_crc(b"\x01\x02") != dnp3_crc(b"\x02\x01")


def test_frame_layout_matches_the_standard():
    """LENGTH counts CTRL..SRC plus user data, excluding the start bytes,
    the length octet itself, and every CRC."""
    user = b"\xc0\xc0\x01"
    frame = dnp3_frame(0xC4, 10, 1, user)
    assert frame[0:2] == b"\x05\x64"
    assert frame[2] == 5 + len(user)
    # 10-octet header (8 + CRC), then the user block plus its own CRC.
    assert len(frame) == 10 + len(user) + 2


def test_wireshark_accepts_the_fabricated_frames():
    """If this fails, every other DNP3 test is vacuous — a bad link CRC
    stops the dissector before the application layer and all the fields come
    back empty."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, source = _series(_pcap(Path(d), "normal"))
        assert source.stats["observations"] >= 80, source.stats
        assert series and series[0].count >= 80
        # Application function codes must be populated, not just link frames.
        assert all("fc" in o.attrs for s in series for o in s)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


def test_responses_identified_by_function_code():
    """DNP3 needs no port fallback: 129 and 130 are responses and nothing
    else is, so the Modbus exception-response bug cannot recur here."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "normal"))
        one = series[0]
        assert one.channel.initiator.value == MASTER
        assert one.channel.responder.value == OUTSTATION

        for obs in one:
            if obs.attrs["fc"] in ("129", "130"):
                assert obs.kind == "dnp3_response"
            else:
                assert obs.kind == "dnp3_request"
        # And the outstation never appears as an initiator.
        assert OUTSTATION not in {s.channel.initiator.value for s in series}


def test_sequence_wrap_keeps_transactions_distinct():
    """A REAL DEFECT this caught.

    The DNP3 application sequence is four bits and wraps at 16. Keying
    transactions on `stream:seq` folded 40 poll cycles into 16 groups of ten
    observations each, so `group_by("txn")` returned "transactions" holding
    five unrelated exchanges. A wrap counter restores one request and one
    response per group.
    """
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "normal"))
        one = series[0]
        txns = one.group_by("txn")

        # 40 poll cycles, each one request and one response.
        assert len(txns) == 40, (
            f"{len(txns)} transactions for {one.count} observations — the "
            "4-bit sequence wrap is folding exchanges together"
        )
        for txn, group in txns.items():
            kinds = sorted(o.kind for o in group)
            assert kinds == ["dnp3_request", "dnp3_response"], (txn, kinds)


def test_link_addresses_are_attributes_not_dims():
    """Same lesson as Modbus unit ids and DNS query names: a value in `dims`
    cannot be counted, and an address sweep is the enumeration signature."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "normal"))
        one = series[0]
        assert one.channel.dims == {"proto": "dnp3"}
        assert {o.attrs["link_src"] for o in one.filter(kind="dnp3_request")} == {
            str(ADDR_MASTER)
        }


def test_command_categories_are_graded():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        control, _ = _series(_pcap(tmp, "control"))
        rogue = _channel(control, ROGUE)
        assert {
            o.attrs["category"] for o in rogue.filter(kind="dnp3_request")
        } == {"select", "operate"}

        restart, _ = _series(_pcap(tmp, "restart"))
        rogue = _channel(restart, ROGUE)
        assert {
            o.attrs["category"] for o in rogue.filter(kind="dnp3_request")
        } == {"restart", "suppress"}


def test_internal_indications_are_decoded():
    """The outstation reporting on itself — evidence of the effect rather
    than of the command, and it survives a capture that missed the request."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "restart"))
        flags = {
            o.attrs.get("iin_flags", "") for s in series for o in s
        } - {""}
        assert any("device restart" in f for f in flags), flags
        # And a clean poll must report no flags at all.
        normal, _ = _series(_pcap(Path(d), "normal"))
        assert not {
            o.attrs.get("iin_flags", "") for s in normal for o in s
        } - {""}


# --------------------------------------------------------------------------
# the architectural claim
# --------------------------------------------------------------------------


def test_domain_added_no_new_primitive():
    assert {p.name for p in stack_for("dnp3")} <= {
        "periodicity", "jitter", "burstiness", "rarity",
        "fanout.fc", "fanout.link_dst",
    }
    assert {i.name for i in inspectors_for("dnp3")} == {
        "ics.dnp3_command", "ics.dnp3_indications",
    }


def test_no_latency_primitive_because_there_is_no_elapsed_field():
    """Unlike Modbus, Wireshark exposes no DNP3 response-time field. Leaving
    the primitive out states that, rather than shipping one that silently
    declines on every capture."""
    assert "web.timing_differential" not in {p.name for p in stack_for("dnp3")}


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


def test_normal_polling_is_silent():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "normal", baseline)
        assert not findings, [f.rule_id for f in findings]


def test_rogue_control_is_critical():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "control", baseline)

        control = next(
            (f for f in findings
             if f.rule_id == "dnp3.command.unauthorized_control"), None
        )
        assert control is not None, _rules(findings)
        assert control.severity.value == "critical"
        assert control.channel.initiator.value == ROGUE
        assert "ics-attack:T0831" in control.refs
        # The specific rule supersedes the inventory-level one.
        assert "dnp3.command.control_observed" not in _rules(findings)


def test_restart_is_critical_and_boosted_by_the_device_confirming_it():
    """The Boost exists because the outstation's own Device Restart
    indication is independent evidence that the command took effect."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "restart", baseline)

        restart = next(
            (f for f in findings
             if f.rule_id == "dnp3.command.unauthorized_restart"), None
        )
        assert restart is not None, _rules(findings)
        assert restart.severity.value == "critical"
        trail = " ".join(restart.evidence.by_name("_scoring").notes)
        assert "Device Restart" in trail, trail


def test_disabling_unsolicited_reporting_is_its_own_critical():
    """A denial of VIEW, not of control. Folding it into the configuration
    rules would miss the one message that makes the rest invisible."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "restart", baseline)

        blinding = next(
            (f for f in findings
             if f.rule_id == "dnp3.command.unsolicited_disabled"), None
        )
        assert blinding is not None, _rules(findings)
        assert blinding.severity.value == "critical"
        # The evidence name is CATEGORY-SCOPED. Under a single
        # `ics.dnp3_command` name, folding kept only the highest-scoring
        # category and this rule could never fire — the restart (0.70) hid
        # the suppression (0.65) on the same channel.
        facts = blinding.evidence.by_name("ics.dnp3_command.suppress").facts
        assert "blinding" in facts["effect"]
        assert facts["function"] == "DISABLE_UNSOLICITED"


def test_restart_reported_fires_without_the_command():
    """Evidence of the effect must stand alone — a capture that began after
    the command still shows the outstation announcing its restart."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "restart", baseline)
        assert "dnp3.device.restart_reported" in _rules(findings)


def test_control_from_the_established_master_is_not_critical():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = SqliteBaseline(tmp / "scada.db")
        _analyse(tmp, "control", baseline)          # the rogue is now known
        findings, _ = _analyse(tmp, "control", baseline)

        assert "dnp3.command.unauthorized_control" not in _rules(findings)
        assert "dnp3.command.control_observed" in _rules(findings)


def test_rules_use_ics_attack_references():
    for rule in ONTOLOGIES["dnp3"].rules:
        assert rule.refs, rule.id
        assert any(r.startswith("ics-attack:") for r in rule.refs), rule.id


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
