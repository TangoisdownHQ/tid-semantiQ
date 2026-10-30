"""MAVLink — the domain with a NATIVE parser.

Modbus and DNP3 proved a domain can be a tshark field list. MAVLink proves it
can be a native parser instead, and that nothing above `capture/` can tell
the difference: `test_native_parser_needs_no_tshark` runs the whole pipeline
with tshark unavailable to the source.

`test_wire_order_is_size_descending` is the one most likely to catch a real
mistake. MAVLink does not serialise fields in declaration order — it sorts by
type size, largest first — and getting that wrong yields plausible-looking
nonsense rather than an error.
"""

from __future__ import annotations

import math
import random
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.mavlink import (
    MavlinkSource,
    haversine_m,
    parse_frames,
)
from core.baseline import SqliteBaseline
from core.model import Context
from core.primitives import stack_for
from core.score import run
from inspectors import inspectors_for
from ontology import ONTOLOGIES
from tools.make_mavlink_pcap import (
    ATTACKER_IP,
    HOME_LAT,
    HOME_LON,
    PROFILES,
    SYS_ATTACKER,
    SYS_VEHICLE,
    command_long,
    global_position,
    heartbeat,
    mavlink_v1,
    mavlink_v2,
    param_set,
    write_pcap,
)


def _pcap(tmp: Path, profile: str) -> Path:
    path = tmp / f"mav-{profile}.pcap"
    write_pcap(path, PROFILES[profile](random.Random(20261024)))
    return path


def _series(path: Path):
    source = MavlinkSource(path)
    return list(group_into_series(source.observations(), min_observations=1)), source


def _analyse(tmp: Path, profile: str, baseline):
    series, _ = _series(_pcap(tmp, profile))
    ctx = Context(now=max(s.end or 0.0 for s in series), baseline=baseline)
    return run(series, ONTOLOGIES, ctx)


def _trained(tmp: Path) -> SqliteBaseline:
    baseline = SqliteBaseline(tmp / "uav.db")
    _analyse(tmp, "normal", baseline)
    return baseline


def _rules(findings):
    return {f.rule_id for f in findings}


def _messages(series):
    return [o for s in series for o in s]


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------


def test_parses_v1_and_v2():
    v1 = mavlink_v1(1, 1, 0, heartbeat(), 7)
    v2 = mavlink_v2(1, 1, 0, heartbeat(), 8)

    one = parse_frames(v1)
    assert len(one) == 1
    assert one[0].version == 1 and one[0].message_id == 0
    assert one[0].system_id == 1 and one[0].sequence == 7
    assert one[0].length == len(v1)

    two = parse_frames(v2)
    assert len(two) == 1
    assert two[0].version == 2 and two[0].message_id == 0
    assert two[0].sequence == 8
    assert two[0].length == len(v2)


def test_several_frames_in_one_datagram():
    """A UDP datagram may carry a burst of messages, so the parser scans
    rather than assuming one frame per packet."""
    blob = (
        mavlink_v2(1, 1, 0, heartbeat(), 1)
        + mavlink_v2(1, 1, 33, global_position(HOME_LAT, HOME_LON, 10.0, 0), 2)
        + mavlink_v1(255, 190, 0, heartbeat(armed=False), 3)
    )
    frames = parse_frames(blob)
    assert [f.message_id for f in frames] == [0, 33, 0]
    assert [f.version for f in frames] == [2, 2, 1]


def test_resynchronises_after_garbage():
    """A lossy link leaves partial frames; a receiver skips to the next magic
    byte rather than giving up on the datagram."""
    blob = b"\x11\x22\x33" + mavlink_v2(1, 1, 0, heartbeat(), 4)
    frames = parse_frames(blob)
    assert len(frames) == 1 and frames[0].message_id == 0


def test_truncated_frame_is_dropped_not_guessed():
    full = mavlink_v2(1, 1, 33, global_position(HOME_LAT, HOME_LON, 10.0, 0), 5)
    assert parse_frames(full[:-4]) == []


def test_signed_v2_frames_are_recognised():
    signed = mavlink_v2(1, 1, 0, heartbeat(), 6, signed=True)
    frames = parse_frames(signed)
    assert len(frames) == 1
    assert frames[0].signed is True
    # The 13-octet signature must be accounted for in the frame length, or
    # the next frame in the datagram would start mid-signature.
    assert frames[0].length == len(signed)

    pair = signed + mavlink_v2(1, 1, 0, heartbeat(), 7)
    assert len(parse_frames(pair)) == 2


# --------------------------------------------------------------------------
# payload decoding
# --------------------------------------------------------------------------


def test_wire_order_is_size_descending():
    """MAVLink sorts fields by type size, largest first — NOT declaration
    order. Decoding in declaration order produces plausible nonsense rather
    than an error, so this asserts against values that could not survive a
    misparse.
    """
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "normal"))
        messages = _messages(series)

        # COMMAND_LONG wire order is param1..7, command, target, component,
        # confirmation. HEARTBEAT is custom_mode first, then the five u8s.
        beats = [o for o in messages if o.attrs["msgid"] == "0"]
        assert beats
        vehicle = next(o for o in beats if o.attrs["sysid"] == str(SYS_VEHICLE))
        assert vehicle.attrs["vehicle_type"] == "2"
        assert vehicle.attrs["autopilot"] == "3"
        assert vehicle.attrs["armed"] == "1"
        assert vehicle.attrs["custom_mode"] == "4"

        positions = [o for o in messages if o.attrs["msgid"] == "33"]
        assert positions
        first = positions[0]
        # Latitude must land near the fixture's home, not in the Pacific.
        assert abs(float(first.attrs["lat"]) - HOME_LAT) < 0.01
        assert abs(float(first.attrs["lon"]) - HOME_LON) < 0.01
        assert abs(float(first.attrs["alt_m"]) - 45.0) < 0.5
        assert float(first.attrs["ground_speed_m_s"]) > 0


def test_command_long_decodes_its_command():
    frame = command_long(400, param1=0.0)
    blob = mavlink_v2(SYS_ATTACKER, 190, 76, frame, 1)
    parsed = parse_frames(blob)[0]
    assert parsed.message_id == 76

    from capture.mavlink import _command_long

    decoded = _command_long(parsed.payload)
    assert decoded["command"] == "400"
    assert decoded["command_name"] == "COMPONENT_ARM_DISARM"
    assert decoded["arm_action"] == "DISARM"
    assert decoded["target_system"] == str(SYS_VEHICLE)

    # ...and param1 = 1 is an arm, not a disarm.
    armed = _command_long(parse_frames(
        mavlink_v2(SYS_ATTACKER, 190, 76, command_long(400, param1=1.0), 2)
    )[0].payload)
    assert armed["arm_action"] == "arm"


def test_param_set_decodes_its_name():
    blob = mavlink_v2(SYS_ATTACKER, 190, 23, param_set("SYSID_MYGCS", 42.0), 1)
    from capture.mavlink import _param_set

    decoded = _param_set(parse_frames(blob)[0].payload)
    assert decoded["param_id"] == "SYSID_MYGCS"
    assert decoded["param_value"] == "42"


# --------------------------------------------------------------------------
# geography
# --------------------------------------------------------------------------


def test_haversine_is_metres_not_degrees():
    """Degrees of longitude shrink toward the poles, so a degree-based
    distance would make the same jump look larger at high latitude."""
    # One degree of latitude is about 111 km anywhere.
    assert 110_000 < haversine_m(0, 0, 1, 0) < 112_000
    assert 110_000 < haversine_m(64, 0, 65, 0) < 112_000
    # One degree of longitude is ~111 km at the equator, ~49 km at 64N.
    equator = haversine_m(0, 0, 0, 1)
    arctic = haversine_m(64, 0, 64, 1)
    assert equator > 2 * arctic
    assert haversine_m(1.5, 2.5, 1.5, 2.5) == 0.0


def test_position_jump_is_computed_against_the_previous_fix():
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "spoof"))
        jumps = [
            float(o.attrs["jump_speed_m_s"])
            for o in _messages(series) if "jump_speed_m_s" in o.attrs
        ]
        assert jumps, "no discontinuities computed"
        # Normal flight is ~5 m/s; the planted jump is thousands.
        assert max(jumps) > 1000
        assert sorted(jumps)[len(jumps) // 2] < 50


def test_first_fix_has_no_jump():
    """There is nothing to compare the first position against, so no
    discontinuity may be reported for it."""
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "normal"))
        positions = [o for o in _messages(series) if o.attrs["msgid"] == "33"]
        assert positions
        assert "jump_m" not in positions[0].attrs
        assert all("jump_m" in o.attrs for o in positions[1:])


# --------------------------------------------------------------------------
# the architectural claim
# --------------------------------------------------------------------------


def test_native_parser_needs_no_tshark():
    """The capture contract's other half. Modbus and DNP3 are tshark field
    lists; this domain is a native parser, and nothing above `capture/`
    knows which it got."""
    import capture.mavlink as module

    source = inspect_source = module.MavlinkSource
    assert "tshark" not in module.__dict__
    assert not hasattr(source, "command")      # not a TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, evidences = _analyse(tmp, "hijack", baseline)
        assert findings, "the native path produced no findings"
        assert evidences


def test_domain_added_no_new_primitive():
    assert {p.name for p in stack_for("mavlink")} == {
        "periodicity", "burstiness", "rarity", "fanout.msgid",
    }
    assert {i.name for i in inspectors_for("mavlink")} == {
        "uav.mavlink_command", "uav.position_jump", "uav.unsigned_link",
    }


def test_message_id_is_an_attribute_not_a_dim():
    """Fifth domain, same lesson: a value in `dims` cannot be counted."""
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "normal"))
        for one in series:
            assert one.channel.dims == {"proto": "mavlink"}
        # And identity is the SYSTEM id, not the IP — an injected command may
        # arrive from any address, but it must claim a system id.
        assert all(
            s.channel.initiator.kind == "mavlink_sysid" for s in series
        )


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


def test_normal_flight_is_silent():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "normal", baseline)
        assert not findings, [f.rule_id for f in findings]


def test_injected_disarm_is_critical():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "hijack", baseline)

        disarm = next(
            (f for f in findings
             if f.rule_id == "mavlink.command.disarm_injected"), None
        )
        assert disarm is not None, _rules(findings)
        assert disarm.severity.value == "critical"
        assert disarm.channel.initiator.value == f"{SYS_ATTACKER}.190"

        facts = disarm.evidence.by_name("uav.mavlink_command.disarm").facts
        assert facts["arm_action"] == "DISARM"
        assert facts["command"] == "COMPONENT_ARM_DISARM"


def test_ground_station_takeover_is_critical():
    """Rewriting SYSID_MYGCS is how an injected link makes itself the
    operator, and it persists for the rest of the flight."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "hijack", baseline)

        takeover = next(
            (f for f in findings
             if f.rule_id == "mavlink.command.takeover_injected"), None
        )
        assert takeover is not None, _rules(findings)
        facts = takeover.evidence.by_name("uav.mavlink_command.takeover").facts
        assert facts["param_id"] == "SYSID_MYGCS"
        assert "ground station" in facts["effect"]


def test_categories_fold_separately():
    """The hijack capture carries a disarm, a takeover, a mode change and a
    land command on ONE channel. Under a single inspector name, folding
    would keep only the highest-scoring and silently disable the rest — the
    defect found in DNP3."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "hijack", baseline)
        rules = _rules(findings)
        assert "mavlink.command.disarm_injected" in rules
        assert "mavlink.command.takeover_injected" in rules
        assert "mavlink.command.mode_change_injected" in rules


def test_position_discontinuity_is_reported_unproven():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "spoof", baseline)

        jump = next(
            (f for f in findings
             if f.rule_id == "mavlink.integrity.position_discontinuity"), None
        )
        assert jump is not None, _rules(findings)
        # HIGH, not CRITICAL: a capture gap produces the same shape.
        assert jump.severity.value == "high"

        facts = jump.evidence.by_name("uav.position_jump").facts
        assert float(facts["implied_speed_m_s"]) > 1000
        assert float(facts["jump_m"]) > 1000
        notes = " ".join(jump.evidence.by_name("uav.position_jump").notes)
        assert "capture gap" in notes
        assert "ground speed" in notes


def test_plausible_flight_speed_is_not_a_discontinuity():
    """A fast fixed-wing must not trip the physics check. The threshold is
    an implied speed, so the test varies the interval rather than the
    distance."""
    from core.model import Channel, Direction, Entity, Locus, Observation
    from inspectors.uav import MavlinkPositionJump

    channel = Channel(domain="mavlink", dims={"proto": "mavlink"},
                      initiator=Entity("mavlink_sysid", "1.1"),
                      responder=Entity("ip", "10.40.0.10"))
    ctx = Context(now=0.0)

    def judge(jump_m: float, gap_s: float):
        obs = Observation(
            ts=0.0, channel=channel, direction=Direction.EGRESS, size=40,
            kind="mavlink_message",
            attrs={
                "msgid": "33", "sysid": "1",
                "jump_m": f"{jump_m}",
                "since_last_fix_s": f"{gap_s}",
                "jump_speed_m_s": f"{jump_m / gap_s}",
            },
            locus=Locus("m.pcap", frames=(1,)),
        )
        return MavlinkPositionJump().run(obs, ctx)

    # 100 m in 0.2 s is 500 m/s — impossible.
    assert judge(100.0, 0.2) is not None
    # The same 100 m over 10 s is 10 m/s — an ordinary multirotor.
    assert judge(100.0, 10.0) is None
    # 50 m/s is a fast fixed-wing and must stay silent.
    assert judge(500.0, 10.0) is None


def test_unsigned_link_is_context_not_a_finding():
    """Unsigned MAVLink is the default almost everywhere. It is recorded so a
    command finding can say the link had no way to reject the sender, and it
    must never produce a report line of its own."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, evidences = _analyse(tmp, "normal", baseline)
        recorded = any(
            i.name == "uav.unsigned_link" for e in evidences for i in e.inspections
        )
        assert recorded, "the unsigned link was not recorded at all"
        assert not any("unsigned" in f.rule_id for f in findings)


def test_established_ground_station_is_not_flagged():
    """The gate works both ways: once the attacker's system id is known, its
    commands are inventory rather than injection."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = SqliteBaseline(tmp / "uav.db")
        _analyse(tmp, "hijack", baseline)        # the attacker is now known
        findings, _ = _analyse(tmp, "hijack", baseline)
        assert "mavlink.command.disarm_injected" not in _rules(findings)


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
