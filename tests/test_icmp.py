"""ICMP: echo as a measurable channel, errors as diagnosis.

ICMP was dropped on the floor entirely — `_handle_frame` handled TCP and UDP
and returned nothing for anything else — so a capture full of "host
unreachable" told the reader nothing. That mattered most right after the tool
started reporting TCP connection outcomes: "4 connections never answered" is a
symptom, and the ICMP error is the diagnosis sitting in the same capture.

The two halves are handled differently on purpose, and the tests assert the
distinction:

  ECHO becomes an Observation, because it is a conversation with a cadence.
  ICMP echo is a real covert channel, so a periodic exchange holding one
  identifier is something the timing primitives must be able to reach.

  ERRORS become capture-level facts, because an error is not a conversation
  with the router that sent it — it is an explanation of a conversation with
  somebody else. `test_error_names_the_destination_it_is_about` is the
  load-bearing one: the value is in the QUOTED packet, which names the
  address and port that failed rather than only the router that complained.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.decode import PROTO_ICMP, PROTO_ICMPV6, decode_icmp
from capture.pcap import PcapSource
from capture.pcapfile import LINKTYPE_ETHERNET
from out.narrate import _connections, narrate


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    ) + payload


def icmp_echo(kind: int, echo_id: int, seq: int, data: bytes = b"") -> bytes:
    return struct.pack(">BBHHH", kind, 0, 0, echo_id, seq) + data


def icmp_error(kind: int, code: int, quoted: bytes) -> bytes:
    """An ICMP error, carrying the packet that caused it."""
    return struct.pack(">BBHI", kind, code, 0, 0) + quoted


def quoted_tcp(src: str, dst: str, sport: int, dport: int) -> bytes:
    """An IPv4 header plus the first 8 transport bytes, as RFC 792 quotes."""
    transport = struct.pack(">HHI", sport, dport, 0)
    return ipv4(src, dst, 6, transport)


def frame(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    return (b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00"
            + ipv4(src, dst, proto, payload))


def write_pcap(path: Path, frames) -> None:
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, LINKTYPE_ETHERNET))
        for index, data in enumerate(frames):
            handle.write(struct.pack("<IIII", 1_700_000_000 + index, 0,
                                     len(data), len(data)))
            handle.write(data)


def capture(frames):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "icmp.pcap"
        write_pcap(path, frames)
        source = PcapSource(path)
        return list(source.observations()), source.stats


# --------------------------------------------------------------------------
# decoding
# --------------------------------------------------------------------------


def test_echo_request_and_reply_are_named():
    request = decode_icmp(PROTO_ICMP, icmp_echo(8, 0x1234, 1))
    reply = decode_icmp(PROTO_ICMP, icmp_echo(0, 0x1234, 1))

    assert request.name == "echo request", request
    assert reply.name == "echo reply", reply
    assert not request.is_error
    assert request.echo_id == 0x1234
    assert request.echo_seq == 1


def test_unreachable_codes_are_distinguished():
    """"host unreachable" and "administratively prohibited" are different
    facts: one is a routing failure, the other is a deliberate filter."""
    cases = {
        (3, 1): "host unreachable",
        (3, 3): "port unreachable",
        (3, 13): "communication administratively prohibited",
        (11, 0): "TTL exceeded in transit",
    }
    for (kind, code), expected in cases.items():
        message = decode_icmp(PROTO_ICMP, icmp_error(kind, code, b"\x00" * 28))
        assert message.name == expected, (kind, code, message.name)
        assert message.is_error, message


def test_error_names_the_destination_it_is_about():
    """THE LOAD-BEARING CASE. The value of an error is the quoted packet: it
    names the address and port that failed, not the router that complained."""
    quoted = quoted_tcp("10.0.0.5", "203.0.113.9", 44444, 443)
    message = decode_icmp(PROTO_ICMP, icmp_error(3, 13, quoted))

    assert message.quoted_dst == "203.0.113.9", message
    assert message.quoted_dport == 443, message
    assert message.quoted_proto == 6, message


def test_icmpv6_names_and_quoting():
    body = struct.pack(">IHBB", 0, 8, 6, 64) + b"\x00" * 8 + b"\x00" * 16
    # IPv6 header: 40 bytes, destination at offset 24.
    header = (b"\x60\x00\x00\x00" + struct.pack(">HBB", 8, 6, 64)
              + b"\x20\x01" + b"\x00" * 14          # source
              + b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01")  # dest
    transport = struct.pack(">HHI", 1234, 8443, 0)
    message = decode_icmp(PROTO_ICMPV6, icmp_error(1, 1, header + transport))

    assert message.name == "administratively prohibited", message
    assert message.quoted_dport == 8443, message
    assert message.quoted_dst is not None and ":" in message.quoted_dst

    echo = decode_icmp(PROTO_ICMPV6, icmp_echo(128, 7, 2))
    assert echo.name == "echo request", echo
    assert not echo.is_error


def test_unknown_type_is_reported_numerically_not_dropped():
    message = decode_icmp(PROTO_ICMP, icmp_echo(99, 0, 0))
    assert message is not None
    assert message.name == "type 99 code 0", message.name


def test_truncated_and_malformed_icmp_decline():
    assert decode_icmp(PROTO_ICMP, b"") is None
    assert decode_icmp(PROTO_ICMP, b"\x08\x00\x00") is None
    # An error whose quoted packet is truncated still decodes, but declines
    # to invent a destination.
    message = decode_icmp(PROTO_ICMP, icmp_error(3, 1, b"\x45\x00"))
    assert message is not None
    assert message.quoted_dst is None, message


# --------------------------------------------------------------------------
# observations and stats
# --------------------------------------------------------------------------


def test_echo_becomes_a_measurable_channel():
    """A periodic ICMP exchange must be reachable by the timing primitives —
    ICMP echo is a real covert channel."""
    frames = [
        frame("10.0.0.5", "203.0.113.9", PROTO_ICMP,
              icmp_echo(8, 0x1234, seq, b"x" * 32))
        for seq in range(8)
    ]
    observations, stats = capture(frames)

    icmp = [o for o in observations if o.channel.domain == "icmp"]
    assert len(icmp) == 8, [o.channel.domain for o in observations]
    assert stats["icmp"] == 8, stats
    assert icmp[0].channel.dims["type"] == "echo request"
    assert icmp[0].attrs["echo_id"] == "4660"
    assert icmp[0].size == 32, icmp[0].size


def test_request_and_reply_are_separate_channels():
    """One interleaved series of requests and replies has meaningless
    intervals; each direction has its own cadence."""
    frames = []
    for seq in range(4):
        frames.append(frame("10.0.0.5", "203.0.113.9", PROTO_ICMP,
                            icmp_echo(8, 1, seq)))
        frames.append(frame("203.0.113.9", "10.0.0.5", PROTO_ICMP,
                            icmp_echo(0, 1, seq)))
    observations, _stats = capture(frames)

    types = {o.channel.dims["type"] for o in observations
             if o.channel.domain == "icmp"}
    assert types == {"echo request", "echo reply"}, types


def test_errors_are_grouped_not_listed_per_packet():
    """Forty identical "port unreachable" for one address is one fact about
    that address, not forty facts."""
    quoted = quoted_tcp("10.0.0.5", "203.0.113.9", 44444, 443)
    frames = [
        frame("10.0.0.1", "10.0.0.5", PROTO_ICMP, icmp_error(3, 13, quoted))
        for _ in range(40)
    ]
    observations, stats = capture(frames)

    # An error is not a conversation, so it produces no observation.
    assert not [o for o in observations if o.channel.domain == "icmp"]

    errors = stats["icmp_errors"]
    assert errors["total"] == 40, errors
    assert len(errors["groups"]) == 1, errors["groups"]
    group = errors["groups"][0]
    assert group["count"] == 40
    assert group["about"] == "203.0.113.9"
    assert group["dport"] == 443
    assert group["reporters"] == ["10.0.0.1"]


def test_different_reasons_stay_separate():
    quoted = quoted_tcp("10.0.0.5", "203.0.113.9", 1, 443)
    frames = [
        frame("10.0.0.1", "10.0.0.5", PROTO_ICMP, icmp_error(3, 1, quoted)),
        frame("10.0.0.1", "10.0.0.5", PROTO_ICMP, icmp_error(3, 13, quoted)),
    ]
    _observations, stats = capture(frames)
    reasons = {g["reason"] for g in stats["icmp_errors"]["groups"]}
    assert reasons == {"host unreachable",
                       "communication administratively prohibited"}, reasons


# --------------------------------------------------------------------------
# narration
# --------------------------------------------------------------------------


def test_errors_are_narrated_beside_the_connections_they_explain():
    stats = {
        "connections": {
            "counts": {"closed": 90, "unanswered": 4},
            "failed": {"unanswered": {"203.0.113.9": 4}},
            "flows": 94,
        },
        "icmp_errors": {
            "total": 4,
            "groups": [{
                "about": "203.0.113.9", "dport": 443,
                "reason": "communication administratively prohibited",
                "reporters": ["10.0.0.1"], "count": 4, "first_frame": 10,
            }],
        },
    }
    text = "\n".join(_connections(stats, {"203.0.113.9": "shop.test"}, 12))

    assert "4 ICMP error(s) received" in text, text
    assert "203.0.113.9:443" in text, text
    assert "shop.test" in text, text
    assert "administratively prohibited" in text, text
    assert "reported by 10.0.0.1" in text, text
    # Both the symptom and the diagnosis, in one section.
    assert "never answered" in text, text


def test_icmp_only_capture_still_reports_its_errors():
    """Gating the section on TCP flows hid every error in a capture that had
    no TCP at all — where the errors are the entire story."""
    stats = {
        "icmp_errors": {
            "total": 2,
            "groups": [{
                "about": "198.51.100.7", "dport": None,
                "reason": "host unreachable",
                "reporters": ["10.0.0.1"], "count": 2, "first_frame": 3,
            }],
        },
    }
    lines = _connections(stats, {}, 12)
    assert lines, "section suppressed with no TCP flows"
    text = "\n".join(lines)
    assert "198.51.100.7" in text, text
    assert "host unreachable" in text, text


def test_interpretation_states_the_reason_not_only_the_count():
    stats = {
        "icmp_errors": {
            "total": 6,
            "groups": [
                {"about": "a", "dport": 80, "reason": "host unreachable",
                 "reporters": ["r"], "count": 4, "first_frame": 1},
                {"about": "b", "dport": 443,
                 "reason": "communication administratively prohibited",
                 "reporters": ["r"], "count": 2, "first_frame": 2},
            ],
        },
    }
    flat = " ".join(narrate([], [], stats=stats, source_name="t.pcap").split())
    assert "returned 6 ICMP error(s)" in flat, flat
    assert "host unreachable (4)" in flat, flat
    assert "2 destinations" in flat, flat
    assert "filtered and one that simply went unanswered" in flat, flat


def test_no_icmp_means_no_icmp_output():
    """A section claiming zero errors is a statement about data that does
    not exist."""
    assert _connections({}, {}, 12) == []
    flat = narrate([], [], stats={"icmp_errors": {"total": 0, "groups": []}},
                   source_name="t.pcap")
    assert "ICMP" not in flat, flat


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name_, fn in tests:
        try:
            fn()
            print(f"  ok    {name_}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name_}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
