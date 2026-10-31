"""Live capture, and the loopback bug it exposed.

THE REGRESSION TEST HERE IS THE POINT OF THE FILE.
`test_self_to_self_directions_use_port_not_just_address` guards a defect that
only live capture on `lo` could surface: direction was inferred by comparing
IP addresses, and when a host talks to itself both ends share an address. So
every packet read as outbound, the SYN-ACK was never recognised, and the
first live capture reported "8 of 8 TCP connections did not establish" in
the same report that showed eight HTTP requests plainly succeeding.

It was never loopback-only. Any host reaching a service on itself — a
sidecar, a local proxy, a database on 127.0.0.1 — hit it, and in a file
capture it would have looked like a broken network rather than a broken
parser.

No test here opens an interface. Capturing in a test suite needs privilege
and a cooperating network, and would be flaky for reasons unrelated to the
code; the capture program is checked by inspecting the command it would run,
and the frame path is driven from a pipe and from synthetic pcaps.
"""

from __future__ import annotations

import io
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.live import (
    CaptureUnavailable,
    LiveSource,
    available_tools,
    list_interfaces,
    preflight,
)
from capture.pcap import PcapSource
from capture.pcapfile import LINKTYPE_ETHERNET, read_stream
from core.model import Direction


# --------------------------------------------------------------------------
# frame builders
# --------------------------------------------------------------------------


def tcp_frame(src, dst, sport, dport, flags, payload=b"") -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                      1024, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     bytes(int(o) for o in src.split(".")),
                     bytes(int(o) for o in dst.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + tcp


def pcap_bytes(frames) -> bytes:
    out = io.BytesIO()
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                          LINKTYPE_ETHERNET))
    for index, frame in enumerate(frames):
        out.write(struct.pack("<IIII", 1_700_000_000 + index, index * 1000,
                              len(frame), len(frame)))
        out.write(frame)
    return out.getvalue()


def write_pcap(path: Path, frames) -> None:
    path.write_bytes(pcap_bytes(frames))


# --------------------------------------------------------------------------
# the loopback regression
# --------------------------------------------------------------------------


SYN, SYNACK, ACK, FIN_ACK = 0x02, 0x12, 0x10, 0x11


def _loopback_session():
    """A complete client/server exchange where both ends are 127.0.0.1."""
    client, server = "127.0.0.1", "127.0.0.1"
    cport, sport = 54321, 18080
    return [
        tcp_frame(client, server, cport, sport, SYN),
        tcp_frame(server, client, sport, cport, SYNACK),
        tcp_frame(client, server, cport, sport, ACK),
        tcp_frame(client, server, cport, sport, 0x18,
                  b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        tcp_frame(server, client, sport, cport, 0x18,
                  b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhiya"),
        tcp_frame(client, server, cport, sport, FIN_ACK),
        tcp_frame(server, client, sport, cport, FIN_ACK),
    ]


def test_self_to_self_directions_use_port_not_just_address():
    """REGRESSION. Comparing only the address makes every packet outbound
    when a host talks to itself: the SYN-ACK is missed, the connection
    reports "unanswered", and the response bytes are counted as egress."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "lo.pcap"
        write_pcap(path, _loopback_session())
        source = PcapSource(path)
        observations = list(source.observations())
        outcomes = source.stats["connections"]

    assert outcomes["counts"].get("closed") == 1, outcomes
    assert not outcomes["counts"].get("unanswered"), outcomes
    assert not outcomes["counts"].get("refused"), outcomes

    # Both directions must be represented, not just one.
    directions = {o.direction for o in observations}
    assert directions == {Direction.EGRESS, Direction.INGRESS}, directions


def test_self_to_self_byte_counts_split_by_direction():
    """The same bug attributed every response byte to egress, which made a
    download look like an upload."""
    from capture.base import group_into_series

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "lo.pcap"
        write_pcap(path, _loopback_session())
        observations = list(PcapSource(path).observations())

    series = list(group_into_series(observations, min_observations=1))
    net = [s for s in series if s.channel.domain == "net"]
    assert net, [s.channel.domain for s in series]
    one = net[0]
    assert one.bytes_egress > 0, one.bytes_egress
    assert one.bytes_ingress > 0, one.bytes_ingress


def test_distinct_hosts_are_unaffected():
    """The guard against fixing loopback by breaking everything else."""
    frames = [
        tcp_frame("10.0.0.5", "203.0.113.9", 1111, 443, SYN),
        tcp_frame("203.0.113.9", "10.0.0.5", 443, 1111, SYNACK),
        tcp_frame("10.0.0.5", "203.0.113.9", 1111, 443, 0x18, b"hello"),
        tcp_frame("203.0.113.9", "10.0.0.5", 443, 1111, 0x18, b"world!!"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pair.pcap"
        write_pcap(path, frames)
        source = PcapSource(path)
        observations = list(source.observations())

    assert source.stats["connections"]["counts"].get("open") == 1
    assert {o.direction for o in observations} == {
        Direction.EGRESS, Direction.INGRESS
    }


# --------------------------------------------------------------------------
# streaming a capture off a pipe
# --------------------------------------------------------------------------


def test_frames_can_be_read_from_a_pipe():
    """`read_frames` rewinds with seek(0) after sniffing the magic, which a
    pipe cannot do. Live capture arrives down a pipe, so the format has to
    be identified without consuming or rewinding."""
    data = pcap_bytes(_loopback_session())
    process = subprocess.Popen(["cat"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE)
    process.stdin.write(data)
    process.stdin.close()
    frames = list(read_stream(process.stdout))
    process.wait(timeout=10)

    assert len(frames) == 7, len(frames)
    numbers = [f[0] for f in frames]
    assert numbers == list(range(1, 8)), numbers


def test_live_source_reuses_every_parser():
    """LiveSource overrides only where frames come from. If it stopped
    subclassing PcapSource there would be two implementations to drift —
    and the live path would interpret a capture differently from the file
    it could have been saved to."""
    assert issubclass(LiveSource, PcapSource)

    source = LiveSource("lo")
    for method in ("_handle_tcp", "_handle_udp", "_handle_icmp",
                   "connection_outcomes", "icmp_errors"):
        assert getattr(type(source), method, None) is getattr(
            PcapSource, method, None
        ), f"{method} was overridden; it should be inherited"


class _ScriptedLive(LiveSource):
    """A LiveSource whose frames come from a list rather than an interface."""

    def __init__(self, frames, **kwargs):
        super().__init__("lo", **kwargs)
        self._frames = frames

    def _raw_frames(self):
        # Overrides the RAW source, not `frames`, so the stop conditions in
        # `frames` still apply — which is the arrangement that makes
        # --frames and --duration work for any source.
        for index, frame in enumerate(self._frames, start=1):
            yield index, 1_700_000_000.0 + index * 0.01, LINKTYPE_ETHERNET, frame


def test_live_path_produces_the_same_observations_as_a_file():
    """The equivalence that makes replaying a file a valid test of live
    behaviour. Same frames in, same observations out."""
    from capture.base import group_into_series

    frames = _loopback_session()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "lo.pcap"
        write_pcap(path, frames)
        from_file = list(PcapSource(path).observations())

    from_live = list(_ScriptedLive(frames).observations())

    assert len(from_file) == len(from_live), (len(from_file), len(from_live))
    assert ([(o.kind, o.direction, o.size) for o in from_file]
            == [(o.kind, o.direction, o.size) for o in from_live])

    # And the http content survives the live path too.
    live_series = list(group_into_series(from_live, min_observations=1))
    assert any(s.channel.domain == "http" for s in live_series), [
        s.channel.domain for s in live_series
    ]


def test_frame_limit_stops_the_capture():
    source = _ScriptedLive(_loopback_session() * 10, max_frames=5)
    list(source.observations())
    assert "reached --frames 5" in source.stopped_because, \
        source.stopped_because


# --------------------------------------------------------------------------
# the capture program, and refusing to guess
# --------------------------------------------------------------------------


def test_dumpcap_command_writes_a_pcap_stream_to_stdout():
    source = LiveSource("lo", bpf="tcp port 80", duration=30, tool="dumpcap")
    command = source._command()

    assert command[0] == "dumpcap"
    assert "-i" in command and "lo" in command
    # -w - is the pipe; -P forces classic pcap, which the reader handles
    # without needing pcapng block parsing on a stream.
    assert command[command.index("-w") + 1] == "-"
    assert "-P" in command
    assert "tcp port 80" in command
    # dumpcap owns the clock too: an internal timer would not fire while
    # this process is blocked reading from a quiet interface.
    assert "duration:30" in " ".join(command)


def test_tcpdump_is_an_alternative_not_a_rewrite():
    source = LiveSource("lo", bpf="udp", tool="tcpdump")
    command = source._command()
    assert command[0] == "tcpdump"
    assert command[command.index("-w") + 1] == "-"
    # -U flushes per packet; without it tcpdump buffers and a live report
    # lags behind the traffic by a block.
    assert "-U" in command
    assert "udp" in command


def test_unknown_interface_is_refused_with_the_list():
    """Naming a bad interface otherwise surfaces as a subprocess failure
    several seconds later, by which point the cause is buried."""
    interfaces = list_interfaces()
    if not interfaces:
        return
    try:
        preflight("definitely-not-an-interface")
    except CaptureUnavailable as error:
        assert "no interface named" in str(error), error
        assert interfaces[0] in str(error), error
    else:
        raise AssertionError("bad interface accepted")


def test_a_real_interface_passes_preflight():
    interfaces = list_interfaces()
    if "lo" not in interfaces:
        return
    preflight("lo")   # must not raise


def test_missing_capture_program_explains_the_fix():
    source = LiveSource("lo", tool=None)
    if available_tools():
        return          # cannot exercise the failure on this machine
    try:
        source._command()
    except CaptureUnavailable as error:
        assert "does not capture directly" in str(error), error
    else:
        raise AssertionError("missing tool accepted")


def test_the_tool_does_not_need_root():
    """The privilege boundary is a pipe. This process never asks for
    CAP_NET_RAW — dumpcap holds it, which is what it is written for."""
    import inspect

    import capture.live as live

    text = inspect.getsource(live)
    # No raw sockets, no setuid, no privilege escalation anywhere.
    for forbidden in ("AF_PACKET", "SOCK_RAW", "setuid", "sudo", "pkexec"):
        assert forbidden not in text, forbidden


def test_process_isolation_is_platform_correct():
    """start_new_session is a POSIX setsid; Windows has no such call and uses
    a creation flag. Picking the wrong one leaves the capture child with no
    process-group isolation, so Ctrl-C would race it."""
    import os as _os
    from capture.live import LiveSource

    saved = _os.name
    try:
        _os.name = "posix"
        assert LiveSource._isolation_kwargs() == {"start_new_session": True}
        _os.name = "nt"
        kwargs = LiveSource._isolation_kwargs()
        assert "creationflags" in kwargs and "start_new_session" not in kwargs
    finally:
        _os.name = saved


def test_windows_gets_an_npcap_message_and_no_posix_calls():
    """On Windows the missing-tool guidance names Npcap, and the permission
    check must not reach for grp/geteuid, which do not exist there."""
    import os as _os
    import capture.live as live

    saved = _os.name
    try:
        _os.name = "nt"
        assert "Npcap" in live._no_tool_message()
        # Must not raise despite grp/geteuid being POSIX-only; the nt branch
        # never touches them. (geteuid exists on this Linux host, so the only
        # way this crashes on real Windows is reaching the posix block.)
        live._permission_note()
    finally:
        _os.name = saved
    # the POSIX message still reads as before, so the Linux test above holds
    _os.name = "posix" if hasattr(_os, "geteuid") else saved
    try:
        assert "does not run as root" in live._no_tool_message()
    finally:
        _os.name = saved


def test_a_numeric_interface_index_is_never_rejected():
    """dumpcap/tcpdump accept a bare index, which is the usual way to name an
    interface on Windows — preflight must not reject it even when it is not in
    the parsed name list."""
    from capture.live import preflight
    try:
        preflight("999999")   # not a real index, but a digit — not rejected
    except CaptureUnavailable as error:
        # only acceptable failure here is "no capture program", never
        # "no interface named"
        assert "no interface named" not in str(error), error


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
