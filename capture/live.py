"""Live capture from an interface, via dumpcap.

THE TOOL NEVER NEEDS ROOT, and that is the central design decision rather
than a convenience. Capturing packets requires CAP_NET_RAW; this process
does not take it. Instead it runs `dumpcap`, which ships with that
capability already granted and whose entire job is to hold it safely — it
is a few thousand lines written to be run privileged, as against this
codebase, which is tens of thousands written on the assumption that it is
not. Running an analyser as root so it can also parse adversarial input is
the wrong way round.

So the privilege boundary sits at a pipe: dumpcap reads the interface and
writes a pcap stream to stdout, and everything here is ordinary user code
reading bytes. The same arrangement works unchanged with `tcpdump`, or with
the operator running dumpcap themselves and piping it in.

LIVE CAPTURE IS LEGALLY DIFFERENT FROM READING A FILE, which is why this
module asks for an interface explicitly and will not guess one. A loopback
capture sees only this machine talking to itself. A capture on a physical
interface sees whatever that segment carries, which on a shared network
reaches other people's communications and is governed by different rules in
most jurisdictions. The tool cannot judge authorisation; it can refuse to
make the choice silently, so the interface is always named by the operator.

EVERY PARSER IS REUSED. `LiveSource` subclasses `PcapSource` and overrides
only where frames come from, so TCP flow tracking, TLS record shape,
certificates, native HTTP, DNS, ICMP and connection outcomes all behave
identically live and from a file. There is no second implementation to drift.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Iterator, List, Optional, Sequence, Tuple

from capture.pcap import PcapSource
from capture.pcapfile import read_stream

__all__ = ["LiveSource", "CaptureUnavailable", "available_tools",
           "list_interfaces"]


class CaptureUnavailable(RuntimeError):
    """No usable capture program, or it refused. Carries the fix."""


#: Preference order. dumpcap first because it is the one designed to hold
#: the capability: it drops privileges, has no dissectors, and writes a
#: stream and nothing else.
_TOOLS = ("dumpcap", "tcpdump")


def available_tools() -> List[str]:
    return [name for name in _TOOLS if shutil.which(name)]


def list_interfaces() -> List[str]:
    """Interfaces the system reports, for an error message that helps.

    `/sys/class/net` is the fast, clean source and is used where it exists
    (Linux). Elsewhere — Windows, macOS — there is no such directory, so the
    capture tool's own `-D` listing is parsed instead, which also gives a
    Windows user the device names dumpcap expects.
    """
    try:
        names = sorted(os.listdir("/sys/class/net"))
        if names:
            return names
    except OSError:
        pass
    return _interfaces_via_tool()


def _interfaces_via_tool() -> List[str]:
    """Interface names from `dumpcap -D` / `tcpdump -D`, best-effort.

    Used only to make an error message helpful, never to hard-reject, so a
    parse that misses a device simply yields a shorter hint rather than a
    false "no such interface".
    """
    tool = (available_tools() or [None])[0]
    if tool is None:
        return []
    try:
        result = subprocess.run([tool, "-D"], capture_output=True,
                                text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    names = []
    for line in result.stdout.splitlines():
        # dumpcap: "1. eth0" / "1. \Device\NPF_{...} (Ethernet)"
        # tcpdump: "1.eth0 [Up, Running]"
        match = re.match(r"\s*\d+[.)]?\s*(\S+)", line)
        if match:
            names.append(match.group(1))
    return names


class LiveSource(PcapSource):
    """Observations from a live interface.

    `duration` and `max_frames` both exist because a live capture otherwise
    never ends, and an analysis that never produces output is not an
    analysis. Either bound is enough; with neither, it runs until
    interrupted and reports what it saw.
    """

    def __init__(
        self,
        iface: str,
        burst_gap_s: float = 0.050,
        retain_payloads: bool = False,
        parse_http: bool = True,
        bpf: str = "",
        snaplen: int = 262_144,
        duration: Optional[float] = None,
        max_frames: Optional[int] = None,
        tool: Optional[str] = None,
    ):
        # The parent keys several things off a path. A live capture has none,
        # so the interface name stands in — it is what a Locus should say the
        # observation came from.
        super().__init__(
            path=f"live:{iface}",
            burst_gap_s=burst_gap_s,
            retain_payloads=retain_payloads,
            parse_http=parse_http,
        )
        self.iface = iface
        self.bpf = bpf
        self.snaplen = snaplen
        self.duration = duration
        self.max_frames = max_frames
        self.tool = tool
        self._process: Optional[subprocess.Popen] = None
        self.started: Optional[float] = None
        self.stopped_because = ""

    # -- the capture program -----------------------------------------------

    def _command(self) -> List[str]:
        tool = self.tool or (available_tools() or [None])[0]
        if tool is None:
            raise CaptureUnavailable(_no_tool_message())
        if tool == "dumpcap":
            # -P forces classic pcap on stdout. -q silences the packet
            # counter, which would otherwise interleave with the report.
            command = ["dumpcap", "-i", self.iface, "-w", "-", "-P", "-q",
                       "-s", str(self.snaplen)]
            if self.duration:
                # Let dumpcap own the clock as well: if this process is
                # blocked reading, an internal timer would not fire until
                # the next frame arrived, which on a quiet interface could
                # be never.
                command += ["-a", f"duration:{int(self.duration)}"]
            if self.bpf:
                command += ["-f", self.bpf]
            return command

        command = ["tcpdump", "-i", self.iface, "-w", "-", "-U",
                   "-s", str(self.snaplen)]
        if self.bpf:
            command += [self.bpf]
        return command

    @staticmethod
    def _isolation_kwargs() -> dict:
        """Put the capture child in its own process group so Ctrl-C reaches
        this process and the child is stopped deliberately, not raced.

        The mechanism is platform-specific: POSIX does it with a new session
        (setsid, via start_new_session); Windows has no setsid, so it uses
        the CREATE_NEW_PROCESS_GROUP creation flag instead. Passing
        start_new_session on Windows would be silently ignored, leaving no
        isolation at all — hence the split."""
        if os.name == "nt":
            # getattr because the constant only exists on a Windows
            # interpreter; defined-away to 0 elsewhere so the branch is
            # inspectable without crashing a non-Windows Python.
            return {"creationflags":
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
        return {"start_new_session": True}

    def start(self) -> None:
        command = self._command()
        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **self._isolation_kwargs(),
            )
        except (OSError, FileNotFoundError) as error:
            raise CaptureUnavailable(
                f"could not start {command[0]}: {error}"
            ) from error
        self.started = time.time()

    def stop(self) -> None:
        """Ask the capture to finish, then insist.

        SIGTERM first so dumpcap flushes what it has: killing it outright
        can truncate the last frame, and a half-written frame is a parse
        error reported as a corrupt capture.
        """
        process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        except (OSError, ProcessLookupError):
            pass

    def _stderr(self) -> str:
        process = self._process
        if process is None or process.stderr is None:
            return ""
        try:
            return process.stderr.read().decode("utf-8", "replace").strip()
        except OSError:
            return ""

    # -- frames ------------------------------------------------------------

    def _raw_frames(self) -> Iterator[Tuple[int, float, int, bytes]]:
        """Frames straight off the capture program, unbounded.

        Split from `frames` so that the stop conditions are applied to ANY
        frame source. With the bounds written inline, a subclass or a test
        substituting a different source silently lost them — which is how
        `--frames` came to be ignored by everything except the real pipe.
        """
        if self._process is None:
            self.start()
        process = self._process
        assert process is not None and process.stdout is not None
        yield from read_stream(process.stdout)

    def frames(self) -> Iterator[Tuple[int, float, int, bytes]]:
        """Stream frames until a bound is hit, the capture ends, or Ctrl-C.

        A KeyboardInterrupt is caught rather than propagated: the operator
        pressing Ctrl-C means "stop capturing and tell me what you saw", not
        "discard the last few minutes". Everything already parsed is still
        reported, and `stopped_because` records why it ended.
        """
        if self.started is None:
            self.started = time.time()
        deadline = (self.started + self.duration) if self.duration else None
        count = 0

        try:
            for frame_no, ts, linktype, frame in self._raw_frames():
                yield frame_no, ts, linktype, frame
                count += 1
                if self.max_frames and count >= self.max_frames:
                    self.stopped_because = f"reached --frames {self.max_frames}"
                    break
                # Checked against the wall clock, not the frame timestamp:
                # the bound the operator asked for is real elapsed time, and
                # on a quiet interface those diverge.
                if deadline and time.time() >= deadline:
                    self.stopped_because = f"reached --duration {self.duration:g}s"
                    break
        except KeyboardInterrupt:
            self.stopped_because = "interrupted"
        except (OSError, ValueError) as error:
            self.stopped_because = f"capture stream ended: {error}"
        finally:
            self.stop()

        process = self._process
        if not self.stopped_because and process is not None:
            # The child exited on its own. If it failed, its stderr is the
            # only thing that explains why — a silent zero-frame capture is
            # indistinguishable from an idle interface otherwise.
            returncode = process.poll()
            message = self._stderr()
            if returncode not in (0, None) or (count == 0 and message):
                raise CaptureUnavailable(
                    f"{self._command()[0]} exited {returncode}"
                    + (f": {message}" if message else "")
                )
            self.stopped_because = "capture ended"

    # -- reporting ---------------------------------------------------------

    def describe(self) -> str:
        elapsed = (time.time() - self.started) if self.started else 0.0
        return (
            f"live capture on {self.iface}"
            + (f", filter {self.bpf!r}" if self.bpf else "")
            + f" — {elapsed:.1f}s elapsed, {self.stats['frames']:,} frames"
            + (f" ({self.stopped_because})" if self.stopped_because else "")
        )


def preflight(iface: str) -> None:
    """Fail early and usefully on the things that go wrong first.

    A bad interface name and a missing capability both surface from
    dumpcap as a nonzero exit several seconds later, by which point the
    cause is buried. Both are cheap to check up front.
    """
    interfaces = list_interfaces()
    # A bare integer is a valid interface selector for dumpcap/tcpdump (and
    # the usual way to name one on Windows), so never reject a digit even
    # when it is not in the parsed name list.
    if interfaces and iface not in interfaces and not iface.isdigit():
        raise CaptureUnavailable(
            f"no interface named {iface!r}. Available: "
            + ", ".join(interfaces)
        )
    if not available_tools():
        raise CaptureUnavailable(_no_tool_message())
    _permission_note()


def _no_tool_message() -> str:
    """Platform-specific guidance for a missing capture program."""
    if os.name == "nt":
        return (
            "no capture program found. Install Wireshark for Windows, which "
            "provides dumpcap.exe (and the Npcap driver capture needs), and "
            "make sure its folder is on PATH. This tool does not capture "
            "directly."
        )
    return (
        "no capture program found. Install wireshark-cli (for dumpcap) or "
        "tcpdump. This tool does not capture directly and does not run as root."
    )


def _permission_note() -> None:
    """Warn about the thing that most often blocks capture, per platform.

    The POSIX path is the 'wireshark' group that grants dumpcap its
    capability; `grp` and `geteuid` live only there, so the whole block is
    guarded to POSIX and Windows gets the Npcap note instead.
    """
    if os.name != "posix":
        if os.name == "nt" and shutil.which("dumpcap"):
            print(
                "note: live capture on Windows needs the Npcap driver "
                "(installed with Wireshark). If capture fails with a "
                "permissions error, reinstall Npcap with 'Support raw "
                "802.11' / admin as needed.",
                file=sys.stderr,
            )
        return
    if not shutil.which("dumpcap"):
        return
    # Capture needs CAP_NET_RAW, which dumpcap normally carries. Where it does
    # not, the failure is a permissions error that reads like a bug, so say
    # what to do about it instead.
    import grp

    try:
        members = set(grp.getgrnam("wireshark").gr_mem)
    except KeyError:
        return
    user = os.environ.get("USER") or ""
    if user and user not in members and os.geteuid() != 0:
        # Not fatal — the capability may be granted some other way.
        print(
            f"note: {user} is not in the 'wireshark' group; if capture "
            f"fails, that is why (usermod -aG wireshark {user}, then "
            f"log out and back in)",
            file=sys.stderr,
        )
