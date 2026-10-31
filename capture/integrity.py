"""Honesty about the capture itself.

Every other module interprets the traffic; this one interprets the FILE. A
capture is not a neutral record — it was made by a tool, on a machine, with
settings, and the most common defects each quietly corrupt a different
analysis downstream:

  TRUNCATION. A snaplen cut frames short, so payload-dependent parsing
  (TLS handshakes, HTTP, DNS answers) saw only the front of messages.
  Detected from the packet itself: the IP header states a total length,
  and when the frame holds fewer bytes than the header claims, the
  difference was never captured. This is independent of the pcap record's
  own lengths, so it also catches files whose metadata lies.

  DUPLICATES. A SPAN port fed by both directions of the same link, or a
  bonded interface, delivers many frames twice. Every volume number is
  then inflated, and a request/response pair can appear as four packets.
  Detected as byte-identical frames within a small window — real traffic
  repeats (TCP retransmits), but a retransmit differs in IP id/checksum,
  so BYTE-identical neighbours are the capture apparatus, not the network.

  CLOCK. Timestamps that run backwards poison every interval measurement —
  cadence, jitter, latency — which are the heart of this tool. Large gaps
  mean the capture stopped and resumed (machine asleep, rotation), and a
  cadence spanning a gap is an artefact.

None of these is reported as a finding, because none is about the traffic.
They surface in their own section, as facts about what the measurements
below them can and cannot be trusted to mean.
"""

from __future__ import annotations

import os
import stat as _stat
import struct
import time
from collections import deque
from typing import Any, Dict, Optional

from capture.decode import _strip_link

__all__ = ["IntegrityTracker", "capture_liveness"]

#: A capture file written within this many seconds of being read is treated
#: as possibly still in progress. Short enough not to flag a file saved a
#: minute ago, long enough to catch one a running capture just flushed.
_FRESH_WINDOW_S = 3.0


def capture_liveness(path: str, size_before: Optional[int],
                     now: Optional[float] = None,
                     fresh_window_s: float = _FRESH_WINDOW_S) -> Dict[str, Any]:
    """Whether a capture FILE looks like it is still being written.

    Reading a pcap that a running capture is appending to analyses only the
    bytes flushed so far — a partial snapshot that silently changes between
    runs (which is exactly how a growing engagement capture misled a reader
    once). Two signals, both about the file on disk rather than the traffic,
    so wall-clock time is the honest clock here:

      - it GREW while being read (size now exceeds the size at open) — proof
        it is being written right now;
      - it was last written within a few seconds of being read — a strong
        hint the same.

    Returns {} for anything that is not a regular file (a live `live:iface`
    pseudo-path, a pipe), so the live path never false-flags itself.
    """
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return {}
    if not _stat.S_ISREG(info.st_mode):
        return {}
    out: Dict[str, Any] = {}
    if size_before is not None and info.st_size > size_before:
        out["growing_bytes"] = info.st_size - size_before
    age = (now if now is not None else time.time()) - info.st_mtime
    if 0.0 <= age < fresh_window_s:
        out["last_written_s"] = round(age, 1)
    return out

#: A silent span this long inside a capture is reported as a gap. Chosen to
#: be far above any burst spacing and below "the operator left for lunch".
_GAP_S = 60.0

#: How many recent frames to compare for byte-identical duplicates. SPAN
#: duplication delivers the copy within a frame or two of the original.
_DUP_WINDOW = 8


class IntegrityTracker:
    """Feed every raw frame; read `report()` once at end of capture."""

    def __init__(self, gap_s: float = _GAP_S) -> None:
        self._gap_s = gap_s
        self._recent: deque = deque(maxlen=_DUP_WINDOW)
        self._last_ts: Optional[float] = None
        self.frames = 0
        self.duplicates = 0
        self.truncated = 0
        self.truncated_missing = 0      # bytes the snaplen threw away
        self.backwards = 0
        self.max_regression = 0.0
        self.gaps = 0
        self.largest_gap = 0.0
        self.largest_gap_at: Optional[float] = None

    def frame(self, ts: float, linktype: int, frame: bytes) -> None:
        self.frames += 1

        # Clock. Only when both timestamps exist — a reader that could not
        # resolve a timestamp yields 0.0, and judging order against that
        # would manufacture a regression per real frame.
        if ts and self._last_ts:
            delta = ts - self._last_ts
            if delta < 0:
                self.backwards += 1
                self.max_regression = max(self.max_regression, -delta)
            elif delta > self._gap_s:
                self.gaps += 1
                if delta > self.largest_gap:
                    self.largest_gap = delta
                    self.largest_gap_at = self._last_ts
        if ts:
            self._last_ts = ts

        # Duplicates: byte-identical to a recent frame. Hash would do, but
        # the window is 8 and frames are already in memory — direct compare
        # cannot false-positive on a hash collision.
        if any(frame == seen for seen in self._recent):
            self.duplicates += 1
        self._recent.append(frame)

        # Truncation: the IP header's claimed length against what is here.
        data = _strip_link(linktype, frame)
        if data is None or not data:
            return
        version = data[0] >> 4
        claimed = 0
        if version == 4 and len(data) >= 4:
            claimed = struct.unpack(">H", data[2:4])[0]
        elif version == 6 and len(data) >= 6:
            claimed = 40 + struct.unpack(">H", data[4:6])[0]
        if claimed > len(data):
            self.truncated += 1
            self.truncated_missing += claimed - len(data)

    def report(self) -> Dict[str, Any]:
        """The artefact counts, empty when the capture is clean — so a
        consumer can test truthiness instead of comparing seven zeros."""
        out: Dict[str, Any] = {}
        if self.truncated:
            out["truncated"] = self.truncated
            out["truncated_missing"] = self.truncated_missing
        if self.duplicates:
            out["duplicates"] = self.duplicates
        if self.backwards:
            out["backwards"] = self.backwards
            out["max_regression_s"] = self.max_regression
        if self.gaps:
            out["gaps"] = self.gaps
            out["largest_gap_s"] = self.largest_gap
            out["largest_gap_at"] = self.largest_gap_at
        if out:
            out["frames"] = self.frames
        return out
