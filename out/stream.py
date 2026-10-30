"""Collapsing findings across sliding windows.

A sliding window re-emits each channel as it advances, so the same defect is
found again every window. That repetition is deliberate — more evidence
accumulates and confidence should rise — but it must not reach the operator
as twenty copies of one finding.

`Finding.id` is `rule_id:channel_fingerprint`, stable across emissions, so
collapsing is keyed on that. The instance KEPT is the highest-confidence one,
because later windows hold strictly more evidence than earlier ones; the
count of windows it appeared in is reported alongside, since a finding seen
in one window out of thirty is a different claim from one seen in all of
them.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from core.model import Evidence, Finding, severity_rank

__all__ = ["FindingAggregator", "StreamedFinding"]


@dataclass
class StreamedFinding:
    """One finding plus how it behaved across windows."""

    finding: Finding
    windows_seen: int = 1
    first_window: int = 0
    last_window: int = 0
    lowest_confidence: float = 0.0
    highest_confidence: float = 0.0

    @property
    def persistent(self) -> bool:
        """Seen in more than one window.

        Worth distinguishing: a transient finding can be a windowing
        artefact — a cadence that looked regular across one boundary and not
        the next — whereas one that survives every window is a property of
        the traffic rather than of where the window happened to fall.
        """
        return self.windows_seen > 1

    @property
    def strengthened(self) -> bool:
        """Confidence rose as evidence accumulated, which is the expected
        shape for a real finding under a sliding window."""
        return self.highest_confidence > self.lowest_confidence + 1e-9


#: Channels whose measurements are retained for `--out json`. Bounded,
#: because an unbounded map here is a memory leak proportional to capture
#: LENGTH rather than to anything interesting.
MAX_RETAINED_EVIDENCE = 20_000


@dataclass
class FindingAggregator:
    """Collapse repeated findings, keeping the best-evidenced instance.

    MEMORY IS BOUNDED, and it was not at first. `_evidence` held one entry
    per channel EVER SEEN so that `--out json` could report measurements for
    channels that produced no finding. On a nine-hour capture of real
    browsing that is one entry per DNS zone ever queried — tens of thousands,
    growing for as long as the stream runs, which defeats the whole point of
    windowing the input.

    Findings are kept without limit, because they are bounded by the number
    of distinct (rule, channel) pairs that actually fired — small by
    construction, and the thing the operator came for. Evidence for silent
    channels is LRU-capped and the eviction is counted.
    """

    max_evidence: int = MAX_RETAINED_EVIDENCE
    _seen: Dict[str, StreamedFinding] = field(default_factory=dict)
    _window: int = 0
    #: Latest evidence per channel, LRU-ordered and capped.
    _evidence: "OrderedDict[str, Evidence]" = field(default_factory=OrderedDict)
    _evidence_evicted: int = 0

    def begin_window(self) -> None:
        self._window += 1

    def add(self, findings: Iterable[Finding],
            evidences: Iterable[Evidence] = ()) -> None:
        for evidence in evidences:
            key = evidence.channel.key
            if key in self._evidence:
                self._evidence.move_to_end(key)
            self._evidence[key] = evidence
            while len(self._evidence) > self.max_evidence:
                self._evidence.popitem(last=False)
                self._evidence_evicted += 1

        for finding in findings:
            existing = self._seen.get(finding.id)
            if existing is None:
                self._seen[finding.id] = StreamedFinding(
                    finding=finding,
                    first_window=self._window,
                    last_window=self._window,
                    lowest_confidence=finding.confidence,
                    highest_confidence=finding.confidence,
                )
                continue

            existing.windows_seen += 1
            existing.last_window = self._window
            existing.lowest_confidence = min(
                existing.lowest_confidence, finding.confidence
            )
            if finding.confidence > existing.highest_confidence:
                existing.highest_confidence = finding.confidence
                # Keep the better-evidenced instance, not the first seen.
                existing.finding = finding

    # -- reading out -------------------------------------------------------

    @property
    def windows(self) -> int:
        return self._window

    def findings(self) -> List[Finding]:
        """Deduplicated, worst first — the same order a batch run produces."""
        out = [entry.finding for entry in self._seen.values()]
        out.sort(
            key=lambda f: (severity_rank(f.severity), f.confidence),
            reverse=True,
        )
        return out

    def streamed(self) -> List[StreamedFinding]:
        entries = list(self._seen.values())
        entries.sort(
            key=lambda e: (
                severity_rank(e.finding.severity), e.finding.confidence
            ),
            reverse=True,
        )
        return entries

    def evidences(self) -> List[Evidence]:
        return list(self._evidence.values())

    @property
    def evidence_evicted(self) -> int:
        return self._evidence_evicted

    def notes(self) -> List[str]:
        """Advisory lines about how findings behaved across windows.

        A transient finding is worth flagging rather than hiding: it may be a
        windowing artefact, and the operator is the one who can tell.
        """
        out: List[str] = []
        if self._window <= 1:
            return out
        transient = [
            entry for entry in self._seen.values()
            if not entry.persistent
        ]
        if self._evidence_evicted:
            out.append(
                f"measurements for {self._evidence_evicted} silent channel(s) "
                f"were dropped to stay under the {self.max_evidence}-channel "
                "retention cap. Findings are unaffected; --out json holds "
                "fewer channel rows than the capture contained."
            )
        if transient:
            out.append(
                f"{len(transient)} of {len(self._seen)} finding(s) appeared in "
                f"only one of {self._window} windows — check whether the "
                "evidence straddles a window boundary before trusting them"
            )
        return out
