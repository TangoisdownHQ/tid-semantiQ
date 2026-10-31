"""Annotations for the Wireshark Lua plugin, as a Lua table on disk.

The colorfilters file highlights flagged packets; the Lua plugin goes the
rest of the way — it attaches each finding to the packets as a protocol
subtree, so inside Wireshark the analyst can filter on `semantiq.severity`,
add `semantiq.title` as a column, and click a packet to read what this tool
concluded about it and with what confidence.

The split of labour is deliberate and keeps the architecture honest:

  ANALYSIS HAPPENS HERE, NOT IN LUA. A Lua dissector runs per-packet and
  streaming, which is structurally wrong for flow-level behavioural
  analysis — cadence does not exist in any single packet. So semantiQ
  analyses the capture and writes its verdicts down; the plugin only
  looks them up by frame and by stream. The plugin can never disagree
  with the report, because it holds no opinion of its own.

THE FILE IS A LUA TABLE, NOT JSON. Wireshark ships no JSON library with
its Lua, and vendoring a parser into the plugin would be a second
implementation of somebody's format. A `return { ... }` table needs no
parser at all — the plugin `dofile()`s it — and generating it is string
formatting plus one escaping function. The data file is pure data (one
`return` of a literal table); the plugin rejects anything else on size:
executable code has no business in an annotations file.

The mapping consumes the display filters the findings already carry —
`tcp.stream eq N`, `frame.number == N`, `frame.number in {...}` (with its
truncation comment) — the same strings the report prints, so what the
plugin highlights is exactly what the report told the analyst to look at.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from core.model import Finding
from out.bpf import bpf_for_finding

__all__ = ["write_lua_annotations", "parse_display_filter"]


_STREAM_RE = re.compile(r"^tcp\.stream eq (\d+)$")
_FRAME_ONE_RE = re.compile(r"^frame\.number == (\d+)$")
_FRAME_SET_RE = re.compile(r"^frame\.number in \{([\d,]+)\}$")


def parse_display_filter(
    display_filter: str,
) -> Optional[Tuple[str, List[int]]]:
    """("tcp_stream"|"frame", [numbers]) for the filter shapes findings emit.

    The truncation comment (`...}  # first 40 of 53 frames`) is stripped —
    the plugin annotates the frames the filter names, and the report already
    told the reader the list was cut.

    Returns None for a shape this module does not recognise, which the
    caller COUNTS rather than ignores: an unannotatable finding must be a
    number in the operator's face, not a silent gap in Wireshark.
    """
    text = display_filter.split("#", 1)[0].strip()
    match = _STREAM_RE.match(text)
    if match:
        return ("tcp_stream", [int(match.group(1))])
    match = _FRAME_ONE_RE.match(text)
    if match:
        return ("frame", [int(match.group(1))])
    match = _FRAME_SET_RE.match(text)
    if match:
        return ("frame", [int(n) for n in match.group(1).split(",") if n])
    return None


def _lua_string(text: str) -> str:
    """A safe Lua string literal: the annotations must be data even when a
    finding title (or a capture-derived value inside one) is hostile."""
    escaped = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'


def write_lua_annotations(
    path: Path,
    findings: Sequence[Finding],
    source_name: str = "",
) -> Tuple[int, int]:
    """Write the annotations table. Returns (annotated, unannotatable).

    `unannotatable` counts findings whose reference is not a packet filter —
    a HAR entry, say — and the caller reports it, because a plugin that
    silently shows fewer findings than the report would have the analyst
    trust the quieter of two disagreeing views.
    """
    by_stream: Dict[int, List[Finding]] = defaultdict(list)
    by_frame: Dict[int, List[Finding]] = defaultdict(list)
    skipped = 0

    for finding in findings:
        if not finding.display_filter:
            skipped += 1
            continue
        parsed = parse_display_filter(finding.display_filter)
        if parsed is None:
            skipped += 1
            continue
        kind, numbers = parsed
        bucket = by_stream if kind == "tcp_stream" else by_frame
        for number in numbers:
            bucket[number].append(finding)

    def _entry(finding: Finding) -> str:
        # The capture filter travels with the finding so the plugin's summary
        # can show "re-capture this flow" right where the analyst meets it —
        # built from the channel by the same code the --bpf sink uses.
        bpf = bpf_for_finding(finding) or ""
        return (
            "{ rule = %s, title = %s, severity = %s, confidence = %.2f, "
            "bpf = %s }"
            % (
                _lua_string(finding.rule_id),
                _lua_string(finding.title),
                _lua_string(finding.severity.name),
                finding.confidence,
                _lua_string(bpf),
            )
        )

    def _bucket(mapping: Dict[int, List[Finding]]) -> List[str]:
        lines = []
        for number in sorted(mapping):
            entries = ", ".join(_entry(f) for f in mapping[number])
            lines.append(f"    [{number}] = {{ {entries} }},")
        return lines

    lines = [
        "-- generated by tid-semantiQ; load with wireshark/semantiq.lua",
        "-- pure data: one table, no code. The plugin refuses anything else.",
        "return {",
        f"  source = {_lua_string(source_name)},",
        "  by_tcp_stream = {",
        *_bucket(by_stream),
        "  },",
        "  by_frame = {",
        *_bucket(by_frame),
        "  },",
        "}",
    ]
    path.write_text("\n".join(lines) + "\n")
    annotated = len(findings) - skipped
    return annotated, skipped
