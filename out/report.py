"""Human-readable report — the default output.

Written for an analyst reading a terminal at 2am, which sets three rules:

  1. Every claim is followed by the number that produced it. "Possible
     beacon" alone is unactionable; "60.1s period, MAD 2.4s, 0.3% of hosts
     use this destination" can be checked.
  2. The Wireshark filter is on the line, not in a footnote. A finding you
     cannot open is a finding you cannot triage.
  3. A cold baseline is announced at the top, because otherwise a page of
     "uncommon destination" findings reads as a broken tool rather than as
     an empty denominator.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from core.model import Evidence, Finding, Narrative, Severity

__all__ = ["render"]

_MARKER = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: " !",
    Severity.MEDIUM: " ~",
    Severity.LOW: " .",
    Severity.INFO: "  ",
}

#: Features worth printing per primitive, in the order an analyst reads them.
#: Deliberately a short list — dumping every computed number buries the two
#: that matter. The full set is always in `--out json`.
_HEADLINE = {
    "periodicity": (
        ("period_s", "period {:.1f}s"),
        ("interval_mad_s", "MAD {:.1f}s"),
        ("observations", "{:.0f} callbacks"),
    ),
    "jitter": (("implied_jitter_pct", "~{:.0f}% jitter"),),
    "rarity": (
        ("prevalence", "{:.1%} of hosts"),
        ("age_s", "first seen {:.0f}s ago"),
    ),
    "asymmetry": (
        ("asymmetry", "asymmetry {:+.2f}"),
        ("egress_bytes", "{:.0f}B out"),
        ("ingress_bytes", "{:.0f}B in"),
    ),
    "burstiness": (("burstiness", "burstiness {:+.2f}"),),
    "fanout.qname": (
        ("unique_values", "{:.0f} unique names"),
        ("unique_fraction", "{:.0%} unique"),
    ),
    "fanout.dport": (("unique_values", "{:.0f} ports"),),
    "entropy": (("bits_per_byte", "{:.2f} bits/byte"),),
    # Share and denominator together, never the share alone: "90% failed"
    # reads identically at n=10 and n=10,000, and the score deliberately
    # does not — see the Wilson bound in FailureRate.
    "failure_rate.rcode": (
        ("failure_share", "{:.1%} failed"),
        ("failures", "{:.0f} of"),
        ("answered", "{:.0f} answered"),
    ),
    "web.timing_differential": (
        ("fast_median_ms", "fast {:.1f}ms"),
        ("slow_median_ms", "slow {:.1f}ms"),
        ("separation_ms", "sep {:.1f}ms"),
        ("within_spread_ms", "spread {:.2f}ms"),
        ("gap_ratio", "gap x{:.0f}"),
    ),
}


def render(
    findings: Sequence[Finding],
    evidences: Sequence[Evidence],
    narratives: Optional[dict] = None,
    warm_up: Optional[str] = None,
    stats: Optional[dict] = None,
    redactor=None,
    advisories: Sequence[str] = (),
) -> str:
    """`redactor` masks inspection facts before printing.

    The terminal is an output like any other — reports get screenshotted,
    pasted into tickets, and scrolled past in shared sessions. A live session
    cookie printed to stdout is leaked.
    """
    lines: List[str] = []
    narratives = narratives or {}
    if redactor is None:
        from core.redact import redact_secrets
        redactor = redact_secrets

    if stats:
        lines.append(
            "capture: {frames} frames, {decoded} decoded, "
            "{tcp} tcp, {udp} udp, {dns} dns".format(**stats)
        )
    lines.append(
        f"channels scored: {len(evidences)}    findings: {len(findings)}"
    )

    if warm_up:
        lines += ["", f"  WARNING  {warm_up}"]

    # Advisories are not findings. They exist because an analysis that cannot
    # run should say what it needs — "1 distinct session token; quality
    # analysis needs 8" is actionable, and silence is not.
    for advisory in advisories:
        lines += ["", f"  ADVICE   {advisory}"]

    if not findings:
        lines += [
            "",
            "No findings. This is a real answer only if the baseline is warm",
            "and the capture is long enough to accumulate cadence — a 30-second",
            "capture cannot evidence a 60-second beacon. Measurements for every",
            "channel are in --out json regardless.",
        ]
        return "\n".join(lines)

    groups = _coalesce(findings)
    shown = sum(1 for _lead, siblings in groups if siblings)
    if shown:
        lines.append(
            f"  {len(findings):,} findings collapsed into {len(groups):,} "
            f"by rule and host; see 'also on' rosters"
        )

    for finding, siblings in groups:
        lines += ["", _header(finding)]

        channel = finding.channel
        if channel.initiator and channel.responder:
            dims = "  ".join(f"{k}={v}" for k, v in sorted(channel.dims.items()))
            lines.append(
                f"    {channel.initiator.value} -> {channel.responder.value}   {dims}"
            )

        # Only the evidence this rule referenced. Evidence is per-channel and
        # a finding is per-rule, so printing all of it repeats every
        # inspection under every finding on the same host.
        cited = set(finding.cited)

        for result in finding.evidence.results:
            if result.name == "_scoring":
                continue
            if cited and result.name not in cited:
                continue
            headline = _format_features(result.name, result.features)
            if headline:
                lines.append(f"    {result.name:<16} {headline}")

        # Inspections print as key/value facts rather than a headline
        # template: their evidence is strings whose names vary per inspector,
        # so there is nothing stable to format against.
        for inspection in finding.evidence.inspections:
            if cited and inspection.name not in cited:
                continue
            count = (
                f"  x{inspection.occurrences}" if inspection.occurrences > 1 else ""
            )
            lines.append(
                f"    {inspection.name:<16} score {inspection.score:.2f}{count}"
            )
            for key, value in redactor(inspection.facts, inspection.secret_facts).items():
                lines.append(f"      {key:<24} {value}")
            where = inspection.reference()
            if where and where != (finding.display_filter or finding.reference):
                lines.append(f"      {'seen at':<24} {where}")

        for result in finding.evidence.results:
            if cited and result.name not in cited:
                continue
            for note in result.notes:
                if result.name != "_scoring":
                    lines.append(f"      note: {result.name}: {note}")
        for inspection in finding.evidence.inspections:
            if cited and inspection.name not in cited:
                continue
            for note in inspection.notes:
                lines.append(f"      note: {inspection.name}: {note}")

        scoring = finding.evidence.by_name("_scoring")
        if scoring and scoring.notes:
            lines.append(f"    confidence      {' | '.join(scoring.notes)}")

        if finding.refs:
            lines.append(f"    refs            {', '.join(finding.refs)}")

        # Labelled by what it actually is. A HAR yields no Wireshark filter,
        # and printing one under that heading would send the analyst to the
        # wrong packet in a capture that does not contain this traffic.
        if finding.display_filter:
            lines.append(f"    wireshark       {finding.display_filter}")
        elif finding.reference:
            lines.append(f"    found at        {finding.reference}")

        lines += _roster(siblings)

        narrative = narratives.get(finding.id)
        if isinstance(narrative, Narrative):
            lines += ["", f"    {narrative.summary}"]
            for para in narrative.reasoning.splitlines():
                if para.strip():
                    lines.append(f"    {para.strip()}")

    return "\n".join(lines)


#: Below this many siblings, print each finding in full. Two findings on one
#: host are readable; a roster of two is just indirection.
_COALESCE_AT = 3


def _coalesce(findings: Sequence[Finding]) -> List[Tuple[Finding, List[Finding]]]:
    """Group findings that are one behaviour reported many times.

    WHY. Adding the DNS resolution-failure rule produced 67 findings on a
    real capture, all of them the same rule, the same host and the same
    misconfiguration — one per (zone, qtype) channel. The measurement is
    correct at that grain and the attribution should stay there: an operator
    chasing it needs to know which zone. But 67 restatements of one fact is
    the alert fatigue this tool exists to avoid, and no amount of correctness
    in the scoring layer survives a report nobody finishes reading.

    So the grain of the MEASUREMENT and the grain of the REPORT are allowed
    to differ. The loudest member prints in full and its siblings become a
    roster of what else matched. Nothing is dropped — the JSON output is
    still per-channel, and the roster names every sibling or says how many
    it elided.

    Keyed on (rule_id, initiator): same rule, same originating host. NOT on
    responder, because a host beaconing to twelve destinations is exactly
    the shape that must stay visible as twelve.
    """
    order: List[Tuple[str, str]] = []
    buckets: Dict[Tuple[str, str], List[Finding]] = {}
    for finding in findings:
        initiator = (
            finding.channel.initiator.value if finding.channel.initiator else ""
        )
        key = (finding.rule_id, initiator)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(finding)

    groups: List[Tuple[Finding, List[Finding]]] = []
    for key in order:
        members = sorted(buckets[key], key=lambda f: -f.confidence)
        if len(members) < _COALESCE_AT:
            groups += [(member, []) for member in members]
        else:
            groups.append((members[0], members[1:]))
    return groups


def _roster(siblings: Sequence[Finding]) -> List[str]:
    """One line per coalesced sibling: its dims and its confidence."""
    if not siblings:
        return []

    lines = [f"    also on         {len(siblings)} further channel(s), "
             f"same rule and host:"]
    for sibling in siblings[:_ROSTER_ROWS]:
        dims = "  ".join(
            f"{k}={v}" for k, v in sorted(sibling.channel.dims.items())
        )
        lines.append(f"      {sibling.confidence:.2f}  {dims}")
    if len(siblings) > _ROSTER_ROWS:
        lines.append(
            f"      … {len(siblings) - _ROSTER_ROWS} more "
            f"(all channels in --out json)"
        )
    return lines


#: Roster rows before truncating. A truncation that does not say how much it
#: hid reads as completeness; see the note in out/narrate.py.
_ROSTER_ROWS = 12


def _header(finding: Finding) -> str:
    marker = _MARKER.get(finding.severity, "  ")
    return (
        f"{marker} [{finding.severity.value.upper():<8}] "
        f"{finding.title}  (confidence {finding.confidence:.2f})\n"
        f"    {finding.rule_id}  {finding.channel.fingerprint}"
    )


def _format_features(name: str, features) -> str:
    specs = _HEADLINE.get(name)
    if not specs:
        return ""
    parts = []
    for key, template in specs:
        value = features.get(key)
        if value is not None:
            parts.append(template.format(value))
    return "  ".join(parts)
