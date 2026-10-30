"""Level 1: turn computed measurements into prose, and verify every claim.

WHAT THIS IS ALLOWED TO DO, and nothing more: restate values the analysis
already computed, in sentences a reader who does not read packet dumps can
act on. It cannot decide whether something is malicious, cannot adjust a
confidence, and cannot create a Finding — `Finding` is frozen and only
`core/score.py` constructs one. That is invariant I2 of the spec, and it is
the reason a model can be added here without weakening anything.

THE CHECK, NOT THE PROMPT, IS WHAT KEEPS IT HONEST.

A prompt asking a model to avoid inventing numbers is a request. What makes
it an invariant is `Narrative.verify_against()`: the model must name every
feature it relies on, each name is looked up in the Evidence ledger, and a
narrative citing anything that was never computed is REJECTED rather than
displayed. Rejection is not an error — the report falls back to its computed
text, which is complete on its own. The model is an accessory to the
analysis, never a dependency of it.

Three further rules, each learned from a way this could go wrong:

  SECRETS NEVER ENTER THE PROMPT. Inspectors declare `secret_facts`, and
  `core/redact.py` masks them before the prompt is assembled — not before
  it is displayed. A redaction that happens after the model has seen the
  token protects nobody.

  THE PROMPT CARRIES ONLY COMPUTED VALUES. No payload bytes, no raw
  headers. If a number is not in the Evidence, the model cannot cite it,
  so there is no reason to show it.

  A MISSING MODEL IS NOT AN ERROR. Any backend failure, timeout, malformed
  reply or failed verification degrades to the computed report with a note
  saying why. A tool that breaks because a GPU was busy is worse than one
  that stays quiet.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from agents.provider import LLM, LLMError
from core.model import Evidence, Finding, Narrative

__all__ = ["explain_findings", "explain_capture", "ExplainResult", "SYSTEM"]


SYSTEM = """You explain network-capture measurements to a security analyst.

You are given measurements that have ALREADY been computed by a
deterministic analyser. Your job is to explain what they mean in plain
language. You are not the analyser.

Rules, which are enforced mechanically after you answer:

1. Use ONLY the numbers given to you. Never introduce a figure that is not
   in the input. Every feature you rely on must be listed in "cited".
2. Do not state that something is malicious, an attack, or a compromise.
   Describe the behaviour and name the benign and malicious readings that
   are both consistent with it.
3. If the measurements do not support a conclusion, say so. "This is
   regular polling of unknown purpose" is a better answer than a guess.
4. No recommendations unless they follow directly from a measurement.
5. Be concise and concrete. An analyst at 2am is reading this.

Answer with JSON only, no prose outside it, in exactly this form:

{"summary": "one sentence", "reasoning": "two to five sentences",
 "cited": ["periodicity.period_s", "rarity.prevalence"]}

"cited" names features in the form <measurement>.<feature>, copied exactly
from the input. A name you invent will cause your whole answer to be
discarded."""


class ExplainResult:
    """Narratives that passed verification, plus why any did not.

    The rejections are kept and reported. A silently dropped explanation
    looks like a model that had nothing to say, which is a different and
    much more comforting fact than a model that made numbers up.
    """

    def __init__(self) -> None:
        self.narratives: Dict[str, Narrative] = {}
        self.rejected: List[Tuple[str, str]] = []
        self.model = ""

    @property
    def ok(self) -> int:
        return len(self.narratives)

    def notes(self) -> List[str]:
        out: List[str] = []
        for subject, reason in self.rejected:
            out.append(f"explanation for {subject} discarded: {reason}")
        return out


# --------------------------------------------------------------------------
# evidence -> prompt
# --------------------------------------------------------------------------


def _features(evidence: Evidence, redactor) -> Tuple[List[str], set]:
    """Every computed feature, as `name.feature = value` lines.

    Returns the lines and the set of legal citation names, so the prompt and
    the verifier are derived from one source. Building them separately is how
    a verifier ends up rejecting names the prompt invited.
    """
    lines: List[str] = []
    legal: set = set()

    for result in evidence.results:
        if result.name == "_scoring":
            continue
        lines.append(f"  {result.name}: score {result.score:.3f} "
                     f"(n={result.sample_size}, method={result.method})")
        for key, value in sorted(result.features.items()):
            citation = f"{result.name}.{key}"
            legal.add(citation)
            lines.append(f"    {citation} = {value}")
        for note in result.notes:
            lines.append(f"    note: {note}")

    for inspection in evidence.inspections:
        lines.append(f"  {inspection.name}: score {inspection.score:.3f} "
                     f"({inspection.occurrences} occurrence(s))")
        # Redacted HERE, before the prompt exists. Masking at display time
        # would mean the model had already read the token.
        safe = redactor(inspection.facts, inspection.secret_facts)
        for key, value in sorted(safe.items()):
            citation = f"{inspection.name}.{key}"
            legal.add(citation)
            lines.append(f"    {citation} = {value}")

    return lines, legal


def _finding_prompt(finding: Finding, redactor) -> Tuple[str, set]:
    channel = finding.channel
    where = ""
    if channel.initiator and channel.responder:
        where = f"{channel.initiator.value} -> {channel.responder.value}"
    dims = "  ".join(f"{k}={v}" for k, v in sorted(channel.dims.items()))

    lines, legal = _features(finding.evidence, redactor)
    # Only the evidence this rule actually used. Showing the rest invites an
    # explanation built on measurements the verdict did not rest on.
    cited = set(finding.cited)
    if cited:
        kept = []
        keep_legal = set()
        current: Optional[str] = None
        for line in lines:
            if not line.startswith("    "):
                current = line.strip().split(":")[0]
            if current in cited or not cited:
                kept.append(line)
        lines = kept
        keep_legal = {c for c in legal if c.rpartition(".")[0] in cited}
        legal = keep_legal or legal

    # The legal set, listed explicitly rather than left to be inferred from
    # the value lines. A smaller local model reliably cites plausible
    # neighbours otherwise — `failure_rate.rcode.rcode_name` was offered
    # twice, which appears in the method string but is not a feature. Being
    # unambiguous about what may be cited is not weakening the check; the
    # check still runs, and this just stops it rejecting answers that were
    # trying to be correct.
    allowed = sorted(legal)
    prompt = "\n".join([
        f"RULE: {finding.rule_id}",
        f"TITLE: {finding.title}",
        f"SEVERITY: {finding.severity.value}",
        f"CONFIDENCE: {finding.confidence:.2f} (computed, do not restate as "
        f"certainty)",
        f"DOMAIN: {channel.domain}",
        f"CHANNEL: {where}  {dims}".rstrip(),
        "",
        "MEASUREMENTS:",
        *lines,
        "",
        "CITABLE NAMES — the \"cited\" list may contain ONLY these strings,",
        "copied exactly. An empty list is acceptable. Anything else causes",
        "your whole answer to be discarded:",
        *(f"  {name}" for name in allowed),
        "",
        "Explain what this means.",
    ])
    return prompt, legal


def _capture_prompt(report: str, stats: Optional[Mapping[str, Any]]) -> str:
    # The computed narration IS the input. The model is summarising a report
    # that already exists rather than analysing a capture, which is what
    # keeps it unable to introduce anything.
    head = report[:12000]
    truncated = len(report) > len(head)
    return "\n".join([
        "Below is a computed observation report for a packet capture.",
        "Summarise what an analyst should understand from it.",
        "",
        "Leave 'cited' empty for this task — it is a summary of the report,",
        "not a claim about a specific measurement.",
        "",
        head,
        ("\n[report truncated for length]" if truncated else ""),
    ])


# --------------------------------------------------------------------------
# reply -> Narrative
# --------------------------------------------------------------------------


_JSON = re.compile(r"\{.*\}", re.S)


def _parse(reply: str) -> Optional[Dict[str, Any]]:
    """Pull the JSON object out of a reply.

    Tolerant of fenced code blocks and of a model that cannot resist a
    sentence of preamble — but NOT tolerant of a missing object. Guessing a
    summary out of free text would mean accepting an answer whose citations
    were never stated, and the citations are the entire safety mechanism.
    """
    text = reply.strip()
    if text.startswith("```"):
        text = text.split("```")[1] if "```" in text[3:] else text[3:]
        if text.startswith("json"):
            text = text[4:]
    match = _JSON.search(text)
    if match is None:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _narrative(
    subject_id: str, data: Mapping[str, Any], model: str
) -> Optional[Narrative]:
    summary = str(data.get("summary") or "").strip()
    reasoning = str(data.get("reasoning") or "").strip()
    if not summary:
        return None
    cited = data.get("cited") or []
    if isinstance(cited, str):
        cited = [cited]
    return Narrative(
        finding_id=subject_id,
        summary=summary,
        reasoning=reasoning,
        cited_features=tuple(str(c).strip() for c in cited if str(c).strip()),
        model=model,
    )


# --------------------------------------------------------------------------
# public entry points
# --------------------------------------------------------------------------


def explain_findings(
    llm: LLM,
    findings: Sequence[Finding],
    redactor=None,
    limit: int = 10,
) -> ExplainResult:
    """One verified Narrative per finding, as far as the model manages.

    `limit` is a cost ceiling, not a filter: findings arrive severity-ordered
    from the scorer, so the cap drops the least severe. It is reported when
    it bites.
    """
    if redactor is None:
        from core.redact import redact_secrets
        redactor = redact_secrets

    result = ExplainResult()
    result.model = getattr(llm, "name", "unknown")

    for finding in findings[:limit]:
        prompt, legal = _finding_prompt(finding, redactor)
        try:
            reply = llm.complete(SYSTEM, prompt)
        except LLMError as error:
            result.rejected.append((finding.rule_id, str(error)))
            # A backend that is down will be down for the next one too.
            break

        data = _parse(reply)
        if data is None:
            result.rejected.append(
                (finding.rule_id, "reply was not JSON")
            )
            continue

        narrative = _narrative(finding.id, data, result.model)
        if narrative is None:
            result.rejected.append((finding.rule_id, "no summary in reply"))
            continue

        # THE CHECK. Every cited feature must exist in the ledger.
        ok, unknown = narrative.verify_against(finding.evidence)
        if not ok:
            result.rejected.append((
                finding.rule_id,
                "cited measurements that were never computed: "
                + ", ".join(unknown),
            ))
            continue

        # Belt and braces: a citation can exist in the Evidence yet not be
        # among the features this finding was shown. Accepting it would let
        # an explanation lean on a measurement the verdict did not use.
        # Same last-dot rule as verify_against: a measurement name contains
        # dots, so splitting on the first one mis-attributes every citation
        # to a parameterised primitive or an inspector.
        outside = [
            c for c in narrative.cited_features if legal and c not in legal
        ]
        if outside:
            result.rejected.append((
                finding.rule_id,
                "cited measurements outside this finding: " + ", ".join(outside),
            ))
            continue

        result.narratives[finding.id] = narrative

    if len(findings) > limit:
        result.rejected.append((
            "(cap)",
            f"{len(findings) - limit} further finding(s) not explained; "
            f"raise --explain-limit",
        ))
    return result


def explain_capture(
    llm: LLM,
    report: str,
    stats: Optional[Mapping[str, Any]] = None,
) -> Tuple[Optional[Narrative], Optional[str]]:
    """A plain-language summary of the whole computed report.

    Returns (narrative, error). No citation check applies: there is no single
    Evidence to verify against, and the input is the report itself rather
    than a capture — the model cannot introduce a measurement because it was
    only ever shown conclusions that are already computed and printed
    directly below its summary, where any disagreement is visible.
    """
    try:
        reply = llm.complete(SYSTEM, _capture_prompt(report, stats))
    except LLMError as error:
        return None, str(error)

    data = _parse(reply)
    if data is None:
        return None, "reply was not JSON"
    narrative = _narrative("capture", data, getattr(llm, "name", "unknown"))
    if narrative is None:
        return None, "no summary in reply"
    return narrative, None
