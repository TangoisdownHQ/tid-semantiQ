"""Level 2: hypothesise, measure, then interpret what came back.

THE LOOP, and the reason it is two calls rather than one:

    1. PROPOSE.  The model sees a channel's computed measurements and the
       closed probe vocabulary, and answers with a hypothesis plus the
       measurements that would support or undermine it.
    2. MEASURE.  This module runs those probes through the ordinary
       primitives. The model is not involved. Refusals come back with a
       reason.
    3. INTERPRET. The model sees the RESULTS — including the refusals — and
       says what they showed, explicitly including the case where they
       undermined its own hypothesis.

Splitting it is the whole point. Asked in one call, a model states a
hypothesis and its confirmation in the same breath, and the confirmation is
generated rather than measured. Here it has to commit to a prediction before
any number exists, and then account for the number it got. A hypothesis that
fails is a useful output, so the prompt asks for it by name and the result
carries `supported` as a verdict the model must state about its own idea.

WHAT IS STILL NOT TRUSTED. No `Finding` is created — this produces an
`Investigation`, which is a report of questions asked and answers measured.
Nothing here feeds the scorer, adjusts a confidence, or alters a rule. The
probe results are real measurements and are printed as such; the prose
around them is the model's and is labelled as the model's.

HONESTY ABOUT WHAT THIS IS FOR. It cannot find what the primitives cannot
measure. It is a way of pointing the existing measurements at a question
nobody wrote a rule for — which is exactly the gap a ruleset always has, and
why "no findings" was never the same thing as "nothing here".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from agents.explain import _features, _parse
from agents.probe import (
    MAX_PROBES,
    Probe,
    ProbeResult,
    describe_vocabulary,
    parse_probes,
    run_probe,
)
from agents.provider import LLM, LLMError
from core.model import Context, Evidence, Series

__all__ = ["Investigation", "investigate_channel", "investigate", "PROPOSE",
           "INTERPRET"]


PROPOSE = """You direct a network-capture analyser. You do not analyse
anything yourself.

You are shown what has already been measured on one channel, and a list of
measurements the analyser can perform on request. Propose ONE hypothesis
about what this channel is doing, and the measurements that would test it.

A good hypothesis is falsifiable and names what would disprove it. "This
could be DNS tunnelling, which would require near-random query names and
high name cardinality" is testable. "This looks suspicious" is not.

Rules:
1. Only request measurements from the list given. Arguments must use
   attributes listed as present on the channel.
2. Predict what the measurement will show IF your hypothesis holds. You are
   committing to this before you see any result.
3. Request at most 4 measurements. Prefer the ones that would DISPROVE the
   hypothesis — a measurement that cannot fail tells you nothing.
4. Do not state a conclusion. You have no results yet.

Answer with JSON only:

{"hypothesis": "one sentence, falsifiable",
 "predicts": "what the measurements should show if it holds",
 "probes": [{"measure": "entropy", "args": {}, "rationale": "why"},
            {"measure": "fanout", "args": {"attr": "qname"},
             "rationale": "why"}]}"""


INTERPRET = """You are shown a hypothesis you proposed, and the measurements
the analyser actually performed. Say what they showed.

Rules:
1. Judge your own hypothesis against the numbers. If they do not support it,
   say so plainly — "supported": false is a useful and expected answer.
2. Use only the numbers given. A measurement that was refused or declined is
   not evidence either way; treat it as absent, not as zero.
3. Do not call anything malicious. Describe the behaviour and name the
   readings consistent with it, benign ones included.
4. Cite the probe ids you relied on, copied exactly.

Answer with JSON only:

{"supported": true,
 "conclusion": "two to four sentences on what the measurements showed",
 "cited": ["entropy()@abc123", "fanout(attr=qname)@abc123"]}"""



def _why_no_json(reply: str) -> str:
    """Distinguish a truncated reply from one that was never JSON.

    Both fail `_parse`, and reporting them identically as "not JSON" sends
    the reader to inspect the prompt when the actual cause is a token cap.
    A reply that opens with `{` and does not close was cut short.
    """
    text = reply.strip()
    if not text:
        return "the model returned nothing"
    if text.startswith("{") and text.count("{") > text.count("}"):
        return (f"reply was cut off mid-JSON after {len(text)} chars — "
                f"raise the token budget")
    return "reply was not JSON"


@dataclass
class Investigation:
    """One hypothesis, the probes it asked for, and what they returned."""

    channel: str
    label: str = ""
    hypothesis: str = ""
    predicts: str = ""
    results: List[ProbeResult] = field(default_factory=list)
    supported: Optional[bool] = None
    conclusion: str = ""
    model: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def measured(self) -> List[ProbeResult]:
        return [r for r in self.results if r.measured]

    def render(self, indent: str = "  ") -> List[str]:
        """The investigation, as the report prints it.

        Deliberate ordering: hypothesis, prediction, then MEASUREMENTS, then
        the model's reading of them. The numbers sit between the claim and
        the interpretation so a reader meets the evidence before the verdict
        and can disagree with the second while keeping the first.
        """
        out = [f"{indent}channel      {self.label or self.channel}"]
        if self.hypothesis:
            out.append(f"{indent}hypothesis   {self.hypothesis}")
        if self.predicts:
            out.append(f"{indent}predicted    {self.predicts}")

        if self.results:
            out.append(f"{indent}measured     "
                       f"{len(self.measured)} of {len(self.results)} probe(s) "
                       f"returned a value")
            for result in self.results:
                out.append(f"{indent}  {result.summary()}")
                if result.probe.rationale:
                    out.append(f"{indent}      asked because: "
                               f"{result.probe.rationale}")

        if self.supported is not None:
            verdict = "SUPPORTED" if self.supported else "NOT SUPPORTED"
            out.append(f"{indent}verdict      {verdict} "
                       f"(the model's reading of the numbers above)")
        if self.conclusion:
            out.append(f"{indent}             {self.conclusion}")
        for note in self.notes:
            out.append(f"{indent}note         {note}")
        return out


def _channel_brief(series: Series, evidence: Optional[Evidence],
                   redactor) -> str:
    channel = series.channel
    where = ""
    if channel.initiator and channel.responder:
        where = f"{channel.initiator.value} -> {channel.responder.value}"
    dims = "  ".join(f"{k}={v}" for k, v in sorted(channel.dims.items()))

    lines = [
        f"CHANNEL: {channel.fingerprint}",
        f"DOMAIN: {channel.domain}",
        f"ENDPOINTS: {where}  {dims}".rstrip(),
        f"EXCHANGES: {series.count}",
        f"BYTES: {series.bytes_egress} out, {series.bytes_ingress} in",
    ]
    if series.start is not None and series.end is not None:
        lines.append(f"SPAN: {series.end - series.start:.1f} s")

    if evidence is not None:
        computed, _legal = _features(evidence, redactor)
        if computed:
            lines += ["", "ALREADY MEASURED:", *computed]
    else:
        lines += ["", "ALREADY MEASURED: nothing — this channel produced no "
                  "measurement at all"]
    return "\n".join(lines)


def investigate_channel(
    llm: LLM,
    series: Series,
    evidence: Optional[Evidence],
    ctx: Context,
    redactor=None,
    label: str = "",
) -> Investigation:
    """Propose, measure, interpret — for one channel. Never raises."""
    if redactor is None:
        from core.redact import redact_secrets
        redactor = redact_secrets

    investigation = Investigation(
        channel=series.channel.fingerprint,
        label=label,
        model=getattr(llm, "name", "unknown"),
    )

    brief = _channel_brief(series, evidence, redactor)
    propose_prompt = "\n\n".join([brief, describe_vocabulary(series)])

    try:
        # Generous budget: this answer carries a hypothesis, a prediction
        # and up to four probes with rationales, and a reply truncated
        # mid-object is indistinguishable from one that never parsed.
        reply = llm.complete(PROPOSE, propose_prompt, max_tokens=1800)
    except LLMError as error:
        investigation.notes.append(f"no hypothesis: {error}")
        return investigation

    plan = _parse(reply)
    if plan is None:
        investigation.notes.append(f"no hypothesis: {_why_no_json(reply)}")
        return investigation

    investigation.hypothesis = str(plan.get("hypothesis") or "").strip()
    investigation.predicts = str(plan.get("predicts") or "").strip()

    probes, complaints = parse_probes(
        plan.get("probes"), series.channel.fingerprint, limit=MAX_PROBES
    )
    investigation.notes.extend(complaints)
    if not probes:
        investigation.notes.append(
            "no runnable measurement was proposed, so nothing was tested"
        )
        return investigation

    # THE MEASUREMENT. No model involved; refusals carry their reason.
    investigation.results = [run_probe(p, series, ctx) for p in probes]

    # Nothing measured means there is nothing to interpret. Asking anyway
    # invites a conclusion drawn from refusals, which is the exact failure
    # this design exists to prevent.
    if not investigation.measured:
        investigation.notes.append(
            "every proposed measurement was refused or declined, so the "
            "hypothesis was not tested"
        )
        return investigation

    results_text = "\n".join(
        [f"HYPOTHESIS: {investigation.hypothesis}",
         f"YOU PREDICTED: {investigation.predicts}",
         "",
         "MEASUREMENTS PERFORMED:"]
        + [f"  {r.summary()}" for r in investigation.results]
        + ["",
           "Probe ids you may cite:"]
        + [f"  {r.probe.id}" for r in investigation.measured]
    )

    try:
        verdict_reply = llm.complete(INTERPRET, results_text,
                                     max_tokens=1200)
    except LLMError as error:
        investigation.notes.append(f"no interpretation: {error}")
        return investigation

    verdict = _parse(verdict_reply)
    if verdict is None:
        investigation.notes.append(
            f"no interpretation: {_why_no_json(verdict_reply)}")
        return investigation

    investigation.conclusion = str(verdict.get("conclusion") or "").strip()
    supported = verdict.get("supported")
    if isinstance(supported, bool):
        investigation.supported = supported
    elif isinstance(supported, str):
        investigation.supported = supported.strip().lower() in (
            "true", "yes", "supported"
        )

    # Citations are checked against the probes that actually ran, which is
    # the same discipline as Level 1 against the Evidence ledger. A
    # conclusion resting on a measurement that was refused is rejected —
    # the conclusion text is kept out rather than shown with a caveat,
    # because a caveat next to a confident sentence gets skimmed past.
    legal = {r.probe.id for r in investigation.measured}
    cited = verdict.get("cited") or []
    if isinstance(cited, str):
        cited = [cited]
    invented = [str(c) for c in cited if str(c) not in legal]
    if invented:
        investigation.notes.append(
            "conclusion discarded: cited measurements that were not "
            "performed: " + ", ".join(invented)
        )
        investigation.conclusion = ""
        investigation.supported = None

    return investigation


def investigate(
    llm: LLM,
    series: Sequence[Series],
    evidences: Sequence[Evidence],
    ctx: Context,
    redactor=None,
    targets: int = 3,
    names: Optional[Mapping[str, str]] = None,
) -> List[Investigation]:
    """Investigate the most interesting channels that produced no finding.

    TARGET SELECTION IS THE INTERESTING PART, and it is deterministic rather
    than model-chosen. The channels worth a hypothesis are the ones that
    SCORED but did not fire: a cadence of 0.77 against a 0.65 gate that
    failed the rarity conjunction is precisely the case a ruleset cannot
    report and an analyst still wants explained. Letting the model pick its
    own targets would let it select for whatever it finds easy to narrate.

    Ranked by the highest primitive score on the channel, so "nearly fired"
    comes first.
    """
    by_key = {e.channel.key: e for e in evidences}

    ranked: List[Tuple[float, Series, Optional[Evidence]]] = []
    for one in series:
        evidence = by_key.get(one.channel.key)
        if evidence is None:
            continue
        best = max(
            (r.score for r in evidence.results if r.name != "_scoring"),
            default=0.0,
        )
        ranked.append((best, one, evidence))
    ranked.sort(key=lambda item: -item[0])

    out: List[Investigation] = []
    for _score, one, evidence in ranked[:targets]:
        label = ""
        if names and one.channel.responder:
            label = names.get(one.channel.responder.value, "")
        identity = label or one.channel.fingerprint
        dims = " ".join(f"{k}={v}" for k, v in sorted(one.channel.dims.items())
                        if k not in ("proto", "dport"))
        out.append(investigate_channel(
            llm, one, evidence, ctx, redactor=redactor,
            label=f"{identity}  {dims}".strip(),
        ))
    return out
