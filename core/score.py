"""Evidence -> Finding. The only place a verdict is produced.

An ontology rule names a behaviour, states which primitive outputs must hold
for it to apply, and how to weigh them into a confidence. The scorer evaluates
rules against `Evidence` and emits frozen `Finding`s. Nothing downstream may
change a confidence, a severity, or a title — see invariant I2 in
docs/SPEC-observation.md.

WHY RULES ARE DATA AND NOT CODE PATHS. Every domain beyond the first is
onboarded by writing rules, not by editing the engine. A rule that needs a
new branch in this file is a signal that the primitive set was wrong, which is
information worth having early.

Rules are Python literals so they are type-checked and unit-testable, with an
optional loader for JSON (stdlib) or YAML (if PyYAML is present) so operators
can edit rulesets without touching the package — the same posture as the
SOC's live-tunable detection settings.
"""

from __future__ import annotations

import json
import operator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from core.model import (
    Context,
    Evidence,
    Finding,
    PrimitiveResult,
    Series,
    Severity,
    severity_rank,
)
from core.correlate import run_correlators
from core.inspect import fold, run_inspectors
from core.primitives import stack_for
from correlators import correlators_for
from inspectors import inspectors_for

__all__ = ["Condition", "Boost", "Rule", "Ontology", "analyse_series",
           "score_series", "run"]


_OPS: Mapping[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
}


# --------------------------------------------------------------------------
# rule model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Condition:
    """A threshold on one primitive's score, or on one of its features.

        Condition("periodicity", ">=", 0.65)
        Condition("asymmetry", ">=", 0.5, feature="asymmetry")

    A condition over a primitive that produced no result is UNMET, never
    vacuously true. Absent evidence must not satisfy a requirement — that is
    the difference between "we checked and it held" and "we did not check".
    """

    primitive: str
    op: str
    value: float
    feature: Optional[str] = None

    def __post_init__(self) -> None:
        if self.op not in _OPS:
            raise ValueError(f"unknown operator {self.op!r}")

    def evaluate(self, evidence: Evidence) -> bool:
        result = evidence.by_name(self.primitive)
        if result is None:
            return False
        if self.feature is None:
            observed: Optional[float] = result.score
        else:
            observed = result.features.get(self.feature)
            if observed is None:
                return False
        return _OPS[self.op](observed, self.value)

    def describe(self) -> str:
        target = f"{self.primitive}.{self.feature}" if self.feature else self.primitive
        return f"{target} {self.op} {self.value:g}"


@dataclass(frozen=True)
class Boost:
    """A bounded confidence adjustment with a stated reason.

    Boosts exist so corroborating-but-not-required evidence can move
    confidence without becoming a gate. `because` is mandatory: an adjustment
    nobody can explain is an adjustment nobody can defend to an analyst, and
    the string is carried into the evidence trail.
    """

    when: Condition
    add: float
    because: str

    def __post_init__(self) -> None:
        if not self.because.strip():
            raise ValueError("a boost must state why")
        if abs(self.add) > 0.25:
            raise ValueError(f"boost {self.add} too large; keep adjustments bounded")


@dataclass(frozen=True)
class Rule:
    """One named behaviour.

    `require`  — all must hold, or the rule does not fire at all.
    `weigh`    — primitive name -> weight, combined into confidence.
    `boosts`   — optional bounded adjustments.

    Weights are renormalised over the primitives that actually produced a
    result, so a rule does not silently lose confidence because an optional
    primitive was inapplicable. Required primitives are enforced by
    `require`, which is the right place for "this must be present".
    """

    id: str
    title: str
    severity: Severity
    require: Tuple[Condition, ...] = ()
    weigh: Mapping[str, float] = field(default_factory=dict)
    boosts: Tuple[Boost, ...] = ()
    refs: Tuple[str, ...] = ()
    #: Rule ids this one subsumes. When both fire, only this one is reported.
    #:
    #: Rules are deliberately not mutually exclusive — one channel really can
    #: be both a periodic callback and an asymmetric transfer, and merging
    #: those would lose the second. But a SPECIFIC rule and the GENERAL rule
    #: it refines are not two findings: "sensitive cookie scoped to all
    #: subdomains" and "cookie missing protections" are one defect reported
    #: twice, and a triager reading both learns nothing from the second.
    supersedes: Tuple[str, ...] = ()
    #: confidence below which the finding is discarded rather than reported.
    #: The single most important knob for operator trust.
    min_confidence: float = 0.5

    def applies(self, evidence: Evidence) -> bool:
        return all(c.evaluate(evidence) for c in self.require)

    def cited_names(self) -> Tuple[str, ...]:
        """Every evidence name this rule looks at, in a stable order."""
        names = [c.primitive for c in self.require]
        names += list(self.weigh)
        names += [b.when.primitive for b in self.boosts]
        seen, ordered = set(), []
        for name in names:
            if name not in seen:
                seen.add(name)
                ordered.append(name)
        return tuple(ordered)

    def confidence(self, evidence: Evidence) -> Tuple[float, Tuple[str, ...]]:
        """Weighted mean of the weighed primitives' scores, plus boosts.

        Returns (confidence, rationale lines). The rationale is a plain
        arithmetic trail — not prose — so the number can be audited without
        trusting anything that generated text.
        """
        rationale: List[str] = []
        total_weight = 0.0
        accumulated = 0.0

        for name, weight in sorted(self.weigh.items()):
            result = evidence.by_name(name)
            if result is None:
                rationale.append(f"{name}: no result, weight {weight:g} dropped")
                continue
            total_weight += weight
            accumulated += weight * result.score
            rationale.append(f"{name}={result.score:.3f} x {weight:g}")

        if total_weight <= 0:
            return 0.0, tuple(rationale + ["no weighed evidence present"])

        confidence = accumulated / total_weight
        rationale.append(f"weighted mean = {confidence:.3f}")

        for boost in self.boosts:
            if boost.when.evaluate(evidence):
                confidence += boost.add
                rationale.append(
                    f"{boost.add:+.3f} ({boost.because}; {boost.when.describe()})"
                )

        confidence = max(0.0, min(1.0, confidence))
        rationale.append(f"final = {confidence:.3f}")
        return confidence, tuple(rationale)


@dataclass(frozen=True)
class Ontology:
    domain: str
    rules: Tuple[Rule, ...]

    def evaluate(self, evidence: Evidence, series: Series) -> List[Finding]:
        """Every rule that fires, highest severity then confidence first.

        Rules are NOT mutually exclusive. One channel can be both a periodic
        callback and a strongly asymmetric transfer, and collapsing those
        into one finding would lose the second. Deduplication, if wanted, is
        a reporting decision.
        """
        findings: List[Finding] = []
        for rule in self.rules:
            if not rule.applies(evidence):
                continue
            confidence, rationale = rule.confidence(evidence)
            if confidence < rule.min_confidence:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    channel=evidence.channel,
                    severity=rule.severity,
                    confidence=confidence,
                    evidence=Evidence(
                        channel=evidence.channel,
                        series_count=evidence.series_count,
                        window=evidence.window,
                        inspections=evidence.inspections,
                        # The arithmetic trail rides along as a pseudo-result
                        # so `--out json` and the SOC event both carry how
                        # the number was reached, not just the number.
                        results=evidence.results + (
                            PrimitiveResult(
                                name="_scoring",
                                score=confidence,
                                features={},
                                sample_size=len(rule.weigh),
                                method=rule.id,
                                notes=rationale,
                            ),
                        ),
                    ),
                    refs=rule.refs,
                    display_filter=series.display_filter(),
                    reference=series.reference(),
                    cited=rule.cited_names(),
                )
            )
        superseded = {
            victim
            for rule in self.rules
            for victim in rule.supersedes
            if any(f.rule_id == rule.id for f in findings)
        }
        findings = [f for f in findings if f.rule_id not in superseded]

        findings.sort(key=lambda f: (severity_rank(f.severity), f.confidence), reverse=True)
        return findings


# --------------------------------------------------------------------------
# optional external rulesets
# --------------------------------------------------------------------------


def load_ontology(path: Path) -> Ontology:
    """Load a ruleset from JSON (stdlib) or YAML (if PyYAML is installed).

    Kept optional on purpose: `core/` has no third-party dependency, so the
    built-in Python rulesets always work on a bare interpreter and external
    files are a convenience for operators.
    """
    text = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                f"{path.name} needs PyYAML; convert it to JSON or install PyYAML"
            ) from exc
        raw = yaml.safe_load(text)
    else:
        raw = json.loads(text)

    def cond(spec: Mapping[str, Any]) -> Condition:
        return Condition(
            primitive=spec["primitive"],
            op=spec.get("op", ">="),
            value=float(spec["value"]),
            feature=spec.get("feature"),
        )

    rules = tuple(
        Rule(
            id=r["id"],
            title=r["title"],
            severity=Severity(r.get("severity", "medium")),
            require=tuple(cond(c) for c in r.get("require", ())),
            weigh={k: float(v) for k, v in r.get("weigh", {}).items()},
            boosts=tuple(
                Boost(when=cond(b["when"]), add=float(b["add"]), because=b["because"])
                for b in r.get("boosts", ())
            ),
            refs=tuple(r.get("refs", ())),
            min_confidence=float(r.get("min_confidence", 0.5)),
        )
        for r in raw["rules"]
    )
    return Ontology(domain=raw["domain"], rules=rules)


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------


def analyse_series(series: Series, ctx: Context) -> Evidence:
    """Primitives and inspectors over one Series. No rules, no verdict.

    Split out from scoring because correlation sits between them: a
    correlator needs every channel's observations before any rule runs, and a
    rule may require a correlation result. So the pipeline is
    analyse-all -> correlate -> score-all, not analyse-and-score per channel.
    """
    results: List[PrimitiveResult] = []
    for primitive in stack_for(series.channel.domain):
        result = primitive.run(series, ctx)
        if result is not None:
            results.append(result)

    # Inspectors run per message and are folded by name, so a cookie flag
    # that is wrong on every response in the capture becomes one finding
    # with a count rather than hundreds of duplicates.
    inspections = run_inspectors(
        series.observations, inspectors_for(series.channel.domain), ctx
    )

    return Evidence(
        channel=series.channel,
        series_count=series.count,
        window=(series.start or 0.0, series.end or 0.0),
        results=tuple(results),
        inspections=inspections,
    )


def score_series(series: Series, ontology: Ontology, ctx: Context) -> Tuple[Evidence, List[Finding]]:
    """Analyse one Series and evaluate its rules.

    Single-channel convenience, used by tests and by callers that have no
    cross-channel question. `run()` is the full pipeline and is what the CLI
    calls — correlation findings are unavailable here by construction.
    """
    evidence = analyse_series(series, ctx)
    return evidence, ontology.evaluate(evidence, series)


def _merge(evidence: Evidence, extra: Sequence) -> Evidence:
    """Fold correlation results into a channel's evidence.

    Re-folds by name so a correlator emitting several results for one channel
    collapses the same way an inspector's would.
    """
    if not extra:
        return evidence
    return Evidence(
        channel=evidence.channel,
        series_count=evidence.series_count,
        window=evidence.window,
        results=evidence.results,
        inspections=fold(list(evidence.inspections) + list(extra)),
    )


def run(
    all_series: Iterable[Series],
    ontologies: Mapping[str, Ontology],
    ctx: Context,
    record: bool = True,
) -> Tuple[List[Finding], List[Evidence]]:
    """The full pipeline: analyse every channel, correlate across them, score.

    Three phases, in this order for a reason:

      1. analyse   primitives + inspectors per channel
      2. correlate relationships between channels, attributed back to one
      3. score     rules over the merged evidence

    Correlation cannot run first (it needs observations grouped by channel)
    and cannot run last (a rule may require its output), so scoring waits for
    every channel to be analysed. That is a real barrier, and the reason the
    whole capture is held in memory.

    Baseline recording happens AFTER scoring, so a channel is never counted
    as evidence of its own prevalence on the run that discovered it — a
    subtle self-defeat that would make `rarity` useless on first contact.

    `record=False` is for STREAMING. A sliding window re-emits the same
    observations every window, so recording each emission would multiply a
    channel's history by the number of windows it survived and make
    `rarity.prevalence` meaningless. A streaming run should be given a
    baseline warmed by a batch pass instead.
    """
    series_list = list(all_series)

    # 1 — per-channel analysis
    analysed: List[Tuple[Series, Evidence]] = []
    for series in series_list:
        if series.channel.domain not in ontologies:
            continue
        analysed.append((series, analyse_series(series, ctx)))

    # 2 — cross-channel correlation
    domains = sorted({s.channel.domain for s, _ in analysed})
    extra = run_correlators(
        [s for s, _ in analysed], correlators_for(domains), ctx
    )

    # 3 — rules over merged evidence
    findings: List[Finding] = []
    evidences: List[Evidence] = []
    for series, evidence in analysed:
        merged = _merge(evidence, extra.get(series.channel.key, ()))
        evidences.append(merged)
        findings.extend(ontologies[series.channel.domain].evaluate(merged, series))
        if record and ctx.baseline is not None:
            ctx.baseline.record(series)

    findings.sort(key=lambda f: (severity_rank(f.severity), f.confidence), reverse=True)
    return findings, evidences
