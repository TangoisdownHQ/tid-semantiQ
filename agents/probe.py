"""Level 2: the model proposes a measurement, the tool performs it.

THE IDEA. Level 1 lets a model rephrase what was already computed. That is
useful and completely safe, but it cannot find anything. The interesting
question is whether a model can direct the ANALYSIS without being trusted to
reach a conclusion — and it can, if what it emits is a question rather than
an answer.

So a probe is a request to measure something, drawn from a closed
vocabulary. The model may say "if this were DNS tunnelling, the names under
this zone would be near-random — measure their entropy". It may not say what
the entropy is, and it may not say what the answer means until the answer
exists. The number comes from the same primitives that produce every other
number in this tool, so a probe result is auditable in exactly the same way.

WHY A CLOSED VOCABULARY AND NOT CODE. The obvious implementation is to let
the model write a filter expression or a snippet and evaluate it. That hands
arbitrary execution to a model reading attacker-controlled input — a
capture is attacker-controlled input — and the author of a crafted packet
gets to influence the prompt. Instead the model emits a primitive NAME and
arguments from a fixed set; this module validates them and constructs the
primitive itself. Nothing the model writes is ever executed, parsed as
Python, or interpolated into a query.

VALIDATION IS ALSO USEFUL, not only safe. An attribute argument is checked
against the attributes actually present in the series, so a probe for an
attribute that does not exist comes back as "this capture has no such
attribute, the ones present are ..." rather than as a silent zero. A zero
would read as "measured, found nothing", which is a different and much
stronger claim than "could not measure".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from core.model import Context, Direction, Series

__all__ = [
    "Probe",
    "ProbeResult",
    "PROBE_SPECS",
    "describe_vocabulary",
    "build_probe",
    "run_probe",
    "attributes_present",
]


#: What may be measured, and with which arguments. Keys are the names a model
#: is allowed to use; `args` names the optional arguments and `needs` the
#: mandatory ones. Anything outside this mapping is refused by name.
PROBE_SPECS: Dict[str, Dict[str, Any]] = {
    "periodicity": {
        "needs": (),
        "args": ("group_attr", "direction"),
        "asks": "how regular is the interval between exchanges",
    },
    "jitter": {
        "needs": (),
        "args": ("direction",),
        "asks": "how much deliberate randomisation is in the interval",
    },
    "burstiness": {
        "needs": (),
        "args": (),
        "asks": "are exchanges clustered or evenly spread",
    },
    "asymmetry": {
        "needs": (),
        "args": (),
        "asks": "how one-sided is the byte volume",
    },
    "entropy": {
        "needs": (),
        "args": (),
        "asks": "how random is the payload (cleartext only; declines on "
                "encrypted channels by design)",
    },
    "fanout": {
        "needs": ("attr",),
        "args": ("saturation",),
        "asks": "how many distinct values of an attribute appear",
    },
    "failure_rate": {
        "needs": ("attr",),
        "args": ("success_values", "failure_values"),
        "asks": "what share of answered exchanges reported a failure",
    },
    "group_sizes": {
        "needs": ("attr",),
        "args": (),
        "asks": "split the channel by an attribute and report group sizes",
    },
}

#: Caps. A probe plan is a suggestion from a model, so it is bounded here
#: rather than trusted to be reasonable.
MAX_PROBES = 8
MAX_VALUES = 16


@dataclass(frozen=True)
class Probe:
    """A measurement to perform, and why.

    `rationale` is the model's stated reason and is carried through to the
    output verbatim. It is prose, never acted upon — the point of printing it
    is that an analyst can disagree with the reasoning while still trusting
    the number, because the number did not come from the reasoning.
    """

    measure: str
    channel: str                      # Channel.fingerprint
    args: Mapping[str, Any] = field(default_factory=dict)
    rationale: str = ""

    @property
    def id(self) -> str:
        detail = ",".join(f"{k}={v}" for k, v in sorted(self.args.items()))
        return f"{self.measure}({detail})@{self.channel}"


@dataclass
class ProbeResult:
    probe: Probe
    #: None when the measurement could not be made. The reason is in `note`,
    #: and the distinction matters: "declined" is not "zero".
    score: Optional[float] = None
    features: Mapping[str, float] = field(default_factory=dict)
    sample_size: int = 0
    note: str = ""

    @property
    def measured(self) -> bool:
        return self.score is not None

    def summary(self) -> str:
        if not self.measured:
            return f"{self.probe.id}: not measured — {self.note}"
        bits = ", ".join(f"{k}={v:.4g}" for k, v in
                         sorted(self.features.items()))
        return (f"{self.probe.id}: score {self.score:.3f} "
                f"(n={self.sample_size}) {bits}")


def attributes_present(series: Series, limit: int = 40) -> Tuple[str, ...]:
    """Attribute names actually carried by this channel's observations.

    Offered to the model so a probe can only ask about something the capture
    contains, and used to validate the argument afterwards. Both matter: the
    first avoids wasted probes, the second makes a bad one explain itself.
    """
    names: Dict[str, None] = {}
    for obs in series:
        for key in obs.attrs:
            names.setdefault(key, None)
        if len(names) >= limit:
            break
    return tuple(sorted(names))


def describe_vocabulary(series: Optional[Series] = None) -> str:
    """The probe list, as it is shown to the model."""
    lines = ["Available measurements:"]
    for name, spec in PROBE_SPECS.items():
        needs = "".join(f" {arg}=<required>" for arg in spec["needs"])
        extra = "".join(f" [{arg}=...]" for arg in spec["args"])
        lines.append(f"  {name}{needs}{extra}")
        lines.append(f"      {spec['asks']}")
    lines.append("")
    lines.append("Argument notes:")
    lines.append("  direction     one of egress, ingress (omit for both)")
    lines.append("  attr          an attribute name carried by the channel")
    lines.append("  saturation    integer; the count treated as 'many'")
    lines.append("  success_values / failure_values  lists of strings")
    if series is not None:
        present = attributes_present(series)
        lines.append("")
        lines.append("Attributes present on this channel: "
                     + (", ".join(present) if present else "(none)"))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# construction
# --------------------------------------------------------------------------


class ProbeRefused(ValueError):
    """The probe was not constructible. Reported to the operator and fed
    back to the model, never raised past the caller."""


def _strings(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)[:MAX_VALUES]
    raise ProbeRefused(f"expected a string or list, got {type(value).__name__}")


def _direction(value: Any) -> Optional[Direction]:
    if value in (None, "", "both"):
        return None
    text = str(value).lower()
    if text == "egress":
        return Direction.EGRESS
    if text == "ingress":
        return Direction.INGRESS
    raise ProbeRefused(f"direction must be egress or ingress, got {value!r}")


def build_probe(probe: Probe, series: Series):
    """Construct the primitive a probe names, or refuse with a reason.

    THE MODEL'S STRING NEVER BECOMES CODE. It selects a key in `PROBE_SPECS`
    and supplies arguments that are each parsed and range-checked here. An
    unknown name, a missing required argument, an argument that is not in the
    spec, or an attribute the capture does not carry are all refusals with an
    explanation rather than exceptions or silent defaults.
    """
    spec = PROBE_SPECS.get(probe.measure)
    if spec is None:
        raise ProbeRefused(
            f"unknown measurement {probe.measure!r}; available: "
            + ", ".join(sorted(PROBE_SPECS))
        )

    allowed = set(spec["needs"]) | set(spec["args"])
    unknown = [key for key in probe.args if key not in allowed]
    if unknown:
        raise ProbeRefused(
            f"{probe.measure} does not take {', '.join(sorted(unknown))}; "
            f"it takes {', '.join(sorted(allowed)) or 'no arguments'}"
        )
    missing = [key for key in spec["needs"] if not probe.args.get(key)]
    if missing:
        raise ProbeRefused(
            f"{probe.measure} needs {', '.join(missing)}"
        )

    # An attribute argument is checked against what the channel actually
    # carries. Measuring a non-existent attribute returns zero, and a zero
    # reads as "looked, found nothing" — a far stronger claim than "could
    # not look".
    attr = probe.args.get("attr") or probe.args.get("group_attr")
    if attr:
        present = attributes_present(series)
        if str(attr) not in present:
            raise ProbeRefused(
                f"this channel has no attribute {attr!r}; it carries: "
                + (", ".join(present) if present else "(none)")
            )

    from core.primitives.structure import Asymmetry, Entropy, Fanout, FailureRate
    from core.primitives.timing import Burstiness, Jitter, Periodicity

    if probe.measure == "periodicity":
        return Periodicity(
            direction=_direction(probe.args.get("direction")),
            group_attr=(str(probe.args["group_attr"])
                        if probe.args.get("group_attr") else None),
        )
    if probe.measure == "jitter":
        return Jitter(direction=_direction(probe.args.get("direction")))
    if probe.measure == "burstiness":
        return Burstiness()
    if probe.measure == "asymmetry":
        return Asymmetry()
    if probe.measure == "entropy":
        return Entropy()
    if probe.measure == "fanout":
        saturation = probe.args.get("saturation", 50.0)
        try:
            saturation = float(saturation)
        except (TypeError, ValueError):
            raise ProbeRefused(f"saturation must be a number, got "
                               f"{saturation!r}") from None
        if not 1.0 <= saturation <= 10000.0:
            raise ProbeRefused("saturation must be between 1 and 10000")
        return Fanout(attr=str(probe.args["attr"]), saturation=saturation)
    if probe.measure == "failure_rate":
        success = _strings(probe.args.get("success_values"))
        failure = _strings(probe.args.get("failure_values"))
        if not success and not failure:
            raise ProbeRefused(
                "failure_rate needs success_values or failure_values, so it "
                "knows which outcomes count as failures"
            )
        return FailureRate(
            attr=str(probe.args["attr"]),
            success_values=frozenset(success),
            failure_values=frozenset(failure),
            label=f"failure_rate.{probe.args['attr']}",
        )
    raise ProbeRefused(f"{probe.measure} is listed but not constructible")


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------


def run_probe(probe: Probe, series: Series, ctx: Context) -> ProbeResult:
    """Perform one probe. Never raises.

    A probe that cannot be built, does not apply, or declines to measure all
    come back as an unmeasured result with a reason. The caller prints the
    reason, and the model is shown it too — "entropy declined because the
    channel is encrypted" is a genuinely informative answer to a reasonable
    question.
    """
    if probe.measure == "group_sizes":
        return _group_sizes(probe, series)

    try:
        primitive = build_probe(probe, series)
    except ProbeRefused as refusal:
        return ProbeResult(probe=probe, note=str(refusal))

    if not primitive.applies_to(series, ctx):
        return ProbeResult(
            probe=probe,
            note=f"{probe.measure} does not apply to this channel "
                 f"(needs more observations, a different direction, or "
                 f"cleartext payloads)",
        )
    try:
        result = primitive.compute(series, ctx)
    except Exception as error:   # noqa: BLE001 - reported, never propagated
        return ProbeResult(probe=probe,
                           note=f"{type(error).__name__}: {error}")
    if result is None:
        return ProbeResult(
            probe=probe,
            note=f"{probe.measure} declined to measure this channel",
        )
    return ProbeResult(
        probe=probe,
        score=result.score,
        features=dict(result.features),
        sample_size=result.sample_size,
        note="; ".join(result.notes),
    )


def _group_sizes(probe: Probe, series: Series) -> ProbeResult:
    """Split by an attribute and report how the observations divide.

    Not a primitive — it answers a shape question rather than producing a
    score, and `Series.group_by` already exists for it. Useful because a
    cadence measured across interleaved groups is meaningless, and this is
    how a model can find out whether grouping is needed before asking for
    the measurement.
    """
    attr = str(probe.args.get("attr") or "")
    present = attributes_present(series)
    if attr not in present:
        return ProbeResult(
            probe=probe,
            note=f"this channel has no attribute {attr!r}; it carries: "
                 + (", ".join(present) if present else "(none)"),
        )
    groups = series.group_by(attr)
    if not groups:
        return ProbeResult(probe=probe,
                           note=f"no observation carried a value for {attr!r}")
    sizes = sorted(((label, sub.count) for label, sub in groups.items()),
                   key=lambda pair: -pair[1])
    features = {f"group.{label}": float(count) for label, count in sizes[:12]}
    features["groups"] = float(len(groups))
    features["largest"] = float(sizes[0][1])
    return ProbeResult(
        probe=probe,
        # A score is required by the shape of the result, so it is the share
        # in the largest group: 1.0 means the attribute does not divide the
        # channel at all, low means it divides it finely.
        score=sizes[0][1] / max(1, series.count),
        features=features,
        sample_size=series.count,
        note=f"{len(groups)} group(s); largest {sizes[0][0]!r} "
             f"with {sizes[0][1]}",
    )


def parse_probes(data: Any, channel: str, limit: int = MAX_PROBES
                 ) -> Tuple[List[Probe], List[str]]:
    """Turn a model's JSON into Probes. Returns (probes, complaints).

    Tolerant of shape — a model will produce a bare object instead of a
    list, or name the field `measurement` instead of `measure` — but never
    tolerant of an unrecognised measurement, which `build_probe` refuses
    later with the full vocabulary in the message.
    """
    if isinstance(data, Mapping):
        data = [data]
    if not isinstance(data, (list, tuple)):
        return [], ["probe plan was not a list"]

    probes: List[Probe] = []
    complaints: List[str] = []
    for entry in data[:limit]:
        if not isinstance(entry, Mapping):
            complaints.append(f"ignored a non-object probe: {entry!r:.60}")
            continue
        measure = str(
            entry.get("measure") or entry.get("measurement") or ""
        ).strip().lower()
        if not measure:
            complaints.append("ignored a probe with no measurement named")
            continue
        args = entry.get("args") or entry.get("arguments") or {}
        if not isinstance(args, Mapping):
            complaints.append(f"ignored non-object args for {measure}")
            args = {}
        probes.append(Probe(
            measure=measure,
            channel=channel,
            args={str(k): v for k, v in args.items()},
            rationale=str(entry.get("rationale") or entry.get("why") or ""),
        ))
    if len(data) > limit:
        complaints.append(
            f"probe plan truncated to {limit}; {len(data) - limit} dropped"
        )
    return probes, complaints
