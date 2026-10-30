"""Level 2: model-proposed measurement, tool-performed.

THE BOUNDARY UNDER TEST is that nothing a model writes becomes code. It
selects a measurement NAME from a closed set and supplies arguments that are
each parsed and range-checked; this module's tests feed that boundary
unknown names, wrong argument names, missing required arguments, hostile
values and attributes the capture does not contain, and assert every one
comes back as a refusal WITH A REASON rather than an exception, a silent
default, or a zero.

The zero case is the subtle one and has its own test. Measuring an attribute
that does not exist would return "0 distinct values", which reads as
"looked, found nothing" — a far stronger claim than "could not look". So an
attribute argument is validated against the attributes actually present, and
the refusal lists them.

The two-phase loop is tested separately: a model must commit to a prediction
BEFORE any number exists, and a conclusion citing a measurement that was
refused is discarded. Asked in one call, a model states a hypothesis and its
confirmation in the same breath and the confirmation is generated rather
than measured — the split is the mechanism, not a stylistic choice.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.investigate import investigate, investigate_channel
from agents.probe import (
    PROBE_SPECS,
    Probe,
    ProbeRefused,
    attributes_present,
    build_probe,
    describe_vocabulary,
    parse_probes,
    run_probe,
)
from agents.provider import EchoLLM, LLMError
from core.model import (
    Channel,
    Context,
    Direction,
    Entity,
    Evidence,
    Locus,
    Observation,
    PrimitiveResult,
    Series,
)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def _ctx():
    return Context(now=1_700_001_000.0, mode="passive")


def _dns_series(count: int = 30, zone: str = "x.test",
                payload: bool = False) -> Series:
    channel = Channel(
        domain="dns",
        dims={"proto": "udp", "qtype": "A", "zone": zone},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "10.0.0.1"),
    )
    observations = []
    for index in range(count):
        name = f"h{index}.{zone}"
        observations.append(Observation(
            ts=1_700_000_000.0 + index * 60.0,
            channel=channel,
            direction=Direction.EGRESS,
            size=40,
            kind="dns_query",
            attrs={"qname": name, "qtype": "A", "encrypted": False,
                   "label_count": "3"},
            payload=name.encode() if payload else None,
            locus=Locus(source="t.pcap", frames=(index * 2 + 1,)),
        ))
        observations.append(Observation(
            ts=1_700_000_000.0 + index * 60.0 + 0.01,
            channel=channel,
            direction=Direction.INGRESS,
            size=90,
            kind="dns_response",
            attrs={"qname": name, "qtype": "A", "encrypted": False,
                   "rcode_name": "NXDOMAIN"},
            # Both directions carry a payload when requested: the base
            # `applies_to` requires EVERY observation to have the field, so
            # a half-populated series makes entropy decline.
            payload=name.encode() if payload else None,
            locus=Locus(source="t.pcap", frames=(index * 2 + 2,)),
        ))
    return Series(channel, observations)


def _evidence(series: Series) -> Evidence:
    result = PrimitiveResult(
        name="periodicity", score=0.77,
        features={"period_s": 60.0, "interval_mad_s": 0.0},
        sample_size=series.count, method="mad",
    )
    return Evidence(
        channel=series.channel, series_count=series.count,
        window=(series.start or 0.0, series.end or 0.0),
        results=(result,), inspections=(),
    )


def _probe(measure: str, **args) -> Probe:
    return Probe(measure=measure, channel="abc123", args=args)


# --------------------------------------------------------------------------
# the closed vocabulary
# --------------------------------------------------------------------------


def test_unknown_measurement_is_refused_with_the_vocabulary():
    series = _dns_series()
    try:
        build_probe(_probe("run_arbitrary_code"), series)
    except ProbeRefused as refusal:
        assert "unknown measurement" in str(refusal)
        # The refusal teaches the model what it may ask for next time.
        assert "periodicity" in str(refusal) and "fanout" in str(refusal)
    else:
        raise AssertionError("unknown measurement accepted")


def test_unknown_argument_is_refused():
    """A model will offer plausible-sounding arguments. Silently ignoring
    them would mean running a different measurement than the one proposed,
    while reporting the proposal."""
    series = _dns_series()
    try:
        build_probe(_probe("burstiness", window_seconds=60), series)
    except ProbeRefused as refusal:
        assert "does not take window_seconds" in str(refusal), refusal
    else:
        raise AssertionError("unknown argument accepted")


def test_missing_required_argument_is_refused():
    series = _dns_series()
    try:
        build_probe(_probe("fanout"), series)
    except ProbeRefused as refusal:
        assert "needs attr" in str(refusal), refusal
    else:
        raise AssertionError("missing argument accepted")


def test_absent_attribute_is_refused_rather_than_measured_as_zero():
    """THE SUBTLE ONE. Counting an attribute that does not exist returns
    zero, and a zero reads as "looked, found nothing" — a much stronger
    claim than "could not look"."""
    series = _dns_series()
    result = run_probe(_probe("fanout", attr="jarl"), series, _ctx())

    assert not result.measured, result
    assert "no attribute 'jarl'" in result.note, result.note
    # And it says what IS available, so the next probe can be valid.
    assert "qname" in result.note, result.note


def test_present_attributes_are_discovered_from_the_observations():
    series = _dns_series()
    present = attributes_present(series)
    assert "qname" in present and "rcode_name" in present, present
    assert "jarl" not in present


def test_direction_argument_is_validated():
    series = _dns_series()
    assert build_probe(_probe("periodicity", direction="egress"), series)
    try:
        build_probe(_probe("periodicity", direction="sideways"), series)
    except ProbeRefused as refusal:
        assert "egress or ingress" in str(refusal), refusal
    else:
        raise AssertionError("bad direction accepted")


def test_saturation_is_range_checked():
    series = _dns_series()
    assert build_probe(_probe("fanout", attr="qname", saturation=10), series)
    for bad in (0, -5, 10 ** 9, "lots"):
        try:
            build_probe(_probe("fanout", attr="qname", saturation=bad), series)
        except ProbeRefused:
            pass
        else:
            raise AssertionError(f"saturation {bad!r} accepted")


def test_failure_rate_needs_to_know_what_counts_as_failure():
    """Without either list the primitive would treat everything as success,
    reporting a healthy channel regardless of the data."""
    series = _dns_series()
    try:
        build_probe(_probe("failure_rate", attr="rcode_name"), series)
    except ProbeRefused as refusal:
        assert "success_values or failure_values" in str(refusal), refusal
    else:
        raise AssertionError("ambiguous failure_rate accepted")


def test_vocabulary_lists_the_channel_attributes():
    text = describe_vocabulary(_dns_series())
    assert "Attributes present on this channel" in text
    assert "qname" in text
    for name in PROBE_SPECS:
        assert name in text, name


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------


def test_probe_runs_a_real_primitive_and_returns_real_features():
    series = _dns_series(count=30)
    result = run_probe(_probe("fanout", attr="qname"), series, _ctx())

    assert result.measured, result.note
    # 30 distinct names across 60 observations.
    assert result.features["unique_values"] == 30.0, result.features
    assert result.sample_size == 60, result.sample_size


def test_probe_measures_cadence_the_tool_already_knows():
    """A probe must produce the same number the ordinary pipeline would —
    it is the same primitive, not a parallel implementation."""
    series = _dns_series(count=30)
    result = run_probe(
        _probe("periodicity", direction="egress"), series, _ctx()
    )
    assert result.measured, result.note
    assert abs(result.features["period_s"] - 60.0) < 1e-6, result.features


def test_declined_measurement_is_not_a_zero():
    """Entropy declines on an encrypted channel by design. The result must
    say "declined", because a 0.0 would assert the payload is not random."""
    series = _dns_series(count=4)
    for obs in series:
        obs.attrs["encrypted"] = True
    result = run_probe(_probe("entropy"), series, _ctx())

    assert not result.measured, result
    assert result.score is None
    assert "entropy" in result.note.lower(), result.note


def test_entropy_measures_cleartext_payloads_when_retained():
    series = _dns_series(count=10, payload=True)
    # Entropy needs payload bytes, which only exist under --retain-payloads.
    result = run_probe(
        _probe("entropy"), series,
        Context(now=1_700_001_000.0, mode="passive", retain_payloads=True),
    )
    assert result.measured, result.note
    assert 0.0 < result.features["bits_per_byte"] < 8.0, result.features


def test_group_sizes_reports_how_a_channel_divides():
    """A cadence measured across interleaved groups is meaningless; this is
    how a model finds out whether grouping is needed before asking."""
    series = _dns_series(count=10)
    result = run_probe(_probe("group_sizes", attr="qtype"), series, _ctx())

    assert result.measured, result.note
    assert result.features["groups"] == 1.0, result.features
    assert result.score == 1.0, result.score   # does not divide at all

    split = run_probe(_probe("group_sizes", attr="qname"), series, _ctx())
    assert split.features["groups"] == 10.0, split.features
    assert split.score < 0.3, split.score      # divides finely


def test_a_probe_never_raises():
    """A capture is attacker-controlled input and a probe plan is model
    output. Neither may crash the analyser."""
    series = _dns_series(count=3)
    for probe in (
        _probe("fanout", attr="qname", saturation=float("nan")),
        _probe("periodicity", group_attr="qname"),
        _probe("failure_rate", attr="rcode_name", success_values=[]),
        _probe("group_sizes", attr=""),
        _probe(""),
        _probe("entropy"),
    ):
        result = run_probe(probe, series, _ctx())
        assert isinstance(result.note, str)


def test_probe_id_is_stable_and_identifies_its_arguments():
    """Citations are checked against probe ids, so two probes differing only
    by argument must not collide."""
    one = _probe("fanout", attr="qname")
    two = _probe("fanout", attr="qtype")
    assert one.id != two.id
    assert "attr=qname" in one.id
    assert _probe("fanout", attr="qname").id == one.id


# --------------------------------------------------------------------------
# parsing a model's plan
# --------------------------------------------------------------------------


def test_plan_parsing_tolerates_shape_but_not_unknown_measurements():
    probes, complaints = parse_probes(
        [{"measure": "entropy", "args": {}},
         {"measurement": "fanout", "arguments": {"attr": "qname"},
          "why": "cardinality"},
         "nonsense",
         {"args": {}}],
        channel="abc",
    )
    assert [p.measure for p in probes] == ["entropy", "fanout"], probes
    assert probes[1].rationale == "cardinality"
    assert len(complaints) == 2, complaints


def test_a_single_probe_object_is_accepted():
    probes, _complaints = parse_probes(
        {"measure": "burstiness", "args": {}}, channel="abc"
    )
    assert len(probes) == 1


def test_plan_is_capped():
    probes, complaints = parse_probes(
        [{"measure": "burstiness"} for _ in range(50)], channel="abc", limit=4
    )
    assert len(probes) == 4
    assert any("truncated" in c for c in complaints), complaints


# --------------------------------------------------------------------------
# the two-phase loop
# --------------------------------------------------------------------------


class _Scripted:
    """Returns a prepared reply per call, and records the prompts."""

    name = "scripted"

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts = []

    def complete(self, system, prompt, max_tokens=1200, temperature=0.2):
        self.prompts.append((system, prompt))
        if not self.replies:
            raise LLMError("no more scripted replies")
        return self.replies.pop(0)


def test_hypothesis_is_committed_before_any_number_exists():
    """The mechanism. The proposal prompt must contain no probe RESULTS —
    asked in one call, a model states a hypothesis and its confirmation
    together and the confirmation is generated rather than measured."""
    series = _dns_series(count=30)
    llm = _Scripted(
        json.dumps({"hypothesis": "These names are generated.",
                    "predicts": "high cardinality",
                    "probes": [{"measure": "fanout",
                                "args": {"attr": "qname"},
                                "rationale": "count distinct names"}]}),
        json.dumps({"supported": True, "conclusion": "Cardinality is high.",
                    "cited": ["fanout(attr=qname)@"
                              + series.channel.fingerprint]}),
    )
    run = investigate_channel(llm, series, _evidence(series), _ctx())

    propose_prompt = llm.prompts[0][1]
    assert "unique_values" not in propose_prompt, propose_prompt
    assert "score" not in propose_prompt.split("ALREADY MEASURED")[0]

    # The second call does carry the measured numbers.
    interpret_prompt = llm.prompts[1][1]
    assert "unique_values=30" in interpret_prompt, interpret_prompt
    assert "YOU PREDICTED" in interpret_prompt

    assert run.supported is True
    assert run.conclusion == "Cardinality is high."
    assert len(run.measured) == 1


def test_conclusion_citing_an_unperformed_measurement_is_discarded():
    """Same discipline as Level 1, against the probes that actually ran."""
    series = _dns_series(count=30)
    llm = _Scripted(
        json.dumps({"hypothesis": "h", "predicts": "p",
                    "probes": [{"measure": "fanout",
                                "args": {"attr": "qname"}}]}),
        json.dumps({"supported": True, "conclusion": "Definitely a tunnel.",
                    "cited": ["entropy()@" + series.channel.fingerprint]}),
    )
    run = investigate_channel(llm, series, _evidence(series), _ctx())

    assert run.conclusion == "", run.conclusion
    assert run.supported is None
    assert any("not performed" in note for note in run.notes), run.notes


def test_unsupported_hypothesis_is_a_real_outcome():
    """A hypothesis the numbers contradict is a useful output and must be
    reported as such, not quietly dropped."""
    series = _dns_series(count=30)
    llm = _Scripted(
        json.dumps({"hypothesis": "Payload is encrypted.", "predicts": "high entropy",
                    "probes": [{"measure": "fanout",
                                "args": {"attr": "qname"}}]}),
        json.dumps({"supported": False,
                    "conclusion": "Cardinality alone does not show this.",
                    "cited": []}),
    )
    run = investigate_channel(llm, series, _evidence(series), _ctx())

    assert run.supported is False
    assert "does not show" in run.conclusion
    rendered = "\n".join(run.render())
    assert "NOT SUPPORTED" in rendered, rendered


def test_no_interpretation_is_requested_when_nothing_was_measured():
    """Interpreting refusals invites a conclusion drawn from absence, which
    is the exact failure this design prevents."""
    series = _dns_series(count=30)
    llm = _Scripted(
        json.dumps({"hypothesis": "h", "predicts": "p",
                    "probes": [{"measure": "fanout", "args": {"attr": "nope"}}]}),
    )
    run = investigate_channel(llm, series, _evidence(series), _ctx())

    assert len(llm.prompts) == 1, "should not have asked for a verdict"
    assert run.conclusion == ""
    assert any("not tested" in note for note in run.notes), run.notes


def test_refusals_are_shown_in_the_render_not_hidden():
    series = _dns_series(count=30)
    llm = _Scripted(
        json.dumps({"hypothesis": "h", "predicts": "p", "probes": [
            {"measure": "fanout", "args": {"attr": "qname"}},
            {"measure": "fanout", "args": {"attr": "missing"}},
        ]}),
        json.dumps({"supported": True, "conclusion": "c", "cited": []}),
    )
    run = investigate_channel(llm, series, _evidence(series), _ctx())
    rendered = "\n".join(run.render())

    assert "1 of 2 probe(s) returned a value" in rendered, rendered
    assert "not measured" in rendered, rendered


def test_backend_failure_leaves_an_empty_investigation():
    class Dead:
        name = "dead"

        def complete(self, system, prompt, max_tokens=1200, temperature=0.2):
            raise LLMError("connection refused")

    series = _dns_series()
    run = investigate_channel(Dead(), series, _evidence(series), _ctx())
    assert run.hypothesis == ""
    assert any("connection refused" in note for note in run.notes), run.notes


def test_non_json_proposal_is_reported():
    series = _dns_series()
    run = investigate_channel(EchoLLM("I think this is a beacon!"), series,
                              _evidence(series), _ctx())
    assert any("not JSON" in note for note in run.notes), run.notes


def test_targets_are_chosen_by_score_not_by_the_model():
    """Letting the model pick its own targets would let it select for
    whatever it finds easy to narrate. Ranked by highest primitive score, so
    "nearly fired" comes first."""
    quiet = _dns_series(count=8, zone="quiet.test")
    loud = _dns_series(count=30, zone="loud.test")

    def evidence_with(series, score):
        result = PrimitiveResult(
            name="periodicity", score=score, features={"period_s": 60.0},
            sample_size=series.count, method="mad",
        )
        return Evidence(channel=series.channel, series_count=series.count,
                        window=(0.0, 1.0), results=(result,), inspections=())

    llm = EchoLLM(json.dumps({"hypothesis": "h", "predicts": "p",
                              "probes": []}))
    runs = investigate(
        llm, [quiet, loud],
        [evidence_with(quiet, 0.2), evidence_with(loud, 0.9)],
        _ctx(), targets=1,
    )
    assert len(runs) == 1
    assert runs[0].channel == loud.channel.fingerprint, runs[0].channel


def test_investigation_does_not_create_findings():
    """Level 2 produces an Investigation — a report of questions asked and
    answers measured. Nothing here feeds the scorer."""
    series = _dns_series(count=30)
    llm = _Scripted(
        json.dumps({"hypothesis": "h", "predicts": "p",
                    "probes": [{"measure": "fanout",
                                "args": {"attr": "qname"}}]}),
        json.dumps({"supported": True, "conclusion": "c", "cited": []}),
    )
    run = investigate_channel(llm, series, _evidence(series), _ctx())

    from core.model import Finding
    assert not isinstance(run, Finding)
    assert not hasattr(run, "confidence")
    assert not hasattr(run, "severity")


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
