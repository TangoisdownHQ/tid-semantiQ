"""Model-assisted explanation, and the checks that make it safe.

THE TESTS THAT MATTER HERE ARE THE REJECTION TESTS. A prompt asking a model
not to invent numbers is a request; `Narrative.verify_against()` is what
makes it an invariant. So most of this file feeds the pipeline deliberately
bad answers — a fabricated measurement, a measurement that exists but
belongs to another finding, prose instead of JSON, a dead backend — and
asserts that each one is discarded, reported, and leaves the computed report
untouched.

The one thing a model is allowed to do is rephrase computed values. It
cannot create a `Finding` (frozen, and only `core/score.py` constructs one),
cannot change a confidence, and cannot cite anything that was not measured.
These tests are the enforcement of that, not a demonstration of it.

No network is used. `EchoLLM` returns whatever reply a test hands it, which
is exactly the control needed to test the verifier.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.explain import SYSTEM, explain_capture, explain_findings
from agents.provider import (
    PROVIDERS,
    REMOTE_PROVIDERS,
    EchoLLM,
    LLMError,
    build,
)
from core.model import (
    Channel,
    Entity,
    Evidence,
    Finding,
    InspectionResult,
    PrimitiveResult,
    Severity,
)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def _finding(with_inspection: bool = False) -> Finding:
    channel = Channel(
        domain="net",
        dims={"proto": "tcp", "dport": "443", "sni": "cdn.example.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "203.0.113.9"),
    )
    periodicity = PrimitiveResult(
        name="periodicity", score=0.77,
        features={"period_s": 54.2, "interval_mad_s": 4.1,
                  "observations": 40.0},
        sample_size=40, method="mad",
    )
    rarity = PrimitiveResult(
        name="rarity", score=0.9,
        features={"prevalence": 0.003, "age_s": 120.0},
        sample_size=40, method="baseline",
    )
    inspections = ()
    if with_inspection:
        inspections = (
            InspectionResult(
                name="auth.cookie_security", score=0.8,
                facts={"cookie.name": "session",
                       "cookie.value": "SUPERSECRETVALUE"},
                secret_facts=("cookie.value",),
                occurrences=3,
            ),
        )
    evidence = Evidence(
        channel=channel, series_count=40, window=(0.0, 100.0),
        results=(periodicity, rarity), inspections=inspections,
    )
    return Finding(
        rule_id="net.beacon.periodic_callback",
        title="Periodic outbound callback to an uncommon destination",
        channel=channel, severity=Severity.HIGH, confidence=0.82,
        evidence=evidence,
        cited=("periodicity", "rarity") + (
            ("auth.cookie_security",) if with_inspection else ()
        ),
    )


def _reply(summary="A regular callback.", reasoning="Because numbers.",
           cited=()) -> str:
    return json.dumps({"summary": summary, "reasoning": reasoning,
                       "cited": list(cited)})


# --------------------------------------------------------------------------
# the happy path
# --------------------------------------------------------------------------


def test_verified_narrative_is_kept():
    llm = EchoLLM(_reply(cited=["periodicity.period_s", "rarity.prevalence"]))
    finding = _finding()
    result = explain_findings(llm, [finding])

    assert result.ok == 1, result.rejected
    narrative = result.narratives[finding.id]
    assert narrative.summary == "A regular callback."
    assert narrative.model == "echo"
    assert not result.rejected, result.rejected


def test_narrative_with_no_citations_is_allowed():
    """A summary that leans on nothing specific cites nothing. That is
    honest, not suspicious — the check exists to catch fabricated numbers,
    not to require them."""
    llm = EchoLLM(_reply(cited=[]))
    result = explain_findings(llm, [_finding()])
    assert result.ok == 1, result.rejected


def test_prompt_contains_the_computed_features():
    llm = EchoLLM(_reply(cited=["periodicity.period_s"]))
    explain_findings(llm, [_finding()])

    _system, prompt = llm.calls[0]
    assert "periodicity.period_s = 54.2" in prompt, prompt
    assert "rarity.prevalence = 0.003" in prompt, prompt
    assert "net.beacon.periodic_callback" in prompt, prompt


# --------------------------------------------------------------------------
# rejection — the point of the exercise
# --------------------------------------------------------------------------


def test_fabricated_measurement_is_rejected():
    """The load-bearing check. A model citing a feature that was never
    computed has its whole answer discarded."""
    llm = EchoLLM(_reply(cited=["periodicity.period_s",
                                "entropy.bits_per_byte"]))
    result = explain_findings(llm, [_finding()])

    assert result.ok == 0, result.narratives
    assert len(result.rejected) == 1
    _subject, reason = result.rejected[0]
    assert "never computed" in reason, reason
    assert "entropy.bits_per_byte" in reason, reason


def test_citation_outside_this_finding_is_rejected():
    """A measurement can exist in the Evidence and still not be one this
    finding rested on. Accepting it would let an explanation lean on a
    number the verdict never used."""
    finding = _finding(with_inspection=True)
    # jitter is not in this Evidence at all; use the inspection, which is in
    # the Evidence but excluded from a finding that did not cite it.
    narrow = Finding(
        rule_id=finding.rule_id, title=finding.title, channel=finding.channel,
        severity=finding.severity, confidence=finding.confidence,
        evidence=finding.evidence,
        cited=("periodicity",),           # rarity deliberately not cited
    )
    llm = EchoLLM(_reply(cited=["rarity.prevalence"]))
    result = explain_findings(llm, [narrow])

    assert result.ok == 0, result.narratives
    _subject, reason = result.rejected[0]
    assert "outside this finding" in reason, reason


def test_non_json_reply_is_rejected():
    llm = EchoLLM("Sure! Here is my analysis: this looks like a beacon.")
    result = explain_findings(llm, [_finding()])

    assert result.ok == 0
    assert "not JSON" in result.rejected[0][1], result.rejected


def test_reply_with_no_summary_is_rejected():
    llm = EchoLLM(json.dumps({"reasoning": "words", "cited": []}))
    result = explain_findings(llm, [_finding()])
    assert result.ok == 0
    assert "no summary" in result.rejected[0][1], result.rejected


def test_fenced_json_is_still_parsed():
    """Models wrap JSON in code fences constantly. Rejecting that would
    discard correct answers for a formatting habit."""
    llm = EchoLLM("```json\n" + _reply(cited=["rarity.age_s"]) + "\n```")
    result = explain_findings(llm, [_finding()])
    assert result.ok == 1, result.rejected


def test_backend_failure_degrades_to_computed_output():
    """A tool that breaks because a GPU was busy is worse than one that
    stays quiet."""
    class Dead:
        name = "dead"

        def complete(self, system, prompt, max_tokens=1200,
                     temperature=0.2):
            raise LLMError("connection refused")

    result = explain_findings(Dead(), [_finding(), _finding()])
    assert result.ok == 0
    assert len(result.rejected) == 1, "should stop after the first failure"
    assert "connection refused" in result.rejected[0][1]


def test_rejections_are_reported_not_swallowed():
    """A silently dropped explanation looks like a model with nothing to
    say, which is far more comforting than one that invented a number."""
    llm = EchoLLM(_reply(cited=["made.up"]))
    result = explain_findings(llm, [_finding()])
    notes = result.notes()
    assert notes and "discarded" in notes[0], notes


# --------------------------------------------------------------------------
# secrets
# --------------------------------------------------------------------------


def test_secrets_are_redacted_before_the_prompt_is_built():
    """Not before display — before the prompt exists. A redaction applied
    after the model has read the token protects nobody."""
    llm = EchoLLM(_reply(cited=[]))
    explain_findings(llm, [_finding(with_inspection=True)])

    _system, prompt = llm.calls[0]
    assert "SUPERSECRETVALUE" not in prompt, prompt
    # The non-secret fact is still there to be explained.
    assert "cookie.name" in prompt, prompt


def test_no_payload_bytes_reach_the_prompt():
    """The prompt carries computed values only. If a number is not in the
    Evidence the model cannot cite it, so there is no reason to show it."""
    llm = EchoLLM(_reply(cited=[]))
    explain_findings(llm, [_finding(with_inspection=True)])
    _system, prompt = llm.calls[0]

    for forbidden in ("payload", "\\x", "raw bytes"):
        assert forbidden not in prompt.lower(), forbidden


# --------------------------------------------------------------------------
# the model is not permitted to be the analyser
# --------------------------------------------------------------------------


def test_system_prompt_forbids_verdicts():
    assert "not the analyser" in SYSTEM
    assert "malicious" in SYSTEM


def test_explaining_cannot_create_or_alter_findings():
    """Invariant I2. `Finding` is frozen and only the scorer builds one, so
    this asserts the type refuses mutation rather than trusting the prompt."""
    import dataclasses

    finding = _finding()
    llm = EchoLLM(_reply(cited=[]))
    before = (finding.confidence, finding.severity, finding.rule_id)
    explain_findings(llm, [finding])

    assert (finding.confidence, finding.severity, finding.rule_id) == before
    try:
        object.__setattr__  # noqa: B018 - presence check only
        finding.confidence = 0.99
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("Finding was mutable")


def test_explain_limit_caps_cost_and_says_so():
    llm = EchoLLM(_reply(cited=[]))
    findings = [_finding() for _ in range(5)]
    result = explain_findings(llm, findings, limit=2)

    assert result.ok <= 2, result.narratives
    assert any("further finding" in reason
               for _subject, reason in result.rejected), result.rejected


# --------------------------------------------------------------------------
# capture-level summary
# --------------------------------------------------------------------------


def test_capture_summary_is_produced_from_the_report():
    llm = EchoLLM(_reply(summary="One host browsed the web."))
    narrative, error = explain_capture(llm, "── CAPTURE ──\n  frames 100")

    assert error is None, error
    assert narrative is not None
    assert narrative.summary == "One host browsed the web."
    _system, prompt = llm.calls[0]
    assert "── CAPTURE ──" in prompt, prompt


def test_capture_summary_failure_is_returned_not_raised():
    class Dead:
        name = "dead"

        def complete(self, system, prompt, max_tokens=1200, temperature=0.2):
            raise LLMError("timeout")

    narrative, error = explain_capture(Dead(), "report")
    assert narrative is None
    assert "timeout" in error


def test_long_report_is_truncated_and_says_so():
    llm = EchoLLM(_reply())
    explain_capture(llm, "x" * 50000)
    _system, prompt = llm.calls[0]
    assert "truncated" in prompt, prompt[-200:]


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------


def test_default_provider_is_local():
    """A capture contains credentials and internal hostnames. The default
    must not send them anywhere."""
    assert "ollama" in PROVIDERS
    assert "ollama" not in REMOTE_PROVIDERS
    local = build("ollama")
    assert local.name.startswith("ollama/")
    assert "127.0.0.1" in local.url, local.url


def test_remote_providers_are_labelled_as_remote():
    """So the CLI can warn once, loudly, instead of leaving the operator to
    infer where their data went."""
    assert REMOTE_PROVIDERS == {"openai", "huggingface"}, REMOTE_PROVIDERS


def test_openai_backend_accepts_any_base_url():
    """The extension point: a new model should need a URL and a key, not new
    code."""
    llm = build("openai", model="llama-3.3-70b",
                url="http://127.0.0.1:8000/v1", api_key="local")
    assert llm.url == "http://127.0.0.1:8000/v1"
    assert llm.name == "openai/llama-3.3-70b"


def test_huggingface_requires_a_token():
    import os

    saved = {key: os.environ.pop(key, None)
             for key in ("HF_TOKEN", "HUGGINGFACE_API_KEY")}
    try:
        raised = False
        try:
            build("huggingface")
        except LLMError as error:
            raised = True
            assert "HF_TOKEN" in str(error), error
        assert raised, "missing token should be reported, not silently used"

        # And with a token it builds, pointed at the router.
        llm = build("huggingface", api_key="hf_test")
        assert "router.huggingface.co" in llm.url, llm.url
        assert llm.name.startswith("hf/"), llm.name
    finally:
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value


def test_unknown_provider_lists_the_known_ones():
    try:
        build("gpt-nine")
    except LLMError as error:
        assert "ollama" in str(error) and "huggingface" in str(error), error
    else:
        raise AssertionError("unknown provider accepted")


def test_nothing_in_the_analysis_imports_agents():
    """The analysis must be byte-identical with or without a model. If a
    core module grows an `agents` import, that stops being true."""
    import subprocess

    out = subprocess.run(
        ["grep", "-rn", "import agents", "core/", "capture/", "inspectors/",
         "correlators/", "out/", "ontology/"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    assert not out.stdout.strip(), out.stdout


def test_dotted_measurement_names_verify_correctly():
    """REGRESSION, and the local model found it.

    `verify_against` split a citation on the FIRST dot, but measurement
    names contain dots: `fanout.qname`, `failure_rate.rcode`,
    `auth.cookie_security`. So `failure_rate.rcode.failure_share` was read
    as the primitive `failure_rate` with a feature `rcode.failure_share`,
    which exists nowhere — and every correctly-cited explanation of a
    dotted-name measurement was rejected as fabricated.

    Dotted names are the majority: every inspector and every parameterised
    primitive has one. A verifier that rejects true statements is worse than
    no verifier, because it teaches the reader to ignore it.
    """
    from core.model import Narrative

    channel = Channel(
        domain="dns", dims={"zone": "x.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "10.0.0.1"),
    )
    result = PrimitiveResult(
        name="failure_rate.rcode", score=0.99,
        features={"failure_share": 1.0, "answered": 422.0},
        sample_size=422, method="wilson-lower-95/rcode_name",
    )
    fanout = PrimitiveResult(
        name="fanout.qname", score=0.5,
        features={"unique_values": 63.0}, sample_size=126, method="count",
    )
    evidence = Evidence(
        channel=channel, series_count=422, window=(0.0, 1.0),
        results=(result, fanout), inspections=(),
    )

    good = Narrative("f", "s", "r", (
        "failure_rate.rcode.failure_share",
        "failure_rate.rcode.answered",
        "fanout.qname.unique_values",
    ), "test")
    ok, unknown = good.verify_against(evidence)
    assert ok, unknown

    # And a genuinely fabricated feature on a dotted name is still caught.
    bad = Narrative("f", "s", "r", ("failure_rate.rcode.invented",), "test")
    ok, unknown = bad.verify_against(evidence)
    assert not ok and unknown == ("failure_rate.rcode.invented",), unknown

    # A bare name with no feature at all is not a citation.
    bare = Narrative("f", "s", "r", ("periodicity",), "test")
    assert not bare.verify_against(evidence)[0]

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
