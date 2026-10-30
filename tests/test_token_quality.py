"""Session token quality.

The important tests here are the NEGATIVE ones. Flagging a sequential counter
is easy; the hard part is not condemning a strong token because only twelve
samples were available, and not claiming an entropy figure that the sample
size cannot support. `test_strong_token_is_not_flagged` and
`test_entropy_is_never_claimed_beyond_the_sample_ceiling` are what keep this
analysis honest.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.har import HarSource
from core.baseline import NullBaseline
from core.model import Context
from core.score import run
from correlators.tokens import (
    MIN_SAMPLES,
    SessionTokenQuality,
    decoded_structure,
    positional_entropy,
    sequential_span,
)
from ontology import ONTOLOGIES
from out import collect_advisories
from out.sinks import write_json
from tools.make_har import build_har, build_token_har

COUNTER_HOST = "counter.target-practice.test"
STRUCT_HOST = "struct.target-practice.test"
FRAMED_HOST = "framed.target-practice.test"


def _analyse(har: dict, tmp: Path):
    path = tmp / "t.har"
    path.write_text(json.dumps(har))
    series = list(group_into_series(
        HarSource(path).observations(), min_observations=1
    ))
    ctx = Context(
        now=max(s.end or 0.0 for s in series),
        baseline=NullBaseline(),
        mode="assisted",
    )
    findings, evidences = run(series, ONTOLOGIES, ctx)
    return findings, evidences


def _token_facts(evidences, host):
    for evidence in evidences:
        if evidence.channel.dims.get("host") != host:
            continue
        inspection = evidence.by_name("auth.token_quality")
        if inspection is not None:
            return inspection
    return None


# --------------------------------------------------------------------------
# the maths, in isolation
# --------------------------------------------------------------------------


def test_positional_entropy_reports_its_own_ceiling():
    """With n samples a position can show at most n distinct values, so no
    position can MEASURE more than log2(n) bits however good the generator
    is. The ceiling must be reported alongside the measurement or the number
    is a lie."""
    import math

    values = [secrets.token_hex(16) for _ in range(12)]
    measured, ceiling, constant, length = positional_entropy(values)
    assert length == 32
    assert constant == 0
    assert ceiling == 32 * math.log2(12)
    assert measured <= ceiling + 1e-9, "measured entropy exceeded its ceiling"


def test_constant_positions_are_counted_exactly():
    values = [f"FIXEDPREFIX{index:04x}" for index in range(10)]
    _, _, constant, length = positional_entropy(values)
    assert length == 15
    # "FIXEDPREFIX" plus the three leading zeros of a 4-hex counter under 16.
    assert constant == 14


def test_sequential_span_detects_a_counter_regardless_of_order():
    """Observation order in a capture is not generation order, so the test
    must not depend on the values arriving sorted."""
    import random

    values = [f"{0x5f3a2b1c00000000 + i:016x}" for i in range(12)]
    random.Random(7).shuffle(values)
    span, fraction, base = sequential_span(values)
    assert base == 16
    assert span == 11
    assert fraction < 1e-15


def test_sequential_span_quiet_on_random_values():
    values = [secrets.token_hex(16) for _ in range(12)]
    result = sequential_span(values)
    assert result is not None          # hex always parses
    _, fraction, _ = result
    assert fraction > 0.01, "random hex looked clustered"


def test_decoded_structure_reads_padless_base64url():
    import base64

    raw = b"user-4417:victim@example.test:3"
    token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    decoded = decoded_structure(token)
    assert decoded is not None and "victim@example.test" in decoded


def test_decoded_structure_quiet_on_real_randomness():
    for _ in range(20):
        assert decoded_structure(secrets.token_hex(32)) is None


# --------------------------------------------------------------------------
# negative tests — the ones that matter
# --------------------------------------------------------------------------


def test_strong_token_is_not_flagged():
    """A cryptographically strong token observed MIN_SAMPLES times must
    produce no finding.

    This is the test that stops the analysis being a false-positive
    generator. Every weakness signal has to stay quiet on 128 bits of real
    randomness seen a dozen times — which is exactly the situation where a
    naive entropy estimate reports "only 43 bits" and condemns it.
    """
    entries = []
    for index in range(MIN_SAMPLES + 4):
        token = secrets.token_hex(32)
        entries.append({
            "startedDateTime": f"2026-10-23T12:00:{index:02d}.000Z",
            "time": 10,
            "request": {
                "method": "POST", "url": "https://strong.example.test/login",
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Host", "value": "strong.example.test"}],
                "queryString": [], "cookies": [],
                "headersSize": -1, "bodySize": 0,
            },
            "response": {
                "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": "Set-Cookie",
                     "value": f"sessionid={token}; Path=/; Secure; HttpOnly; SameSite=Strict"},
                ],
                "cookies": [],
                "content": {"size": 2, "mimeType": "application/json", "text": "{}"},
                "redirectURL": "", "headersSize": -1, "bodySize": 2,
            },
            "cache": {}, "timings": {},
        })

    with tempfile.TemporaryDirectory() as d:
        findings, evidences = _analyse(
            {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                     "entries": entries}},
            Path(d),
        )
        token_rules = [
            f for f in findings if f.rule_id.startswith("http.session.token_")
        ]
        assert not token_rules, (
            f"strong token flagged: {[(f.rule_id, f.confidence) for f in token_rules]}"
        )

        inspection = _token_facts(evidences, "strong.example.test")
        assert inspection is None or inspection.score == 0.0


def test_strong_tokens_survive_every_sample_size_and_length():
    """Regression guard for the sample-cap bug.

    The bit-shortfall test originally compared the target against
    `varying * log2(n)` — a quantity that SHRINKS with sample size — so a
    genuinely 64-bit 16-hex token was condemned at n=8 and cleared at n=16.
    Any claim whose truth depends on how many times you looked is not a
    finding. Swept across the sizes where that failed.
    """
    import secrets as _secrets

    for hex_bytes in (8, 16, 32):          # 16, 32, 64 hex characters
        for samples in (MIN_SAMPLES, MIN_SAMPLES + 4, MIN_SAMPLES + 8):
            values = [_secrets.token_hex(hex_bytes) for _ in range(samples)]
            result = SessionTokenQuality()._judge(
                ("example.test", "sessionid"), values, samples, set(), []
            )
            assert result is None or result.score == 0.0, (
                f"{hex_bytes * 2}-char token flagged at n={samples}: "
                f"{result.facts.get('issues')}"
            )


def test_short_token_is_flagged_at_any_sample_size():
    """The converse: a genuinely small keyspace must be caught, and the
    verdict must not depend on sample size either."""
    for samples in (MIN_SAMPLES, MIN_SAMPLES + 8):
        values = [f"{index:04x}" for index in range(samples)]
        result = SessionTokenQuality()._judge(
            ("example.test", "sessionid"), values, samples, set(), []
        )
        assert result is not None and result.score > 0.3, (
            f"a 4-hex (16-bit) token was not flagged at n={samples}"
        )


def test_entropy_is_never_claimed_beyond_the_sample_ceiling():
    """Any bit figure the tool reports must be <= what the sample size can
    measure, and the ceiling must be published next to it."""
    with tempfile.TemporaryDirectory() as d:
        _, evidences = _analyse(build_token_har(), Path(d))
        inspection = _token_facts(evidences, FRAMED_HOST)
        assert inspection is not None

        measured = float(inspection.facts["measured_bits_lower_bound"])
        ceiling = float(inspection.facts["measurable_ceiling_bits"])
        assert measured <= ceiling
        assert "measurable_ceiling_bits" in inspection.facts
        assert any("lower bound" in note for note in inspection.notes)


def test_too_few_samples_scores_zero_and_advises():
    """"We could not measure it" must never read as "it is weak" — but it
    must not be silent either."""
    with tempfile.TemporaryDirectory() as d:
        findings, evidences = _analyse(build_har(), Path(d))

        assert not any(
            f.rule_id.startswith("http.session.token_") for f in findings
        ), "a rule fired on an unassessable token"

        inspection = _token_facts(evidences, "api.target-practice.test")
        assert inspection is not None
        assert inspection.score == 0.0
        assert inspection.features["assessable"] == 0.0
        assert "needs 8" in inspection.facts["insufficient"]

        advisories = collect_advisories(evidences)
        assert any("quality analysis needs" in a for a in advisories)


def test_jwts_are_left_to_the_jwt_inspector():
    """A JWT's structure is public by design; scoring its entropy is
    meaningless and would double-report what JwtWeakness already covers."""
    with tempfile.TemporaryDirectory() as d:
        _, evidences = _analyse(build_har(), Path(d))
        for evidence in evidences:
            inspection = evidence.by_name("auth.token_quality")
            if inspection is None:
                continue
            assert "eyJ" not in inspection.facts.get("sample", "")


# --------------------------------------------------------------------------
# positive tests
# --------------------------------------------------------------------------


def test_counter_token_is_critical():
    with tempfile.TemporaryDirectory() as d:
        findings, evidences = _analyse(build_token_har(), Path(d))
        counter = next(
            (f for f in findings
             if f.rule_id == "http.session.token_predictable"
             and f.channel.dims["host"] == COUNTER_HOST),
            None,
        )
        assert counter is not None, "sequential token not detected"
        assert counter.severity.value == "critical"

        facts = counter.evidence.by_name("auth.token_quality").facts
        assert facts["numeric_base"] == "16"
        assert int(facts["numeric_span"]) < 20
        assert "counter" in facts["issues"]


def test_structured_token_naming_the_user_is_critical():
    """The most serious shape: a token an attacker can read and forge."""
    with tempfile.TemporaryDirectory() as d:
        findings, evidences = _analyse(build_token_har(), Path(d))
        struct = next(
            (f for f in findings
             if f.rule_id == "http.session.token_predictable"
             and f.channel.dims["host"] == STRUCT_HOST),
            None,
        )
        assert struct is not None, "decodable structured token not detected"

        facts = struct.evidence.by_name("auth.token_quality").facts
        assert "victim@target-practice.test" in facts["decoded_contains"]
        assert "identifier seen elsewhere" in facts["issues"]


def test_fixed_framing_is_reported_with_the_count():
    with tempfile.TemporaryDirectory() as d:
        _, evidences = _analyse(build_token_har(), Path(d))
        framed = _token_facts(evidences, FRAMED_HOST)
        assert framed is not None
        assert framed.facts["constant_positions"] == "31 of 32"
        assert "never varied" in framed.facts["issues"]


def test_predictable_rule_supersedes_the_structural_one():
    with tempfile.TemporaryDirectory() as d:
        findings, _ = _analyse(build_token_har(), Path(d))
        hosts_critical = {
            f.channel.dims["host"] for f in findings
            if f.rule_id == "http.session.token_predictable"
        }
        hosts_medium = {
            f.channel.dims["host"] for f in findings
            if f.rule_id == "http.session.token_weak_structure"
        }
        assert not (hosts_critical & hosts_medium), (
            "a host reported under both the specific and general token rule"
        )


def test_token_samples_are_redacted():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        findings, evidences = _analyse(build_token_har(), tmp)
        out = tmp / "f.json"
        write_json(out, findings, evidences)
        text = out.read_text()

        # The raw token value and its decoded plaintext are credentials.
        assert "5f3a2b1c0000000" not in text, "raw counter token leaked"
        assert "user-4417:victim@target-practice.test" not in text, (
            "decoded token plaintext leaked"
        )
        # ...but what makes it a finding survives.
        assert "victim@target-practice.test" in text   # decoded_contains
        assert "consistent with a counter" in text


def test_groups_are_kept_separate_per_token_name():
    """Different cookies come from different generators. Averaging them would
    hide a weak token behind a strong one."""
    with tempfile.TemporaryDirectory() as d:
        _, evidences = _analyse(build_token_har(), Path(d))
        names = {
            e.by_name("auth.token_quality").facts["token.name"]
            for e in evidences if e.by_name("auth.token_quality")
        }
        assert names == {"sessionid", "auth_token", "JSESSIONID"}


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
