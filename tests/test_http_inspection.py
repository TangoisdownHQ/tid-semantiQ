"""The tshark backend, the inspectors, and redaction.

Runs against a REAL TLS 1.3 session built by `tools/make_tls_pcap.py` — real
OpenSSL handshake, real AEAD, real NSS keylog — so these exercise actual
decryption rather than a stub. Skips cleanly if tshark is absent.

The redaction tests are the important ones. Every other failure here produces
a worse report; a redaction failure writes live credentials to disk.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.pcap import PcapSource
from core.baseline import NullBaseline
from core.model import Context
from core.redact import looks_secret, mask, passthrough, redact_secrets
from core.score import run
from ontology import ONTOLOGIES
from out.sinks import write_json
from tools.make_tls_pcap import build_frames, capture_session, write_pcap

HAVE_TSHARK = shutil.which("tshark") is not None

#: The literal values planted in the fixture. If any of these appears in an
#: output, redaction has failed. The key is assembled at runtime so a
#: live-shaped token never sits at rest in this repository — secret
#: scanners (including GitHub push protection) would flag it forever.
PLANTED_SECRETS = (
    "sk_live_" + "8f3a2b1c9d4e5f6a7b8c9d0e",            # api key in the URL
    "7f3a2b1c9d4e5f6a",                                 # session cookie value
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6",     # JWT header segment
)


def _fixture(tmp: Path):
    pcap, keylog = tmp / "tls.pcap", tmp / "keys.log"
    chunks = capture_session(keylog)
    assert chunks, "TLS handshake produced no ciphertext"
    write_pcap(pcap, build_frames(chunks))
    return pcap, keylog


def _analyse(tmp: Path):
    from capture.tshark import HttpProfile, TsharkSource

    pcap, keylog = _fixture(tmp)
    source = TsharkSource(pcap, profile=HttpProfile(), keylog=keylog)
    series = list(group_into_series(source.observations(), min_observations=1))
    end = max(s.end or 0.0 for s in series)
    ctx = Context(now=end, baseline=NullBaseline(), mode="assisted")
    findings, evidences = run(series, ONTOLOGIES, ctx)
    return findings, evidences, source


# --------------------------------------------------------------------------
# the tshark backend
# --------------------------------------------------------------------------


def test_tshark_decrypts_with_a_keylog():
    """Real TLS 1.3, decrypted. Without the keylog there is nothing to read,
    which is the whole reason this backend exists."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        pcap, keylog = _fixture(tmp)

        without = TsharkSource(pcap, profile=HttpProfile(), keylog=None)
        assert len(list(without.observations())) == 0, "decrypted without keys"

        with_keys = TsharkSource(pcap, profile=HttpProfile(), keylog=keylog)
        obs = list(with_keys.observations())
        # Asserted as a shape, not a count: the fixture's exchange list is
        # expected to grow, and a hardcoded total makes every addition look
        # like a regression.
        assert obs, "nothing decrypted with the keylog"
        assert {o.kind for o in obs} == {"http_request", "http_response"}
        requests = [o for o in obs if o.kind == "http_request"]
        assert len(requests) == len(obs) - len(requests), (
            "every request should have exactly one response"
        )


def test_tshark_extracts_headers_and_body():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        pcap, keylog = _fixture(tmp)
        obs = list(TsharkSource(pcap, profile=HttpProfile(), keylog=keylog).observations())

        request = next(
            o for o in obs
            if o.kind == "http_request" and o.attrs["path"] == "/v2/account/profile"
        )
        assert request.attrs["method"] == "GET"
        assert set(request.attrs["params"]) == {"api_key", "debug"}
        assert request.attrs["authorization"].startswith("Bearer ")
        assert "authorization" in request.attrs["headers"]

        response = next(
            o for o in obs
            if o.kind == "http_response" and o.attrs.get("request_path")
            == "/v2/account/profile"
        )
        assert response.attrs["status"] == "200"
        assert len(response.attrs["set_cookie"]) == 2
        assert "stripe_key" in response.attrs["body_text"]

        # Locus must round-trip to something Wireshark accepts.
        assert request.locus.display_filter() == "tcp.stream eq 0"


def test_tshark_failure_is_raised_not_swallowed():
    """A tshark that fails yields zero observations, which is
    indistinguishable from a clean capture unless the error surfaces."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import TsharkSource

    with tempfile.TemporaryDirectory() as d:
        bogus = Path(d) / "not-a-capture.pcap"
        bogus.write_bytes(b"this is not a pcap file at all")
        try:
            list(TsharkSource(bogus).observations())
        except RuntimeError as exc:
            assert "tshark exited" in str(exc)
        else:
            raise AssertionError("malformed capture did not raise")


def test_missing_keylog_fails_loudly():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        pcap, _ = _fixture(tmp)
        try:
            list(TsharkSource(pcap, keylog=tmp / "nope.log").observations())
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("missing keylog was ignored")


def test_native_reader_unaffected_by_the_same_capture():
    """The behavioural path must still work on a TLS capture, and must see
    bursts rather than HTTP — the two sources are complementary, not
    alternatives."""
    with tempfile.TemporaryDirectory() as d:
        pcap, _ = _fixture(Path(d))
        source = PcapSource(pcap)
        obs = list(source.observations())
        assert obs, "native reader produced nothing"
        assert all(o.kind == "tcp_burst" for o in obs)
        assert all(o.channel.domain == "net" for o in obs)
        # Every frame in a TLS fixture is TCP, and none may be dropped —
        # a silently undecoded frame is evidence that vanished.
        assert source.stats["tcp"] == source.stats["frames"]
        assert source.stats["decoded"] == source.stats["frames"]


# --------------------------------------------------------------------------
# inspectors
# --------------------------------------------------------------------------


def test_inspectors_find_the_planted_defects():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, evidences, _ = _analyse(Path(d))

        rules = {f.rule_id for f in findings}
        assert "http.session.cookie_takeover_chain" in rules
        assert "http.auth.jwt_unsigned_or_unexpiring" in rules
        assert "http.auth.credential_in_url" in rules

        # Several hosts now, so pick the worst instance of each inspection
        # rather than whichever happened to be enumerated last.
        inspections: dict = {}
        for e in evidences:
            for i in e.inspections:
                if i.name not in inspections or i.score > inspections[i.name].score:
                    inspections[i.name] = i

        jwt = inspections["auth.jwt"]
        assert jwt.facts["jwt.alg"] == "HS256"
        assert "no exp claim" in jwt.facts["jwt.issues"]
        assert "email" in jwt.facts["jwt.claims"]
        assert jwt.features["has_exp"] == 0.0

        cookie = inspections["auth.cookie"]
        assert cookie.facts["cookie.name"] == "session"
        assert cookie.facts["cookie.domain"] == ".target-practice.test"
        assert "missing Secure" in cookie.facts["cookie.flags"]
        assert "missing HttpOnly" in cookie.facts["cookie.flags"]

        # Scoped to the API host: the analytics request carries a 227-char
        # JWT in `token`, which legitimately outranks `api_key` as the worst
        # parameter globally. Asserting the global worst would be asserting
        # the fixture's ordering, not the inspector's behaviour.
        api_evidence = next(
            e for e in evidences
            if e.channel.dims.get("host") == "api.target-practice.test"
        )
        url = api_evidence.by_name("auth.token_in_url")
        assert url is not None, "token-in-URL not found on the API host"
        assert url.facts["worst_parameter"] == "api_key"


def test_specific_rule_supersedes_the_general_one():
    """A wildcard-Domain session cookie and a cookie missing flags are one
    defect, not two. Reporting both teaches a triager nothing."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, _, _ = _analyse(Path(d))
        rules = {f.rule_id for f in findings}
        assert "http.session.cookie_takeover_chain" in rules
        assert "http.session.cookie_insecure" not in rules


def test_findings_cite_only_their_own_evidence():
    """Evidence is per-channel, findings are per-rule. Without `cited`, four
    findings on one host each reprint all three inspections."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, _, _ = _analyse(Path(d))
        jwt_finding = next(
            f for f in findings if f.rule_id == "http.auth.jwt_unsigned_or_unexpiring"
        )
        assert "auth.jwt" in jwt_finding.cited
        assert "auth.cookie" not in jwt_finding.cited


def test_folding_collapses_repeats():
    """One inspector result per message would mean hundreds of duplicates on
    a real capture."""
    from core.inspect import fold
    from core.model import InspectionResult, Locus

    repeats = [
        InspectionResult(
            name="auth.cookie", score=0.4, facts={"cookie.name": "a"},
            loci=(Locus("c.pcap", frames=(i,)),),
        )
        for i in range(1, 40)
    ]
    worse = InspectionResult(
        name="auth.cookie", score=0.9, facts={"cookie.name": "session"},
        loci=(Locus("c.pcap", frames=(99,)),),
    )
    folded = fold(repeats + [worse])

    assert len(folded) == 1
    assert folded[0].score == 0.9                       # worst wins, not mean
    assert folded[0].facts["cookie.name"] == "session"  # facts from the worst
    assert folded[0].occurrences == 40
    assert len(folded[0].loci) <= 8                     # bounded sample


# --------------------------------------------------------------------------
# redaction — the tests that matter most
# --------------------------------------------------------------------------


def test_no_planted_secret_reaches_the_json_output():
    """THE ONE THAT MATTERS. findings.json gets attached to bug reports."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        findings, evidences, _ = _analyse(tmp)
        out = tmp / "findings.json"
        write_json(out, findings, evidences)
        text = out.read_text()

        for secret in PLANTED_SECRETS:
            assert secret not in text, f"LEAKED to findings.json: {secret[:20]}…"


def test_redaction_preserves_the_analysis():
    """A redactor that masks the finding is useless. The first version masked
    `cookie.domain`, `cookie.path` and `jwt.issues` — the actual defects —
    because every key contained a substring like "cookie" or "key"."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        findings, evidences, _ = _analyse(tmp)
        out = tmp / "findings.json"
        write_json(out, findings, evidences)
        data = json.loads(out.read_text())

        facts = {
            i["name"]: i["facts"]
            for f in data["findings"]
            for i in f["evidence"]["inspections"]
        }
        assert facts["auth.cookie"]["cookie.domain"] == ".target-practice.test"
        assert facts["auth.cookie"]["cookie.path"] == "/"
        assert facts["auth.cookie"]["cookie.name"] == "session"
        assert "no exp claim" in facts["auth.jwt"]["jwt.issues"]
        assert facts["auth.jwt"]["jwt.alg"] == "HS256"

        # and the secrets are masked but identifiable
        assert "sha256:" in facts["auth.cookie"]["cookie.value"]
        assert "sha256:" in facts["auth.jwt"]["jwt.raw"]


def test_masked_values_stay_comparable():
    """Same credential in two places must produce the same fingerprint, so a
    token can be followed across hosts without ever being stored."""
    token = "sk_live_" + "51HxQpLMNopQrStUvWxYz0123456789abcdef"
    a = redact_secrets({"token": token}, ("token",))["token"]
    b = redact_secrets({"api_key": token}, ("api_key",))["api_key"]
    assert "sha256:" in a and a.split("sha256:")[1] == b.split("sha256:")[1]
    assert token not in a


def test_short_secrets_are_masked_entirely():
    """Showing 6 of 10 characters of a PIN is a leak, not a redaction."""
    out = redact_secrets({"pin": "8471926"}, ("pin",))["pin"]
    assert "8471926" not in out and "redacted" in out


def test_backstop_catches_undeclared_secrets():
    """An inspector that forgets to declare a secret must still not leak an
    obvious one."""
    opaque = "A" * 40
    assert looks_secret(opaque)
    assert opaque not in redact_secrets({"whatever": opaque})["whatever"]

    # ...and the backstop must stay narrow enough not to eat the analysis
    assert not looks_secret("missing Secure, missing HttpOnly, missing SameSite")
    assert not looks_secret(".target-practice.test")
    assert not looks_secret("/v2/account/profile")
    assert not looks_secret("https://example.com/a/very/long/path/that/goes/on")


def test_unsafe_passthrough_is_opt_in_only():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        findings, evidences, _ = _analyse(tmp)
        out = tmp / "unsafe.json"
        write_json(out, findings, evidences, redactor=passthrough)
        text = out.read_text()
        assert PLANTED_SECRETS[0] in text, "passthrough did not pass through"


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
    print(f"\n{len(tests) - failed}/{len(tests)} passed"
          + ("" if HAVE_TSHARK else "   (tshark absent: backend tests skipped)"))
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
