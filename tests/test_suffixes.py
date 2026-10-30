"""The Public Suffix List, and the findings it changes.

`test_credential_shared_across_two_couk_orgs_is_now_reported` is the one that
matters: it proves the label-count approximation was suppressing a real
finding, not merely being imprecise. Every target under a multi-part ccTLD had
the cross-party gate silently disabled.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.decode import registrable_zone
from capture.har import HarSource
from core.baseline import NullBaseline
from core.model import Context
from core.score import run
from core.suffixes import (
    DEFAULT_PATH,
    ICANN,
    PRIVATE,
    PublicSuffixList,
    default_list,
    party,
    public_suffix,
    registrable_domain,
    same_party,
)
from ontology import ONTOLOGIES


def _label_count(host: str, labels: int = 2) -> str:
    """The approximation this replaced, kept so the tests can show the
    difference rather than assert it."""
    parts = host.rstrip(".").split(".")
    return ".".join(parts[-labels:]) if len(parts) >= labels else host


# --------------------------------------------------------------------------
# the list itself
# --------------------------------------------------------------------------


def test_vendored_list_is_present_and_whole():
    """A truncated or missing file must be obvious, not silently degrade
    every lookup to the parent-domain answer."""
    assert DEFAULT_PATH.exists(), f"vendored list missing at {DEFAULT_PATH}"
    psl = default_list()
    assert psl.stats["rules"] > 9000, psl.describe()
    assert psl.stats["wildcards"] > 100, psl.describe()
    assert psl.stats["exceptions"] >= 10, psl.describe()


def test_mpl_licence_header_is_intact():
    """The file is vendored unmodified under MPL-2.0. Stripping the header
    would make this a modified MPL work with publication obligations."""
    head = DEFAULT_PATH.read_text(encoding="utf-8")[:600]
    assert "Mozilla Public" in head
    assert "MPL" in head


def test_list_is_parsed_once():
    assert default_list() is default_list()


# --------------------------------------------------------------------------
# the algorithm's three traps
# --------------------------------------------------------------------------


def test_longest_rule_wins():
    """Both `com` and `s3.amazonaws.com` match a bucket hostname. Taking the
    first match found instead of the longest is the classic bug."""
    assert public_suffix("bucket.s3.amazonaws.com") == "s3.amazonaws.com"
    assert public_suffix("api.target.com") == "com"
    assert public_suffix("www.foo.co.uk") == "co.uk"


def test_wildcard_rules_match_any_label():
    """`*.ck` makes every label under `ck` a suffix."""
    assert public_suffix("foo.bar.ck") == "bar.ck"
    assert registrable_domain("foo.bar.ck") == "foo.bar.ck"


def test_exception_rules_override_wildcards():
    """`!www.ck` beats `*.ck`, and the suffix is the exception rule MINUS its
    leftmost label."""
    assert public_suffix("www.ck") == "ck"
    assert registrable_domain("www.ck") == "www.ck"


def test_unmatched_tld_falls_back_to_the_rightmost_label():
    """The implicit `*` rule. `.test` is reserved and not in the list."""
    assert public_suffix("target-practice.test") == "test"
    assert registrable_domain("app.target-practice.test") == "target-practice.test"


def test_a_bare_public_suffix_has_no_registrable_domain():
    assert registrable_domain("co.uk") is None
    assert registrable_domain("com") is None
    assert registrable_domain("s3.amazonaws.com") is None
    # ...and `party` falls back to the host rather than returning None, so a
    # pathological bare suffix is still its own party and never matches
    # another.
    assert party("co.uk") == "co.uk"
    assert not same_party("co.uk", "foo.co.uk")


def test_trailing_dots_and_case_are_normalised():
    assert registrable_domain("WWW.Foo.CO.UK.") == "foo.co.uk"
    assert party("API.Target.COM") == "target.com"


def test_ip_addresses_are_not_domains():
    for host in ("10.0.0.5", "203.0.113.42", "::1", "[2001:db8::1]"):
        assert public_suffix(host) is None, host
        assert registrable_domain(host) is None, host
    # An IP is its own party — it must never be pooled with another, and the
    # party key is canonical: brackets and ports are stripped so the bracketed,
    # port-bearing, and bare spellings of one IPv6 literal are a single party.
    assert party("10.0.0.5") == "10.0.0.5"
    assert party("::1") == "::1"
    assert party("[2001:db8::1]") == "2001:db8::1"
    assert party("[2001:db8::1]:443") == "2001:db8::1"
    assert same_party("[2001:db8::1]", "2001:db8::1")
    assert same_party("[2001:db8::1]:443", "2001:db8::1")
    assert not same_party("10.0.0.5", "10.0.0.6")


def test_punycode_rules_are_matched():
    """~500 rules carry unicode labels, but hostnames in a capture arrive as
    punycode, so without conversion those rules would never match."""
    psl = default_list()
    assert psl.stats["punycode_added"] > 400, psl.describe()
    assert psl.stats["punycode_failed"] == 0, psl.describe()
    # 公司.cn, as a capture would present it.
    assert public_suffix("xn--55qx5d.cn") == "xn--55qx5d.cn"


def test_icann_only_mode_ignores_private_suffixes():
    """Which section you want depends on the question. "Who controls this?"
    wants the private section; "which registry delegated it?" does not."""
    assert public_suffix("bucket.s3.amazonaws.com") == "s3.amazonaws.com"
    assert public_suffix(
        "bucket.s3.amazonaws.com", include_private=False
    ) == "com"
    assert registrable_domain(
        "bucket.s3.amazonaws.com", include_private=False
    ) == "amazonaws.com"


def test_inline_text_loading_for_custom_rules():
    """A deployment with internal suffixes must be able to supply its own
    rules without editing the vendored MPL file."""
    psl = PublicSuffixList(text="\n".join([
        "// ===BEGIN ICANN DOMAINS===",
        "corp",
        "// ===END ICANN DOMAINS===",
        "// ===BEGIN PRIVATE DOMAINS===",
        "team.corp",
        "// ===END PRIVATE DOMAINS===",
    ]))
    assert psl.public_suffix("a.team.corp") == "team.corp"
    assert psl.public_suffix("a.team.corp", include_private=False) == "corp"
    assert psl._rules["corp"] == ICANN
    assert psl._rules["team.corp"] == PRIVATE


# --------------------------------------------------------------------------
# what it fixes
# --------------------------------------------------------------------------


def test_multipart_cctlds_are_separate_parties():
    """The headline bug. Two unrelated UK organisations both answered
    `co.uk`, so a credential shared between them read as first-party."""
    assert _label_count("foo.co.uk") == _label_count("bar.co.uk") == "co.uk"
    assert not same_party("foo.co.uk", "bar.co.uk")
    assert party("foo.co.uk") == "foo.co.uk"

    # Pairs must SHARE a suffix, or label-counting already told them apart
    # and the pair demonstrates nothing. (`org.uk` vs `ac.uk` differ under
    # both schemes.)
    for a, b in (
        ("one.com.au", "two.com.au"),
        ("one.co.jp", "two.co.jp"),
        ("one.org.uk", "two.org.uk"),
        ("one.co.nz", "two.co.nz"),
        ("one.co.za", "two.co.za"),
    ):
        assert _label_count(a) == _label_count(b), (a, b)
        assert not same_party(a, b), (a, b)


def test_cloud_suffixes_are_separate_parties():
    """Wrong in the other direction, and arguably worse for this tool: two
    S3 buckets both answered `amazonaws.com`, so a credential reaching an
    attacker-controlled bucket looked like first-party traffic."""
    for a, b in (
        ("victim.s3.amazonaws.com", "attacker.s3.amazonaws.com"),
        ("victim.github.io", "attacker.github.io"),
        ("victim.blob.core.windows.net", "attacker.blob.core.windows.net"),
    ):
        assert _label_count(a) == _label_count(b), (a, b)
        assert not same_party(a, b), (a, b)


def test_genuine_first_party_sharing_still_reads_as_one_party():
    """The gate must not be broken in the opposite direction."""
    assert same_party("api.target.com", "cdn.target.com")
    assert same_party("api.target.co.uk", "cdn.target.co.uk")
    assert same_party("a.b.c.target.com", "target.com")


def test_dns_zone_uses_the_suffix_list():
    """`registrable_zone` feeds DNS `Channel.dims`, so the approximation
    pooled every `*.co.uk` lookup into one channel and diluted the per-zone
    cardinality that tunnelling detection depends on."""
    assert registrable_zone("tunnel.evil.co.uk") == "evil.co.uk"
    assert registrable_zone("other.innocent.co.uk") == "innocent.co.uk"
    assert registrable_zone("abc.tun.example.org") == "example.org"


# --------------------------------------------------------------------------
# the finding it unblocks
# --------------------------------------------------------------------------


def _shared_credential_har(host_a: str, host_b: str) -> dict:
    """One bearer token presented to two hosts."""
    token = "Bearer eyJzaGFyZWQiOiJjcmVkZW50aWFsIn0.AAAAAAAAAAAAAAAAAAAA"
    entries = []
    for index, host in enumerate((host_a, host_a, host_a, host_b)):
        entries.append({
            "startedDateTime": f"2026-10-24T09:00:{index:02d}.000Z",
            "time": 20.0,
            "request": {
                "method": "GET", "url": f"https://{host}/api/data",
                "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": "Host", "value": host},
                    {"name": "Authorization", "value": token},
                ],
                "queryString": [], "cookies": [],
                "headersSize": -1, "bodySize": 0,
            },
            "response": {
                "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "cookies": [],
                "content": {"size": 2, "mimeType": "application/json", "text": "{}"},
                "redirectURL": "", "headersSize": -1, "bodySize": 2,
            },
            "cache": {},
            "timings": {"send": 1.0, "wait": 18.0, "receive": 1.0,
                        "connect": -1, "ssl": -1},
        })
    return {"log": {"version": "1.2",
                    "creator": {"name": "t", "version": "1"},
                    "entries": entries}}


def _findings_for(host_a: str, host_b: str):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.har"
        path.write_text(json.dumps(_shared_credential_har(host_a, host_b)))
        series = list(group_into_series(
            HarSource(path).observations(), min_observations=1
        ))
        ctx = Context(now=max(s.end or 0.0 for s in series),
                      baseline=NullBaseline(), mode="assisted")
        findings, _ = run(series, ONTOLOGIES, ctx)
        return {f.rule_id for f in findings}


def test_credential_shared_across_two_couk_orgs_is_now_reported():
    """THE PROOF.

    Under the label-count approximation both hosts answered `co.uk`, the
    cross-party condition was false, and the CRITICAL rule could not fire —
    so the finding was suppressed for every target under a multi-part ccTLD.
    """
    assert _label_count("api.victim.co.uk") == _label_count("collect.tracker.co.uk")

    rules = _findings_for("api.victim.co.uk", "collect.tracker.co.uk")
    assert "http.auth.credential_sent_to_third_party" in rules, (
        "a credential crossing two unrelated .co.uk organisations was not "
        "reported as cross-party"
    )


def test_credential_shared_within_one_org_stays_low():
    """And the gate still works: genuine first-party sharing must not
    escalate to CRITICAL."""
    rules = _findings_for("api.victim.co.uk", "cdn.victim.co.uk")
    assert "http.auth.credential_sent_to_third_party" not in rules
    assert "http.auth.credential_shared_across_hosts" in rules


def test_credential_reaching_a_foreign_bucket_is_reported():
    """The cloud case: previously both hosts answered `amazonaws.com`."""
    assert _label_count("upload.s3.amazonaws.com") == _label_count(
        "attacker.s3.amazonaws.com"
    )
    rules = _findings_for("upload.s3.amazonaws.com", "attacker.s3.amazonaws.com")
    assert "http.auth.credential_sent_to_third_party" in rules


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
