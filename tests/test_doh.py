"""Encrypted-DNS (DoH / DoT) detection — naming a blind spot honestly.

The point is to stop the report saying "no DNS seen" when the DNS was merely
encrypted. The classifier must fire on a known resolver by SNI (on any port)
or by its address on the DoH/DoT port — but NOT on that same resolver on port
53, which is ordinary DNS the tool already reads. The narrator must then say
the lookups happened and are unreadable here.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.doh import classify_encrypted_dns
from core.model import Channel, Direction, Entity, Locus, Observation, Series
from out.narrate import narrate


# --------------------------------------------------------------------------
# the classifier
# --------------------------------------------------------------------------


def test_sni_to_a_known_resolver_is_doh():
    p, proto, basis = classify_encrypted_dns("cloudflare-dns.com", "9.9.9.9", 443)
    assert p == "Cloudflare" and proto == "DoH"
    assert "SNI" in basis


def test_subdomain_sni_matches_the_provider():
    assert classify_encrypted_dns(
        "mozilla.cloudflare-dns.com", "x", 443)[0] == "Cloudflare"
    assert classify_encrypted_dns("dns.google", "x", 443)[0] == "Google"


def test_resolver_ip_on_443_is_doh_on_853_is_dot():
    assert classify_encrypted_dns("", "1.1.1.1", 443) == \
        ("Cloudflare", "DoH", "1.1.1.1 on 443")
    assert classify_encrypted_dns("", "9.9.9.9", 853) == \
        ("Quad9", "DoT", "9.9.9.9 on 853")


def test_resolver_ip_on_53_is_not_flagged():
    # 1.1.1.1:53 is ordinary cleartext DNS, which the tool already reads.
    assert classify_encrypted_dns("", "1.1.1.1", 53) is None


def test_dot_sni_uses_the_port_for_protocol():
    assert classify_encrypted_dns("one.one.one.one", "1.1.1.1", 853)[1] == "DoT"


def test_unknown_host_and_ip_are_not_flagged():
    assert classify_encrypted_dns("example.com", "203.0.113.9", 443) is None
    assert classify_encrypted_dns("", "203.0.113.9", 443) is None


# --------------------------------------------------------------------------
# the narration section
# --------------------------------------------------------------------------


def _net(host, dest, sni, dport="443", n=4):
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": dport, "sni": sni},
        initiator=Entity("ip", host, labels={"private": True}),
        responder=Entity("ip", dest, labels={"private": False}),
    )
    obs = [Observation(ts=1_700_000_000.0 + i, channel=channel,
                       direction=Direction.EGRESS, size=200, kind="tcp_burst",
                       attrs={"encrypted": True, "sni": sni},
                       locus=Locus(source="t", frames=(i,)))
           for i in range(n)]
    return Series(channel, obs)


def test_encrypted_dns_section_names_the_provider_and_the_blind_spot():
    series = [_net("10.0.0.5", "104.16.248.249", "cloudflare-dns.com")]
    text = " ".join(narrate(series, [], source_name="t.pcap").split())
    assert "ENCRYPTED DNS (DoH / DoT)" in text
    assert "DoH to Cloudflare" in text
    assert "cannot read" in text          # the honesty line
    assert "malware" in text              # the security-signal note


def test_no_section_without_encrypted_dns():
    series = [_net("10.0.0.5", "203.0.113.9", "shop.test")]
    assert "ENCRYPTED DNS" not in narrate(series, [], source_name="t.pcap")


def test_glossary_covers_doh():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in("the host used DoH (DNS over HTTPS)")}
    assert "DoH / DoT (encrypted DNS)" in found


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
