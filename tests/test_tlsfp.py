"""TLS client-fingerprint narration — which library, never which intent.

Three layers under test. The parser additions (GREASE presence and ALPN out
of a ClientHello) have to be read correctly AND must not disturb the
fingerprint, whose GREASE-stripping already existed and is what keeps rarity
scoring from seeing infinite novelty. The classifier must fork on the signals
it claims to fork on and hedge everywhere else. And the narrator must print
the reading beside its evidence with the caveat — once — because a
library-identification presented without the utls caveat would be exactly the
overclaim this tool exists to avoid.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.decode import client_hello
from capture.tlsfp import CAVEAT, classify_client
from core.model import Channel, Direction, Entity, Locus, Observation, Series
from out.narrate import narrate


# --------------------------------------------------------------------------
# a configurable ClientHello builder
# --------------------------------------------------------------------------

_GREASE = 0x1A1A  # one of the RFC 8701 reserved values


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def _record(payload: bytes) -> bytes:
    return bytes([0x16]) + struct.pack(">HH", 0x0303, len(payload)) + payload


def _hello(sni: str = "shop.test", grease: bool = False,
           alpn=(), ciphers=(0xC02F, 0x1301, 0x1302)) -> bytes:
    host = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(host)) + host
    sni_body = struct.pack(">H", len(server_name)) + server_name
    exts = struct.pack(">HH", 0x0000, len(sni_body)) + sni_body

    if alpn:
        names = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
        alpn_body = struct.pack(">H", len(names)) + names
        exts += struct.pack(">HH", 0x0010, len(alpn_body)) + alpn_body

    if grease:
        exts += struct.pack(">HH", _GREASE, 0)

    suite_list = list(ciphers) + ([_GREASE] if grease else [])
    suites = b"".join(struct.pack(">H", c) for c in suite_list)

    body = struct.pack(">H", 0x0303) + b"\x22" * 32
    body += b"\x00"                                   # session id
    body += struct.pack(">H", len(suites)) + suites
    body += b"\x01\x00"                               # compression
    body += struct.pack(">H", len(exts)) + exts
    return _record(_handshake(0x01, body))


# --------------------------------------------------------------------------
# parser: GREASE and ALPN are read; the fingerprint ignores GREASE
# --------------------------------------------------------------------------


def test_grease_is_detected_and_alpn_extracted():
    hello = client_hello(_hello(grease=True, alpn=("h2", "http/1.1")))
    assert hello is not None
    assert hello.uses_grease is True
    assert hello.alpn == ("h2", "http/1.1")
    assert hello.sni == "shop.test"


def test_plain_hello_has_no_grease_and_no_alpn():
    hello = client_hello(_hello())
    assert hello is not None
    assert hello.uses_grease is False
    assert hello.alpn == ()


def test_fingerprint_is_unchanged_by_grease():
    """GREASE values are random per connection, so a fingerprint that
    included them would make every browser connection look novel. The same
    hello with and without GREASE must hash identically."""
    with_g = client_hello(_hello(grease=True))
    without = client_hello(_hello(grease=False))
    assert with_g.fingerprint == without.fingerprint
    # ...while the GREASE fact itself is still reported.
    assert with_g.uses_grease and not without.uses_grease


def test_alpn_changes_the_fingerprint():
    """ALPN is a real extension (0x0010), part of the extension list the
    fingerprint hashes — two clients differing in ALPN are different shapes."""
    a = client_hello(_hello(alpn=("h2",)))
    b = client_hello(_hello())
    assert a.fingerprint != b.fingerprint


# --------------------------------------------------------------------------
# classifier: forks on what it claims, hedges elsewhere
# --------------------------------------------------------------------------


def test_grease_plus_h2_reads_as_browser_like():
    profile = classify_client(uses_grease=True, alpn=("h2", "http/1.1"),
                              cipher_count=15, ext_count=14)
    assert "browser" in profile.family
    assert "mimicking" in profile.family       # utls named, not hidden
    assert any("GREASE" in s for s in profile.signals)


def test_h2_without_grease_is_called_out_as_non_browser():
    profile = classify_client(uses_grease=False, alpn=("h2",),
                              cipher_count=12, ext_count=8)
    assert "non-browser" in profile.family


def test_sparse_no_grease_reads_as_library_stack():
    profile = classify_client(uses_grease=False, alpn=(),
                              cipher_count=3, ext_count=4)
    assert "library" in profile.family or "command-line" in profile.family


def test_ambiguous_shape_is_not_guessed():
    # No GREASE, no ALPN, a cipher list too long to call sparse: say so.
    profile = classify_client(uses_grease=False, alpn=(),
                              cipher_count=20, ext_count=10)
    assert "does not clearly separate" in profile.family


def test_no_product_names_in_verdicts():
    """The classifier reports families with examples, never a bare product
    claim like 'Chrome' as the whole family."""
    for args in ((True, ("h2",)), (False, ("h2",)), (False, ())):
        profile = classify_client(uses_grease=args[0], alpn=args[1],
                                  cipher_count=5, ext_count=5)
        assert not profile.family.startswith(("Chrome", "Firefox", "curl"))


# --------------------------------------------------------------------------
# narrator: the reading appears beside its evidence, caveat printed once
# --------------------------------------------------------------------------


def _tls_series(host: str, peer: str, fingerprint: str, grease: str,
                alpn: str = "", stream: int = 1) -> Series:
    channel = Channel(
        domain="net",
        dims={"proto": "tcp", "dport": "443", "sni": "shop.test"},
        initiator=Entity("ip", host, labels={"private": True}),
        responder=Entity("ip", peer, labels={"private": False}),
    )
    attrs = {
        "encrypted": True, "sni": "shop.test",
        "tls_fingerprint": fingerprint,
        "tls_client_grease": grease,
        "tls_client_ciphers": "15", "tls_client_exts": "12",
    }
    if alpn:
        attrs["tls_client_alpn"] = alpn
    observations = [
        Observation(ts=1_700_000_000.0 + i * 2.0, channel=channel,
                    direction=Direction.EGRESS, size=200, kind="tcp_burst",
                    attrs=dict(attrs),
                    locus=Locus(source="t.pcap", frames=(i + 1,)))
        for i in range(5)
    ]
    return Series(channel, observations)


def test_host_detail_prints_the_client_reading_and_caveat_once():
    series = [
        _tls_series("10.0.0.5", "203.0.113.9", "aaaa", "1", "h2,http/1.1"),
    ]
    text = narrate(series, [], source_name="t.pcap")
    flat = " ".join(text.split())
    assert "tls client" in flat
    assert "browser" in flat
    assert "sends GREASE" in flat
    # evidence line names the print and the channel count
    assert "aaaa on 1 channel" in flat
    # the caveat, exactly once
    assert flat.count("never a verdict") == 1


def test_two_stacks_from_one_host_are_called_out():
    series = [
        _tls_series("10.0.0.5", "203.0.113.9", "aaaa", "1", "h2"),
        _tls_series("10.0.0.5", "198.51.100.7", "bbbb", "0", "", stream=2),
    ]
    text = " ".join(narrate(series, [], source_name="t.pcap").split())
    assert "2 distinct TLS stacks" in text


def test_no_reading_without_client_attrs():
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443"},
        initiator=Entity("ip", "10.0.0.5", labels={"private": True}),
        responder=Entity("ip", "203.0.113.9", labels={"private": False}),
    )
    series = [Series(channel, [
        Observation(ts=1_700_000_000.0, channel=channel,
                    direction=Direction.EGRESS, size=100, kind="tcp_burst",
                    attrs={"encrypted": False},
                    locus=Locus(source="t.pcap", frames=(1,)))
    ])]
    text = narrate(series, [], source_name="t.pcap")
    assert "tls client" not in text
    assert "never a verdict" not in text


def test_glossary_covers_the_new_vocabulary():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in("the host sends GREASE and ALPN h2")}
    assert "TLS client fingerprint (GREASE, ALPN)" in found


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
