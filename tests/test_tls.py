"""Server-side TLS: negotiated version, and the certificate when readable.

Certificates are hand-built in DER here rather than generated with openssl,
so the suite stays dependency-free and the bytes under test are exactly the
bytes written down.

TWO OF THESE TESTS GUARD BUGS THAT SHIPPED, and both failed the same way —
silently, reporting "no certificate observed" on a capture where every
certificate was present:

  - `test_der_walk_descends_all_three_levels`. The DER walk collapsed
    Certificate and tbsCertificate into one level, so every field index after
    the issuer was wrong and the parse bailed out. 232 of 232 readable
    certificates in a real capture were missed.
  - `test_certificate_spanning_tcp_segments_is_reassembled`. A chain is
    routinely 2-4 kB against a ~1460-byte MSS. Parsing each segment alone
    found the small ServerHello every time and the Certificate never.

The failure mode shared by both is why they are here: a parser that returns
"nothing" looks identical to a capture that contained nothing, and nothing in
the report distinguishes them unless a test does.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.pcap import PcapSource, _name_covered
from capture.pcapfile import LINKTYPE_ETHERNET
from capture.tlsinfo import (
    Certificate,
    cert_visibility,
    certificates,
    server_hello,
    version_name,
)


# --------------------------------------------------------------------------
# DER construction
# --------------------------------------------------------------------------


def der(tag: int, content: bytes) -> bytes:
    """One TLV with a correctly encoded definite length."""
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    size = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


SEQ, SET, OID, UTF8, UTCTIME, GENTIME, INT, BITSTR, OCTSTR = (
    0x30, 0x31, 0x06, 0x0C, 0x17, 0x18, 0x02, 0x03, 0x04
)
_CN = bytes((0x55, 0x04, 0x03))
_SAN = bytes((0x55, 0x1D, 0x11))


def name(common: str) -> bytes:
    """An X.501 Name carrying one commonName."""
    atv = der(SEQ, der(OID, _CN) + der(UTF8, common.encode()))
    return der(SEQ, der(SET, atv))


def build_certificate(
    subject: str,
    issuer: str,
    sans=(),
    not_before: str = "250411000000Z",
    not_after: str = "260411235959Z",
    time_tag: int = UTCTIME,
    with_version: bool = True,
) -> bytes:
    """A minimal but structurally real X.509 certificate."""
    fields = b""
    if with_version:
        fields += der(0xA0, der(INT, b"\x02"))
    fields += der(INT, b"\x01")                      # serialNumber
    fields += der(SEQ, der(OID, bytes((0x2A, 0x86, 0x48))))  # signature alg
    fields += name(issuer)
    fields += der(SEQ, der(time_tag, not_before.encode())
                  + der(time_tag, not_after.encode()))
    fields += name(subject)
    fields += der(SEQ, der(SEQ, b"") + der(BITSTR, b"\x00"))  # spki

    if sans:
        general = b"".join(der(0x82, entry.encode()) for entry in sans)
        extension = der(SEQ, der(OID, _SAN) + der(OCTSTR, der(SEQ, general)))
        fields += der(0xA3, der(SEQ, extension))

    tbs = der(SEQ, fields)
    return der(SEQ, tbs + der(SEQ, b"") + der(BITSTR, b"\x00"))


# --------------------------------------------------------------------------
# TLS framing
# --------------------------------------------------------------------------


def handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def record(payload: bytes, version: int = 0x0303) -> bytes:
    return (bytes([0x16]) + struct.pack(">HH", version, len(payload))
            + payload)


def server_hello_body(version: int = 0x0303, cipher: int = 0xC02F,
                      supported_versions: int = 0) -> bytes:
    body = struct.pack(">H", version) + b"\x11" * 32
    body += b"\x00"                        # empty session id
    body += struct.pack(">H", cipher)
    body += b"\x00"                        # compression
    if supported_versions:
        extension = struct.pack(">HH", 0x002B, 2) + struct.pack(
            ">H", supported_versions
        )
        body += struct.pack(">H", len(extension)) + extension
    else:
        body += struct.pack(">H", 0)
    return handshake(0x02, body)


def certificate_message(*certs: bytes) -> bytes:
    entries = b"".join(len(c).to_bytes(3, "big") + c for c in certs)
    return handshake(0x0B, len(entries).to_bytes(3, "big") + entries)


# --------------------------------------------------------------------------
# negotiated version
# --------------------------------------------------------------------------


def test_negotiated_version_is_read_from_server_hello():
    answer = server_hello(record(server_hello_body(version=0x0303)))
    assert answer is not None
    assert answer.version == 0x0303
    assert version_name(answer.version) == "TLS 1.2"


def test_tls13_is_read_from_supported_versions_not_the_legacy_field():
    """TLS 1.3 leaves the legacy field reading 0x0303 for middlebox
    compatibility. Reading only that field reports every 1.3 connection as
    1.2 — a wrong fact stated confidently, which nobody would double-check."""
    wire = record(server_hello_body(version=0x0303,
                                    supported_versions=0x0304))
    answer = server_hello(wire)
    assert answer.version == 0x0304, hex(answer.version)
    assert version_name(answer.version) == "TLS 1.3"


def test_server_hello_absent_returns_none():
    assert server_hello(b"") is None
    assert server_hello(record(handshake(0x0B, b"\x00\x00\x00"))) is None


# --------------------------------------------------------------------------
# certificate parsing
# --------------------------------------------------------------------------


def test_der_walk_descends_all_three_levels():
    """REGRESSION. der -> Certificate -> tbsCertificate is three levels, and
    collapsing the middle one makes every field index after issuer wrong.
    The parse then bails and the report says "no certificate observed"."""
    cert = build_certificate("shop.test", "Test CA",
                             sans=("shop.test", "www.shop.test"))
    found = certificates(record(certificate_message(cert)))

    assert len(found) == 1, found
    leaf = found[0]
    assert leaf.subject == "shop.test", leaf
    assert leaf.issuer == "Test CA", leaf
    assert leaf.sans == ("shop.test", "www.shop.test"), leaf.sans


def test_certificate_without_optional_version_field_still_parses():
    """The [0] version is optional. Assuming it is present shifts every
    index by one and reads the issuer out of serialNumber."""
    cert = build_certificate("old.test", "Old CA", with_version=False)
    found = certificates(record(certificate_message(cert)))
    assert found and found[0].subject == "old.test", found


def test_validity_window_is_parsed():
    cert = build_certificate("shop.test", "Test CA")
    leaf = certificates(record(certificate_message(cert)))[0]
    assert leaf.not_before == "2025-04-11 00:00", leaf.not_before
    assert leaf.not_after == "2026-04-11 23:59", leaf.not_after


def test_utctime_year_pivots_at_fifty():
    """RFC 5280: two-digit years below 50 are 20xx. Without the pivot a
    certificate valid to 2049 reads as having expired in 1949."""
    cert = build_certificate("a.test", "CA", not_before="490101000000Z",
                             not_after="500101000000Z")
    leaf = certificates(record(certificate_message(cert)))[0]
    assert leaf.not_before.startswith("2049"), leaf.not_before
    assert leaf.not_after.startswith("1950"), leaf.not_after


def test_generalized_time_is_parsed():
    cert = build_certificate("a.test", "CA", time_tag=GENTIME,
                             not_before="20250411000000Z",
                             not_after="20260411235959Z")
    leaf = certificates(record(certificate_message(cert)))[0]
    assert leaf.not_before == "2025-04-11 00:00", leaf.not_before


def test_self_signed_is_subject_equals_issuer():
    same = Certificate("box.local", "box.local", "", "", ())
    other = Certificate("shop.test", "Test CA", "", "", ())
    empty = Certificate("", "", "", "", ())

    assert same.self_signed
    assert not other.self_signed
    # Two unreadable names are not evidence of self-signing.
    assert not empty.self_signed


def test_leaf_is_first_and_chain_order_is_preserved():
    leaf = build_certificate("shop.test", "Intermediate CA")
    issuer = build_certificate("Intermediate CA", "Root CA")
    found = certificates(record(certificate_message(leaf, issuer)))

    assert len(found) == 2, found
    assert found[0].subject == "shop.test", found[0]
    assert found[1].subject == "Intermediate CA", found[1]


def test_truncated_certificate_yields_nothing_rather_than_nonsense():
    """A half-read certificate parses into confident garbage; a missing one
    merely says nothing. The second is the safe failure."""
    cert = build_certificate("shop.test", "Test CA")
    wire = record(certificate_message(cert))
    assert certificates(wire[: len(wire) // 2]) == ()


def test_malformed_der_does_not_raise():
    """A certificate is attacker-controlled bytes. A crash here is a denial
    of service against the analyst."""
    for payload in (
        record(certificate_message(b"\x30\x82\xff\xff" + b"\x41" * 20)),
        record(certificate_message(b"\x30" * 64)),
        record(certificate_message(b"")),
        record(b"\x0b\xff\xff\xff"),
    ):
        assert certificates(payload) == () or isinstance(
            certificates(payload), tuple
        )


# --------------------------------------------------------------------------
# absence is a fact, not a gap
# --------------------------------------------------------------------------


def test_tls13_certificate_absence_is_explained_not_implied():
    """"Unreadable by design" and "the server presented nothing" are
    different facts. Conflating them turns a protocol property into an
    anomaly."""
    assert cert_visibility(0x0304, False) == (
        "not visible — TLS 1.3 encrypts it"
    )
    assert cert_visibility(0x0303, False) == (
        "not observed in the captured bytes"
    )
    assert cert_visibility(None, False) == "no server handshake observed"
    assert cert_visibility(0x0304, True) == "visible"


# --------------------------------------------------------------------------
# SNI coverage
# --------------------------------------------------------------------------


def test_wildcard_matches_exactly_one_label():
    """`*.example.com` covers `a.example.com` and must NOT cover
    `a.b.example.com`. Getting it backwards turns a real mismatch into a
    pass."""
    cert = Certificate("*.example.com", "CA", "", "", ("*.example.com",))

    assert _name_covered("a.example.com", cert)
    assert not _name_covered("a.b.example.com", cert)
    # A wildcard does not cover the bare domain.
    assert not _name_covered("example.com", cert)


def test_exact_san_match_and_mismatch():
    cert = Certificate("shop.test", "CA", "", "", ("shop.test", "api.shop.test"))
    assert _name_covered("api.shop.test", cert)
    assert not _name_covered("evil.test", cert)


def test_coverage_falls_back_to_subject_when_there_are_no_sans():
    """Deprecated for years, but still what some appliance and internal
    certificates carry. Reporting those as a mismatch would be wrong."""
    cert = Certificate("legacy.test", "CA", "", "", ())
    assert _name_covered("legacy.test", cert)
    assert not _name_covered("other.test", cert)


def test_coverage_is_case_and_trailing_dot_insensitive():
    cert = Certificate("shop.test", "CA", "", "", ("shop.test",))
    assert _name_covered("SHOP.TEST", cert)
    assert _name_covered("shop.test.", cert)


# --------------------------------------------------------------------------
# end to end through the capture layer
# --------------------------------------------------------------------------


def _write_pcap(path: Path, frames) -> None:
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, LINKTYPE_ETHERNET))
        for index, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", 1_700_000_000 + index,
                                     index * 1000, len(frame), len(frame)))
            handle.write(frame)


def _tcp(src, dst, sport, dport, flags, payload=b"") -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                      1024, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     bytes(int(o) for o in src.split(".")),
                     bytes(int(o) for o in dst.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + tcp


def _client_hello_bytes(sni: str) -> bytes:
    """A ClientHello carrying one SNI, enough for the parser to latch on."""
    host = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(host)) + host
    sni_ext_body = struct.pack(">H", len(server_name)) + server_name
    extension = struct.pack(">HH", 0x0000, len(sni_ext_body)) + sni_ext_body

    body = struct.pack(">H", 0x0303) + b"\x22" * 32
    body += b"\x00"                              # session id
    body += struct.pack(">H", 2) + struct.pack(">H", 0xC02F)
    body += b"\x01\x00"                          # compression
    body += struct.pack(">H", len(extension)) + extension
    return record(handshake(0x01, body))


def test_certificate_spanning_tcp_segments_is_reassembled():
    """REGRESSION. A chain is routinely 2-4 kB against a ~1460-byte MSS, so
    per-segment parsing finds the small ServerHello and never the
    Certificate. Here the server flight is split into 1200-byte pieces."""
    big_sans = tuple(f"host{i:04d}.shop.test" for i in range(200))
    cert = build_certificate("shop.test", "Test CA",
                             sans=("shop.test",) + big_sans)
    flight = record(server_hello_body(version=0x0303)) + record(
        certificate_message(cert)
    )
    assert len(flight) > 2400, len(flight)

    pieces = [flight[i:i + 900] for i in range(0, len(flight), 900)]
    assert len(pieces) >= 3, len(pieces)

    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _tcp(client, server, 5555, 443, 0x02),
        _tcp(server, client, 443, 5555, 0x12),
        _tcp(client, server, 5555, 443, 0x18, _client_hello_bytes("shop.test")),
    ]
    frames += [_tcp(server, client, 443, 5555, 0x18, piece)
               for piece in pieces]

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "tls.pcap"
        _write_pcap(path, frames)
        source = PcapSource(path)
        observations = list(source.observations())

    facts = {}
    for obs in observations:
        for key, value in obs.attrs.items():
            if key.startswith("cert_") or key == "tls_version":
                facts.setdefault(key, value)

    assert facts.get("tls_version") == "TLS 1.2", facts
    assert facts.get("cert_subject") == "shop.test", facts
    assert facts.get("cert_issuer") == "Test CA", facts
    assert facts.get("cert_visible") == "visible", facts
    assert facts.get("cert_covers_sni") == "1", facts


def test_sni_mismatch_is_flagged_end_to_end():
    """The client asked for one name and the server presented a certificate
    for another. A mechanical check, and the most useful single thing a
    certificate can tell you."""
    cert = build_certificate("elsewhere.test", "Test CA",
                             sans=("elsewhere.test",))
    flight = record(server_hello_body(version=0x0303)) + record(
        certificate_message(cert)
    )
    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _tcp(client, server, 6666, 443, 0x02),
        _tcp(server, client, 443, 6666, 0x12),
        _tcp(client, server, 6666, 443, 0x18, _client_hello_bytes("shop.test")),
        _tcp(server, client, 443, 6666, 0x18, flight),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mismatch.pcap"
        _write_pcap(path, frames)
        observations = list(PcapSource(path).observations())

    seen = {}
    for obs in observations:
        for key, value in obs.attrs.items():
            if key.startswith("cert_"):
                seen.setdefault(key, value)

    assert seen.get("cert_subject") == "elsewhere.test", seen
    assert seen.get("cert_covers_sni") == "0", seen


def test_handshake_buffer_is_released_and_bounded():
    """The buffer exists for a handshake, not for a session. Left attached it
    is a per-flow leak proportional to how long the connection lives."""
    cert = build_certificate("shop.test", "Test CA", sans=("shop.test",))
    flight = record(server_hello_body(version=0x0303)) + record(
        certificate_message(cert)
    )
    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _tcp(client, server, 7777, 443, 0x02),
        _tcp(server, client, 443, 7777, 0x12),
        _tcp(client, server, 7777, 443, 0x18, _client_hello_bytes("shop.test")),
        _tcp(server, client, 443, 7777, 0x18, flight),
    ]
    # A megabyte of application data after the handshake must not be buffered.
    frames += [_tcp(server, client, 443, 7777, 0x18, b"\x17\x03\x03" +
                    struct.pack(">H", 1000) + b"x" * 1000)
               for _ in range(50)]

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "release.pcap"
        _write_pcap(path, frames)
        source = PcapSource(path)
        list(source.observations())
        flows = list(source._flows.values())

    assert flows, "no flow recorded"
    assert all(flow.handshake is None for flow in flows), (
        "handshake buffer still attached after the certificate was read"
    )


def test_tls13_flow_stops_buffering_once_version_is_known():
    """There is nothing further to wait for on 1.3, so the buffer is dropped
    immediately rather than accumulating application data to the cap."""
    client, server = "10.0.0.5", "203.0.113.9"
    flight = record(server_hello_body(version=0x0303,
                                      supported_versions=0x0304))
    frames = [
        _tcp(client, server, 8888, 443, 0x02),
        _tcp(server, client, 443, 8888, 0x12),
        _tcp(client, server, 8888, 443, 0x18, _client_hello_bytes("shop.test")),
        _tcp(server, client, 443, 8888, 0x18, flight),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "tls13.pcap"
        _write_pcap(path, frames)
        source = PcapSource(path)
        observations = list(source.observations())
        flows = list(source._flows.values())

    assert all(flow.handshake is None for flow in flows), "still buffering"
    facts = {}
    for obs in observations:
        for key, value in obs.attrs.items():
            facts.setdefault(key, value)
    assert facts.get("tls_version") == "TLS 1.3", facts
    assert facts.get("cert_visible") == "not visible — TLS 1.3 encrypts it", facts


# --------------------------------------------------------------------------
# encrypted record shape — what is readable without any key
# --------------------------------------------------------------------------


def app_record(length: int, version: int = 0x0303) -> bytes:
    """One application-data record of `length` ciphertext bytes."""
    return (bytes([0x17]) + struct.pack(">HH", version, length)
            + b"\x00" * length)


def test_record_sizes_are_measured_without_any_key():
    """The premise of the whole feature: a record header is cleartext, so
    length and direction are readable with no key at all."""
    from capture.tlsinfo import record_shape

    shape = record_shape(app_record(16400) + app_record(40)
                         + app_record(16400))
    assert shape.count == 3, shape
    assert shape.largest == 16400, shape
    assert shape.smallest == 40, shape
    assert shape.full == 2, shape      # two near the ceiling
    assert shape.small == 1, shape     # one tiny


def test_handshake_records_are_not_counted_as_activity():
    """Handshake sizes are a property of the TLS implementation, not of what
    the connection is being used for. Counting them makes every
    connection's first burst look identical."""
    from capture.tlsinfo import record_shape

    handshake = bytes([0x16]) + struct.pack(">HH", 0x0303, 512) + b"\x00" * 512
    shape = record_shape(handshake + app_record(100))
    assert shape.count == 1, shape


def test_record_spanning_segments_is_counted_once_at_its_real_size():
    """REGRESSION, and the bug that shipped. A 16 kB record crosses eleven
    1460-byte segments, so a segment beginning mid-record has no header at
    its start. Parsing segments in isolation read payload bytes as length
    fields and reported a 17,796-byte record — a size TLS cannot produce."""
    from capture.tlsinfo import TLS_CIPHERTEXT_MAX, RecordWalker

    stream = app_record(16400) + app_record(300)
    segments = [stream[i:i + 1460] for i in range(0, len(stream), 1460)]
    assert len(segments) > 5, len(segments)

    walker = RecordWalker()
    for segment in segments:
        walker.feed(segment)

    assert not walker.desynced, "in-order stream should stay synchronised"
    assert walker.shape.count == 2, walker.shape
    assert walker.shape.largest == 16400, walker.shape
    # Physics: no record may exceed the ciphertext ceiling.
    assert walker.shape.largest <= TLS_CIPHERTEXT_MAX, walker.shape


def test_per_segment_parsing_undercounts_a_split_stream():
    """Shows WHY the walker is stateful.

    The header validity checks now stop stateless parsing from INVENTING
    records — a mid-record segment is rejected rather than misread, which
    was the original bug. What remains is undercounting: without the
    cross-segment byte counter there is no way to know where the next real
    header begins, so every record after the first is lost.

    Three records split across segments: stateless sees one, the walker
    sees all three.
    """
    from capture.tlsinfo import RecordWalker, record_shape

    stream = app_record(16400) + app_record(16400) + app_record(300)
    segments = [stream[i:i + 1460] for i in range(0, len(stream), 1460)]

    stateless = sum(record_shape(segment).count for segment in segments)

    walker = RecordWalker()
    for segment in segments:
        walker.feed(segment)

    assert walker.shape.count == 3, walker.shape
    assert stateless < walker.shape.count, (stateless, walker.shape.count)


def test_desynchronisation_stops_reporting_rather_than_guessing():
    """A broken counter produces confident nonsense. Measuring less is the
    only honest option — a record stream cannot be resynchronised without
    the record lengths, which are what was just lost."""
    from capture.tlsinfo import RecordWalker

    walker = RecordWalker()
    walker.feed(app_record(100))
    assert walker.shape.count == 1

    # Random bytes where a header should be.
    walker.feed(b"\xde\xad\xbe\xef" * 20)
    assert walker.desynced, "implausible header should desynchronise"

    before = walker.shape.count
    walker.feed(app_record(200))
    assert walker.shape.count == before, "should report nothing after desync"


def test_implausible_length_is_rejected():
    """2^14 + 256 is the ciphertext ceiling. A larger length is not a
    record header."""
    from capture.tlsinfo import RecordWalker

    walker = RecordWalker()
    walker.feed(bytes([0x17]) + struct.pack(">HH", 0x0303, 60000))
    assert walker.desynced
    assert walker.shape.count == 0


def test_bulk_and_interactive_shapes_are_distinguishable():
    """The payoff. Both are encrypted and unreadable; their shapes are not
    the same."""
    from capture.tlsinfo import RecordWalker

    bulk = RecordWalker()
    for _ in range(20):
        bulk.feed(app_record(16400))

    interactive = RecordWalker()
    for _ in range(20):
        interactive.feed(app_record(48))

    assert bulk.shape.full == 20 and bulk.shape.small == 0, bulk.shape
    assert interactive.shape.small == 20 and interactive.shape.full == 0, (
        interactive.shape
    )
    assert bulk.shape.mean > 300 * interactive.shape.mean


def test_record_shape_reaches_the_observations():
    """End to end: the walker's totals must arrive on the burst attrs,
    because that is where the narrator reads them."""
    client, server = "10.0.0.5", "203.0.113.9"
    flight = record(server_hello_body(version=0x0303,
                                      supported_versions=0x0304))
    frames = [
        _tcp(client, server, 9999, 443, 0x02),
        _tcp(server, client, 443, 9999, 0x12),
        _tcp(client, server, 9999, 443, 0x18, _client_hello_bytes("s.test")),
        _tcp(server, client, 443, 9999, 0x18, flight),
    ]
    # Three full records inbound, one tiny outbound.
    frames.append(_tcp(server, client, 443, 9999, 0x18,
                       app_record(16400) * 3))
    frames.append(_tcp(client, server, 9999, 443, 0x18, app_record(60)))

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "shape.pcap"
        _write_pcap(path, frames)
        observations = list(PcapSource(path).observations())

    seen = {}
    for obs in observations:
        for key, value in obs.attrs.items():
            if key.startswith("tls_rec_"):
                seen[key] = value

    assert seen.get("tls_rec_in") == "3", seen
    assert seen.get("tls_rec_in_full") == "3", seen
    assert seen.get("tls_rec_out") == "1", seen
    assert seen.get("tls_rec_out_small") == "1", seen

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
