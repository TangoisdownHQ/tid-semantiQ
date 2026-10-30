"""Server-side TLS: the negotiated version, and the certificate if visible.

WHY THIS EXISTS. The tool's premise is that it reads captures "encrypted or
not", and for a TLS channel it was reporting exactly two things: the SNI the
client asked for, and a hash of the client's own handshake shape. Nothing
about what the server answered with. For a capture that is mostly TLS — which
is most real captures — that left the interpretation thin on precisely the
traffic the tool claims to specialise in.

What is recoverable without keys:

  - the NEGOTIATED version, always. Not the client's offer: a client
    advertising TLS 1.3 that lands on TLS 1.0 is a fact about the server, and
    the ClientHello alone cannot tell you it happened.
  - the SERVER CERTIFICATE, but only up to TLS 1.2. TLS 1.3 encrypts the
    Certificate message under the handshake keys, so from 1.3 onward it is
    not there to read. That is reported as "not visible, encrypted by TLS
    1.3" rather than as absence — "no certificate seen" and "certificate
    unreadable by design" are different facts and conflating them would
    quietly turn a protocol property into an anomaly.

THE DER PARSER IS DELIBERATELY SMALL. It walks structure positionally and
pulls four things: issuer CN, subject CN, the validity window, and the dNSName
entries from the SAN extension. It does not verify signatures, build chains,
or check revocation — there is no trust decision being made here, only
reporting. Everything is bounds-checked and depth-capped because a capture is
adversarial input: a certificate is attacker-controlled bytes, and the cost of
a parser bug here is a crash in the analyst's tool.
"""

from __future__ import annotations

import struct
from typing import Dict, List, NamedTuple, Optional, Tuple

__all__ = [
    "TLS_VERSIONS",
    "RecordShape",
    "EMPTY_SHAPE",
    "record_shape",
    "RecordWalker",
    "TLS_CIPHERTEXT_MAX",
    "TLS_FULL_RECORD",
    "TLS_SMALL_RECORD",
    "TLS_MAX_RECORD",
    "ServerHello",
    "Certificate",
    "server_hello",
    "certificates",
    "version_name",
]

#: Wire version → name. 0x0304 is TLS 1.3, which also appears via the
#: supported_versions extension rather than the legacy version field.
TLS_VERSIONS: Dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_HANDSHAKE = 0x16
_SERVER_HELLO = 0x02
_CERTIFICATE = 0x0B
_EXT_SUPPORTED_VERSIONS = 0x002B

#: Versions at or below which the Certificate message travels in cleartext.
_CLEARTEXT_CERT_MAX = 0x0303


def version_name(version: int) -> str:
    return TLS_VERSIONS.get(version, f"0x{version:04x}")


class ServerHello(NamedTuple):
    version: int
    cipher: int


class Certificate(NamedTuple):
    subject: str
    issuer: str
    not_before: str
    not_after: str
    sans: Tuple[str, ...]

    @property
    def self_signed(self) -> bool:
        """Issuer equals subject.

        A genuine same-name check, not a trust decision: a self-signed
        certificate is perfectly normal on internal infrastructure and is
        also what a hastily stood-up C2 listener presents. Reported, never
        scored on its own.
        """
        return bool(self.subject) and self.subject == self.issuer


# --------------------------------------------------------------------------
# TLS record / handshake framing
# --------------------------------------------------------------------------


_APPLICATION_DATA = 0x17

#: A TLS record maxes out at 2^14 bytes of plaintext. A sender pushing bulk
#: data fills records; one sending a keystroke or a small message does not.
#: That is the whole basis of record-shape analysis.
TLS_MAX_RECORD = 16384

#: Records at or above this are "full" — near the plaintext ceiling, with
#: room for the AEAD tag and padding. Chosen below 16384 because the
#: ciphertext length includes overhead and implementations differ slightly.
TLS_FULL_RECORD = 16000

#: Records at or below this carry a message too small to be bulk data: a
#: keystroke, an ACK, a control frame, a short JSON reply.
TLS_SMALL_RECORD = 100


class RecordShape(NamedTuple):
    """Sizes of the encrypted records on one side of a connection.

    THE POINT OF THIS, which is the hardest thing the tool claims. Once a
    connection is encrypted the content is gone, but the FRAMING is not: a
    TLS record header is cleartext, so its length and direction are readable
    without any key. And length is informative, because a sender filling
    16 kB records is moving bulk data while one emitting 40-byte records is
    sending individual small messages. Those are different activities and
    they remain distinguishable through encryption.

    What this does NOT do is identify an application. Record shape narrows
    "what kind of activity" and nothing more; several applications share any
    given shape, and a deliberate implementation can pad to whatever shape
    it likes. Reported as shape, never as identity.
    """

    count: int
    total: int
    largest: int
    smallest: int
    full: int          # records at or above TLS_FULL_RECORD
    small: int         # records at or below TLS_SMALL_RECORD

    @property
    def mean(self) -> float:
        return self.total / self.count if self.count else 0.0

    def merged(self, other: "RecordShape") -> "RecordShape":
        if not self.count:
            return other
        if not other.count:
            return self
        return RecordShape(
            count=self.count + other.count,
            total=self.total + other.total,
            largest=max(self.largest, other.largest),
            smallest=min(self.smallest, other.smallest),
            full=self.full + other.full,
            small=self.small + other.small,
        )


EMPTY_SHAPE = RecordShape(0, 0, 0, 0, 0, 0)


#: Hard ceiling on a record's declared length. RFC 8446: the ciphertext is
#: at most 2^14 + 256 (plaintext, up to 255 bytes of padding, and the AEAD
#: tag). Anything above this is not a record header.
TLS_CIPHERTEXT_MAX = TLS_MAX_RECORD + 256


class RecordWalker:
    """Walks the TLS record stream of ONE direction of one connection.

    STATEFUL, AND IT HAS TO BE. Records routinely span TCP segments — a
    16 kB record crosses eleven 1460-byte segments — so a segment that
    begins mid-record carries no record header at its start. Parsing each
    segment in isolation reads payload bytes as length fields, which is
    exactly what the first version of this did: it reported a 17,796-byte
    record, a size TLS cannot produce, and the number looked plausible
    enough to print.

    So this tracks how many bytes remain in the record currently in flight,
    skips them, and only then reads the next header. O(1) memory per
    direction — a counter, not a buffer — which matters because a long
    capture has tens of thousands of concurrent flows.

    DESYNCHRONISATION IS DETECTED, NOT ABSORBED. The counter assumes bytes
    arrive in order and exactly once. A retransmission, a gap from a
    snaplen-truncated capture, or an out-of-order segment breaks that
    assumption, and a broken counter produces confident nonsense. So an
    implausible header sets `desynced`, after which this direction reports
    nothing further. Measuring less is the only honest option: there is no
    way to resynchronise a record stream without the record lengths, which
    are the thing that was just lost.
    """

    __slots__ = ("pending", "desynced", "shape")

    def __init__(self) -> None:
        self.pending = 0
        self.desynced = False
        self.shape = EMPTY_SHAPE

    def feed(self, payload: bytes) -> None:
        if self.desynced or not payload:
            return

        pos = 0
        # Finish the record that was still in flight from a previous segment.
        if self.pending:
            consumed = min(self.pending, len(payload))
            self.pending -= consumed
            pos += consumed
            if self.pending:
                return

        count = total = largest = full = small = 0
        smallest = TLS_CIPHERTEXT_MAX + 1

        while pos < len(payload):
            if pos + 5 > len(payload):
                # A header split across segments. Without buffering the few
                # bytes there is no way to read it, so stop here rather than
                # guess — and mark desynced, because the next segment will
                # start mid-header and the counter would be wrong.
                self.desynced = True
                break
            content_type = payload[pos]
            version = struct.unpack(">H", payload[pos + 1:pos + 3])[0]
            length = struct.unpack(">H", payload[pos + 3:pos + 5])[0]

            # Three cheap validity checks. A real record has a known content
            # type, a plausible version, and a length within the ceiling.
            plausible = (
                content_type in (0x14, 0x15, 0x16, _APPLICATION_DATA)
                and 0x0300 <= version <= 0x0304
                and 0 < length <= TLS_CIPHERTEXT_MAX
            )
            if not plausible:
                self.desynced = True
                break

            if content_type == _APPLICATION_DATA:
                count += 1
                total += length
                largest = max(largest, length)
                smallest = min(smallest, length)
                if length >= TLS_FULL_RECORD:
                    full += 1
                if length <= TLS_SMALL_RECORD:
                    small += 1

            pos += 5
            remaining = len(payload) - pos
            if length > remaining:
                # Spans into the next segment; remember how much is left.
                self.pending = length - remaining
                pos = len(payload)
            else:
                pos += length

        if count:
            self.shape = self.shape.merged(RecordShape(
                count=count, total=total, largest=largest,
                smallest=smallest, full=full, small=small,
            ))


def record_shape(payload: bytes) -> RecordShape:
    """Measure the application-data records in a single complete buffer.

    For one self-contained buffer only — a test fixture, or a segment known
    to begin at a record boundary. Real capture flows use `RecordWalker`,
    which carries the cross-segment state this cannot.
    """
    walker = RecordWalker()
    walker.feed(payload)
    return walker.shape


def _handshake_messages(payload: bytes) -> List[Tuple[int, bytes]]:
    """Every (handshake_type, body) in a buffer of TLS records.

    Several handshake messages share one record, and one message can span
    records — both are normal. This reassembles the handshake stream across
    the records present and then walks messages inside it, which is why
    ServerHello and Certificate can be found in a single pass over one
    server-side burst.

    A message whose length runs past what was captured is dropped rather
    than returned short: a half-read certificate parses into confident
    nonsense, where a missing one merely says nothing.
    """
    stream = bytearray()
    pos = 0
    while pos + 5 <= len(payload):
        content_type = payload[pos]
        length = struct.unpack(">H", payload[pos + 3:pos + 5])[0]
        if content_type != _HANDSHAKE:
            # Anything else (ChangeCipherSpec, application data) ends the
            # readable handshake — past this point the stream is encrypted.
            break
        stream += payload[pos + 5:pos + 5 + length]
        pos += 5 + length

    messages: List[Tuple[int, bytes]] = []
    cursor = 0
    while cursor + 4 <= len(stream):
        kind = stream[cursor]
        size = int.from_bytes(stream[cursor + 1:cursor + 4], "big")
        end = cursor + 4 + size
        if end > len(stream):
            break
        messages.append((kind, bytes(stream[cursor + 4:end])))
        cursor = end
        if len(messages) > 16:
            break
    return messages


def server_hello(payload: bytes) -> Optional[ServerHello]:
    """Negotiated version and cipher from a ServerHello.

    TLS 1.3 leaves the legacy version field reading 0x0303 for middlebox
    compatibility and puts the real answer in the supported_versions
    extension. Reading only the legacy field would report every TLS 1.3
    connection as TLS 1.2 — a wrong fact stated confidently, and the exact
    kind of thing an analyst would never think to double-check.
    """
    for kind, body in _handshake_messages(payload):
        if kind != _SERVER_HELLO:
            continue
        try:
            if len(body) < 35:
                return None
            version = struct.unpack(">H", body[0:2])[0]
            pos = 2 + 32
            session_len = body[pos]
            pos += 1 + session_len
            if pos + 3 > len(body):
                return None
            cipher = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 3  # cipher + compression method

            if pos + 2 <= len(body):
                ext_total = struct.unpack(">H", body[pos:pos + 2])[0]
                pos += 2
                end = min(pos + ext_total, len(body))
                while pos + 4 <= end:
                    ext_type, ext_len = struct.unpack(">HH", body[pos:pos + 4])
                    value = body[pos + 4:pos + 4 + ext_len]
                    if ext_type == _EXT_SUPPORTED_VERSIONS and len(value) >= 2:
                        version = struct.unpack(">H", value[0:2])[0]
                    pos += 4 + ext_len
            return ServerHello(version=version, cipher=cipher)
        except (struct.error, IndexError):
            return None
    return None


def certificates(payload: bytes) -> Tuple[Certificate, ...]:
    """Certificates from a Certificate message, leaf first.

    Empty for TLS 1.3, where the message is encrypted — callers decide how to
    say so, using the negotiated version from `server_hello`.
    """
    for kind, body in _handshake_messages(payload):
        if kind != _CERTIFICATE:
            continue
        found: List[Certificate] = []
        try:
            if len(body) < 3:
                return ()
            total = int.from_bytes(body[0:3], "big")
            pos = 3
            end = min(3 + total, len(body))
            while pos + 3 <= end and len(found) < 4:
                size = int.from_bytes(body[pos:pos + 3], "big")
                pos += 3
                if pos + size > end:
                    break
                parsed = _parse_certificate(body[pos:pos + size])
                if parsed is not None:
                    found.append(parsed)
                pos += size
        except (struct.error, IndexError):
            return tuple(found)
        return tuple(found)
    return ()


def cert_visibility(version: Optional[int], seen: bool) -> str:
    """One phrase explaining the certificate's absence, or its presence.

    Exists so that no caller has to re-derive the TLS 1.3 rule, and so the
    distinction between "unreadable by design" and "not there" is made in
    exactly one place.
    """
    if seen:
        return "visible"
    if version is None:
        return "no server handshake observed"
    if version > _CLEARTEXT_CERT_MAX:
        return f"not visible — {version_name(version)} encrypts it"
    return "not observed in the captured bytes"


# --------------------------------------------------------------------------
# minimal DER
# --------------------------------------------------------------------------


class _Node(NamedTuple):
    tag: int
    value: bytes


def _children(data: bytes, depth: int = 0) -> List[_Node]:
    """Immediate TLV children of a constructed DER value.

    Depth is capped by the caller chain rather than here; `_parse_certificate`
    never recurses more than a handful of levels, which is what keeps a
    deeply-nested hostile certificate from exhausting the stack.
    """
    out: List[_Node] = []
    pos = 0
    while pos < len(data):
        if pos + 2 > len(data):
            break
        tag = data[pos]
        length = data[pos + 1]
        pos += 2
        if length & 0x80:
            count = length & 0x7F
            # Indefinite length (0x80) is not valid DER, and a 5+ byte length
            # is larger than any certificate this will ever see.
            if count == 0 or count > 4 or pos + count > len(data):
                break
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        if pos + length > len(data):
            break
        out.append(_Node(tag, data[pos:pos + length]))
        pos += length
        if len(out) > 64:
            break
    return out


#: OIDs, DER-encoded. commonName, and subjectAltName.
_OID_CN = bytes((0x55, 0x04, 0x03))
_OID_SAN = bytes((0x55, 0x1D, 0x11))


def _common_name(name: bytes) -> str:
    """The commonName from an X.501 Name, or "".

    Name is a SEQUENCE OF SET OF SEQUENCE{OID, value}. Only CN is pulled —
    O and OU would be useful for a human but CN is what gets compared against
    an SNI, which is the comparison worth making.
    """
    for rdn in _children(name):
        for atv in _children(rdn.value):
            parts = _children(atv.value)
            if len(parts) >= 2 and parts[0].value == _OID_CN:
                return parts[1].value.decode("utf-8", "replace")
    return ""


def _time(node: _Node) -> str:
    """UTCTime or GeneralizedTime, normalised to an ISO-ish date.

    Two-digit years in UTCTime pivot at 50 per RFC 5280 — without the pivot a
    certificate valid to 2049 reads as having expired in 1949.
    """
    raw = node.value.decode("ascii", "replace").rstrip("Z")
    if len(raw) < 10:
        return raw
    if node.tag == 0x17:  # UTCTime: YYMMDDHHMMSS
        year = int(raw[0:2])
        century = 1900 if year >= 50 else 2000
        return (f"{century + year:04d}-{raw[2:4]}-{raw[4:6]}"
                f" {raw[6:8]}:{raw[8:10]}")
    return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]} {raw[8:10]}:{raw[10:12]}"


def _sans(extensions: bytes) -> Tuple[str, ...]:
    """dNSName entries from the subjectAltName extension."""
    names: List[str] = []
    for extension in _children(extensions):
        parts = _children(extension.value)
        if not parts or parts[0].value != _OID_SAN:
            continue
        # extnValue is an OCTET STRING wrapping the GeneralNames SEQUENCE.
        payload = parts[-1].value
        for general in _children(payload):
            for entry in _children(general.value):
                # dNSName is context tag [2] of GeneralName.
                if entry.tag == 0x82:
                    names.append(entry.value.decode("ascii", "replace"))
            if general.tag == 0x82:
                names.append(general.value.decode("ascii", "replace"))
        if names:
            break
    return tuple(names[:32])


def _parse_certificate(der: bytes) -> Optional[Certificate]:
    """Pull issuer CN, subject CN, validity and SANs out of one certificate.

    Positional walk of tbsCertificate, which is fixed by the ASN.1 module
    except for the optional explicit version at [0]. Handling that optional
    field is what keeps every subsequent index correct — skip it and issuer
    gets read out of serialNumber.
    """
    try:
        outer = _children(der)
        if not outer:
            return None
        # THREE levels, not two, and the middle one is easy to lose:
        #   der          -> [Certificate SEQUENCE]
        #   Certificate  -> [tbsCertificate, signatureAlgorithm, signature]
        #   tbsCertificate -> the fields walked below
        # Collapsing the middle level makes `tbs` three elements long, the
        # optional-version test inspects tbsCertificate's own tag instead of
        # its first field, and every subsequent index is wrong — which
        # presented as "no certificate observed" on every TLS 1.2 flow in a
        # real capture while the bytes were sitting right there.
        signed = _children(outer[0].value)
        if not signed:
            return None
        tbs = _children(signed[0].value)
        if not tbs:
            return None

        index = 1 if tbs[0].tag == 0xA0 else 0  # optional [0] version
        index += 1  # serialNumber
        index += 1  # signature AlgorithmIdentifier
        if index + 3 >= len(tbs):
            return None

        issuer = _common_name(tbs[index].value)
        validity = _children(tbs[index + 1].value)
        subject = _common_name(tbs[index + 2].value)

        not_before = _time(validity[0]) if len(validity) > 0 else ""
        not_after = _time(validity[1]) if len(validity) > 1 else ""

        sans: Tuple[str, ...] = ()
        for node in tbs[index + 3:]:
            if node.tag == 0xA3:  # extensions [3]
                inner = _children(node.value)
                if inner:
                    sans = _sans(inner[0].value)
                break

        return Certificate(
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            sans=sans,
        )
    except (struct.error, IndexError, UnicodeDecodeError, ValueError):
        return None
