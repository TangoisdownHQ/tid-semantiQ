"""Header decoders: link -> IP -> TCP/UDP, plus TLS ClientHello and DNS.

Scope is deliberately narrow — only what the v0.1 primitives consume. Every
decoder returns None on anything malformed or truncated rather than raising,
because a capture is adversarial input: a crash on a crafted packet is a
denial of service against the analyst, and a snaplen-truncated frame is
normal, not exceptional.
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Dict, List, NamedTuple, Optional, Tuple

from core.suffixes import party
from capture.pcapfile import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
)

__all__ = ["IPPacket", "Segment", "DNS_RCODES", "decode_ip", "decode_tcp", "decode_udp",
           "client_hello", "ClientHello", "dns_question", "dns_message",
           "DnsMessage", "DnsRecord", "decode_icmp", "IcmpMessage",
           "PROTO_ICMP", "PROTO_ICMPV6", "is_private", "scope_of",
           "ssh_banner", "ntp_info", "NtpInfo", "dhcp_info", "DhcpInfo",
           "quic_info", "QuicInfo", "ethernet_src_mac"]

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_VLAN = 0x8100
_ETHERTYPE_QINQ = 0x88A8

PROTO_TCP = 6
PROTO_UDP = 17


class IPPacket(NamedTuple):
    src: str
    dst: str
    proto: int
    payload: bytes


class Segment(NamedTuple):
    sport: int
    dport: int
    payload: bytes
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False


def decode_ip(linktype: int, frame: bytes) -> Optional[IPPacket]:
    """Link layer through IP, returning the transport payload."""
    data = _strip_link(linktype, frame)
    if data is None or not data:
        return None

    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        total_len = struct.unpack(">H", data[2:4])[0]
        proto = data[9]
        src = str(ipaddress.IPv4Address(data[12:16]))
        dst = str(ipaddress.IPv4Address(data[16:20]))
        # Trust the header length over the buffer: trailing padding is common
        # on short frames and would otherwise be counted as payload.
        end = total_len if 0 < total_len <= len(data) else len(data)
        return IPPacket(src, dst, proto, data[ihl:end])

    if version == 6:
        if len(data) < 40:
            return None
        payload_len = struct.unpack(">H", data[4:6])[0]
        nxt = data[6]
        src = str(ipaddress.IPv6Address(data[8:24]))
        dst = str(ipaddress.IPv6Address(data[24:40]))
        body = data[40:40 + payload_len] if payload_len else data[40:]
        # Walk the extension-header chain to reach the transport header.
        # Without this, any packet carrying a routing or options header
        # decodes as an unknown protocol and silently disappears.
        while nxt in (0, 43, 44, 60):
            if len(body) < 8:
                return None
            ext_len = (body[1] + 1) * 8
            nxt, body = body[0], body[ext_len:]
        return IPPacket(src, dst, nxt, body)

    return None


def ethernet_src_mac(linktype: int, frame: bytes) -> Optional[str]:
    """The source MAC of an Ethernet frame, as `aa:bb:cc:dd:ee:ff`, or None.

    Only Ethernet carries a usable per-host source MAC in a fixed place;
    the cooked and raw link types do not, and for them this returns None
    rather than reading six arbitrary bytes as an address.

    A source MAC only names the DEVICE for a host on the local segment —
    for anything beyond the gateway the frame's source MAC is the gateway's,
    not the remote endpoint's. The caller is responsible for that gate (it
    attributes MACs only to private-scope addresses); this function just
    reports what the frame says.
    """
    if linktype != LINKTYPE_ETHERNET or len(frame) < 12:
        return None
    return ":".join(f"{b:02x}" for b in frame[6:12])


def _strip_link(linktype: int, frame: bytes) -> Optional[bytes]:
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_NULL:
        return frame[4:] if len(frame) > 4 else None
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        offset = 14
        # VLAN and QinQ tags stack; skip each 4-byte tag to reach the real
        # ethertype. Captures from a trunk port or a tagged SPAN are full of
        # these and dropping them loses whole network segments.
        while ethertype in (_ETHERTYPE_VLAN, _ETHERTYPE_QINQ):
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack(">H", frame[offset + 2:offset + 4])[0]
            offset += 4
        if ethertype in (_ETHERTYPE_IPV4, _ETHERTYPE_IPV6):
            return frame[offset:]
        return None
    if linktype == LINKTYPE_LINUX_SLL:
        return frame[16:] if len(frame) > 16 else None
    if linktype == LINKTYPE_LINUX_SLL2:
        return frame[20:] if len(frame) > 20 else None
    return None


def decode_tcp(data: bytes) -> Optional[Segment]:
    if len(data) < 20:
        return None
    sport, dport = struct.unpack(">HH", data[0:4])
    offset = (data[12] >> 4) * 4
    if offset < 20 or len(data) < offset:
        return None
    flags = data[13]
    return Segment(
        sport=sport,
        dport=dport,
        payload=data[offset:],
        syn=bool(flags & 0x02),
        ack=bool(flags & 0x10),
        fin=bool(flags & 0x01),
        rst=bool(flags & 0x04),
    )


def decode_udp(data: bytes) -> Optional[Segment]:
    if len(data) < 8:
        return None
    sport, dport, length = struct.unpack(">HHH", data[0:6])
    end = length if 8 <= length <= len(data) else len(data)
    return Segment(sport=sport, dport=dport, payload=data[8:end])


# --------------------------------------------------------------------------
# TLS ClientHello
# --------------------------------------------------------------------------


class ClientHello(NamedTuple):
    sni: Optional[str]
    version: int
    cipher_count: int
    extensions: Tuple[int, ...]
    fingerprint: str
    #: Whether the client sent GREASE (RFC 8701). This is stripped before the
    #: fingerprint is hashed, but kept here because its mere presence is a
    #: strong, honest library discriminator — browsers and utls-based tools
    #: send it; most command-line and library TLS stacks do not.
    uses_grease: bool = False
    #: ALPN protocols offered, e.g. ("h2", "http/1.1"). Offering h2 is
    #: browser-like; its absence is typical of a minimal client.
    alpn: Tuple[str, ...] = ()


def client_hello(payload: bytes) -> Optional[ClientHello]:
    """Parse a TLS ClientHello for SNI and a handshake-shape fingerprint.

    `fingerprint` is OUR OWN hash over (version, cipher suites, extension
    list, groups, sig algs) with GREASE values removed. It is deliberately
    NOT JA3 or JA4:

      - JA4 proper is published under the FoxIO License 1.1, which restricts
        commercial use. This repository is Apache-2.0, which explicitly
        permits it — so vendoring JA4 would hand downstream users a licence
        that promises more than the embedded component allows. Going open
        does not unlock JA4; it makes the conflict worse. Hence an own hash.
      - A fingerprint identifies the TLS *library*, not intent. Anything
        using utls mimics Chrome exactly, so a mimicking implant yields
        Chrome's fingerprint. This value is a rarity feature joined to other
        evidence, never a verdict — which is why it lands in `attrs` for
        `Fanout`/`Rarity` to use and has no primitive of its own.

    GREASE values (RFC 8701) are stripped before hashing, otherwise a browser
    that randomises them produces a different fingerprint every connection
    and rarity scoring sees infinite novelty.
    """
    try:
        if len(payload) < 9 or payload[0] != 0x16:
            return None
        if payload[5] != 0x01:  # handshake type: client_hello
            return None

        pos = 9
        version = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2 + 32  # version + random

        session_len = payload[pos]
        pos += 1 + session_len

        cipher_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        ciphers = [
            struct.unpack(">H", payload[pos + i:pos + i + 2])[0]
            for i in range(0, cipher_len, 2)
        ]
        pos += cipher_len

        comp_len = payload[pos]
        pos += 1 + comp_len

        extensions: List[int] = []
        sni: Optional[str] = None
        groups: List[int] = []
        sigalgs: List[int] = []
        alpn: List[str] = []

        if pos + 2 <= len(payload):
            ext_total = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2
            end = min(pos + ext_total, len(payload))
            while pos + 4 <= end:
                ext_type, ext_len = struct.unpack(">HH", payload[pos:pos + 4])
                body = payload[pos + 4:pos + 4 + ext_len]
                pos += 4 + ext_len
                extensions.append(ext_type)
                if ext_type == 0x0000 and len(body) >= 5:
                    name_len = struct.unpack(">H", body[3:5])[0]
                    sni = body[5:5 + name_len].decode("ascii", "replace") or None
                elif ext_type == 0x0010 and len(body) >= 2:
                    # ALPN: a 2-byte list length, then length-prefixed names.
                    alpn_end = min(2 + struct.unpack(">H", body[0:2])[0], len(body))
                    ap = 2
                    while ap + 1 <= alpn_end:
                        nlen = body[ap]
                        name = body[ap + 1:ap + 1 + nlen]
                        if len(name) == nlen and nlen:
                            alpn.append(name.decode("ascii", "replace"))
                        ap += 1 + nlen
                elif ext_type == 0x000A and len(body) >= 2:
                    glen = struct.unpack(">H", body[0:2])[0]
                    groups = [
                        struct.unpack(">H", body[2 + i:4 + i])[0]
                        for i in range(0, min(glen, len(body) - 2), 2)
                    ]
                elif ext_type == 0x000D and len(body) >= 2:
                    slen = struct.unpack(">H", body[0:2])[0]
                    sigalgs = [
                        struct.unpack(">H", body[2 + i:4 + i])[0]
                        for i in range(0, min(slen, len(body) - 2), 2)
                    ]

        clean_ciphers = [c for c in ciphers if not _is_grease(c)]
        clean_exts = [e for e in extensions if not _is_grease(e)]
        uses_grease = (
            any(_is_grease(c) for c in ciphers)
            or any(_is_grease(e) for e in extensions)
        )
        material = "|".join(
            [
                str(version),
                "-".join(map(str, clean_ciphers)),
                "-".join(map(str, clean_exts)),
                "-".join(str(g) for g in groups if not _is_grease(g)),
                "-".join(str(s) for s in sigalgs if not _is_grease(s)),
            ]
        )
        digest = hashlib.sha256(material.encode()).hexdigest()[:16]

        return ClientHello(
            sni=sni,
            version=version,
            cipher_count=len(clean_ciphers),
            extensions=tuple(clean_exts),
            fingerprint=digest,
            uses_grease=uses_grease,
            alpn=tuple(alpn),
        )
    except (struct.error, IndexError, UnicodeDecodeError):
        return None


def _is_grease(value: int) -> bool:
    """RFC 8701 GREASE: 0x?A?A where both bytes match."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------


_QTYPES: Dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS",
    48: "DNSKEY", 65: "HTTPS", 255: "ANY",
}


#: DNS response codes worth naming. Anything else is reported numerically.
DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsRecord(NamedTuple):
    """One resource record from an answer section."""

    name: str
    rtype: str
    ttl: int
    #: Address for A/AAAA, target name for CNAME/NS/PTR, "" for anything
    #: whose rdata this decoder does not interpret.
    value: str


class DnsMessage(NamedTuple):
    qname: str
    qtype: str
    is_response: bool
    rcode: int
    answers: Tuple[DnsRecord, ...]
    #: True when the answer section was cut short — a snaplen-truncated
    #: capture is normal, and partial answers are still worth having, but a
    #: consumer must be able to tell "no answers" from "answers not visible".
    truncated: bool


def _read_name(payload: bytes, pos: int) -> Optional[Tuple[str, int]]:
    """Read a possibly-compressed domain name. Returns (name, next_pos).

    `next_pos` is the offset after the name AS ENCODED AT `pos` — following a
    pointer must not advance the caller's cursor past the pointer itself,
    which is the classic way to desynchronise a record walk.

    Compression is mandatory to support here, unlike in the question section:
    essentially every real answer encodes its owner name as a pointer back to
    the question. Refusing pointers would mean parsing no answers at all.

    Loops are the hazard — a pointer chain can be crafted to cycle forever,
    and a decoder that follows it hangs on a packet an attacker chose. Guarded
    two ways: every jump must go strictly BACKWARDS (which is all the wire
    format permits and makes a cycle impossible), and the jump count is
    capped regardless.
    """
    labels: List[str] = []
    jumps = 0
    cursor = pos
    after: Optional[int] = None

    while True:
        if cursor >= len(payload):
            return None
        length = payload[cursor]

        if length == 0:
            cursor += 1
            break

        if length & 0xC0 == 0xC0:
            if cursor + 2 > len(payload):
                return None
            target = struct.unpack(">H", payload[cursor:cursor + 2])[0] & 0x3FFF
            if after is None:
                after = cursor + 2
            # Strictly backwards only. A forward or self pointer cannot occur
            # in a well-formed message and is the shape a loop needs.
            if target >= cursor:
                return None
            jumps += 1
            if jumps > 16:
                return None
            cursor = target
            continue

        if length & 0xC0:
            return None  # reserved label type
        end = cursor + 1 + length
        if end > len(payload):
            return None
        labels.append(payload[cursor + 1:end].decode("ascii", "replace"))
        cursor = end
        if len(labels) > 128:
            return None

    return ".".join(labels), (after if after is not None else cursor)


def dns_message(payload: bytes) -> Optional[DnsMessage]:
    """Parse a DNS message: the first question, plus the answer section.

    THE ANSWER SECTION WAS NOT READ AT ALL UNTIL NOW, and that omission was
    load-bearing in a bad way. Without it the tool could never learn which
    address a name resolved to, so an endpoint could only be named if it
    happened to speak TLS with an SNI — in a real capture that left most of
    117 addresses as bare IPs in a report whose whole job is to say what is
    going on. It also meant CNAME chains and TTLs were invisible.

    Only the question's rcode and the answer section are read. Authority and
    additional sections are skipped: NS/SOA glue is high-volume and answers a
    question nobody has asked of this tool yet.

    Returns partial answers on a truncated message rather than failing — a
    snaplen-clipped response still carries its rcode, and discarding the whole
    record because the tail is missing loses more than it protects.
    """
    try:
        if len(payload) < 12:
            return None
        flags, qdcount, ancount = struct.unpack(">HHH", payload[2:8])
        if qdcount < 1:
            return None

        read = _read_name(payload, 12)
        if read is None:
            return None
        qname, pos = read
        if not qname or pos + 4 > len(payload):
            return None
        qtype = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 4  # qtype + qclass

        answers: List[DnsRecord] = []
        truncated = False
        for _ in range(min(ancount, 64)):
            record = _read_name(payload, pos)
            if record is None:
                truncated = True
                break
            name, pos = record
            if pos + 10 > len(payload):
                truncated = True
                break
            rtype, _rclass, ttl, rdlength = struct.unpack(
                ">HHIH", payload[pos:pos + 10]
            )
            pos += 10
            if pos + rdlength > len(payload):
                truncated = True
                break
            answers.append(
                DnsRecord(
                    name=name,
                    rtype=_QTYPES.get(rtype, str(rtype)),
                    ttl=ttl,
                    value=_rdata(payload, pos, rdlength, rtype),
                )
            )
            pos += rdlength

        return DnsMessage(
            qname=qname,
            qtype=_QTYPES.get(qtype, str(qtype)),
            is_response=bool(flags & 0x8000),
            rcode=flags & 0x000F,
            answers=tuple(answers),
            truncated=truncated,
        )
    except (struct.error, IndexError, UnicodeDecodeError, ValueError):
        return None


def _rdata(payload: bytes, pos: int, length: int, rtype: int) -> str:
    """Interpret rdata for the record types worth naming.

    Deliberately narrow. An address and a CNAME target are what let the
    narrator put a name on an endpoint; MX preferences and TXT strings are
    not, and a decoder that guesses at every type is a decoder with more
    places to be wrong on hostile input.
    """
    try:
        if rtype == 1 and length == 4:
            return str(ipaddress.IPv4Address(payload[pos:pos + 4]))
        if rtype == 28 and length == 16:
            return str(ipaddress.IPv6Address(payload[pos:pos + 16]))
        if rtype in (5, 2, 12):  # CNAME, NS, PTR
            read = _read_name(payload, pos)
            return read[0] if read else ""
    except (ValueError, struct.error, IndexError):
        return ""
    return ""


def dns_question(payload: bytes) -> Optional[Tuple[str, str, bool, int]]:
    """First question from a DNS message: (qname, qtype, is_response, rcode).

    Kept as the narrow entry point for callers that only need the question —
    it is present in both queries and responses, which keeps one code path for
    both directions, and it is where the tunnelling signal lives, since the
    encoder has to put its data in the name.

    `rcode` was added after running against a real capture: 11,859 of 13,197
    responses were NXDOMAIN, which is a loud signal for DGA traffic,
    tunnelling and resolver misconfiguration alike — and the parser was
    discarding it, so no rule could ever see it. It is meaningless on a
    query, where it reads 0.
    """
    message = dns_message(payload)
    if message is None:
        return None
    return (message.qname, message.qtype, message.is_response, message.rcode)


PROTO_ICMP = 1
PROTO_ICMPV6 = 58

#: (type, code) → wording, for the messages worth naming. An error names the
#: reason a connection failed, which is the half of the connectivity story
#: that TCP flags alone cannot tell: a SYN with no reply and a SYN answered
#: by "administratively prohibited" look identical at the TCP layer.
_ICMP4_NAMES = {
    (0, None): "echo reply",
    (8, None): "echo request",
    (3, 0): "network unreachable",
    (3, 1): "host unreachable",
    (3, 2): "protocol unreachable",
    (3, 3): "port unreachable",
    (3, 4): "fragmentation needed",
    (3, 9): "network administratively prohibited",
    (3, 10): "host administratively prohibited",
    (3, 13): "communication administratively prohibited",
    (5, None): "redirect",
    (11, 0): "TTL exceeded in transit",
    (11, 1): "fragment reassembly time exceeded",
    (12, None): "parameter problem",
}

_ICMP6_NAMES = {
    (129, None): "echo reply",
    (128, None): "echo request",
    (1, 0): "no route to destination",
    (1, 1): "administratively prohibited",
    (1, 2): "beyond scope of source address",
    (1, 3): "address unreachable",
    (1, 4): "port unreachable",
    (2, None): "packet too big",
    (3, 0): "hop limit exceeded in transit",
    (3, 1): "fragment reassembly time exceeded",
    (4, None): "parameter problem",
}

#: Types that carry the packet that caused them. RFC 792 quotes the original
#: IP header plus the first 8 transport bytes, which is exactly enough to
#: recover the destination and port that failed.
_ICMP4_ERRORS = frozenset({3, 4, 5, 11, 12})
_ICMP6_ERRORS = frozenset({1, 2, 3, 4})


class IcmpMessage(NamedTuple):
    kind: int
    code: int
    name: str
    is_error: bool
    #: Echo identifier and sequence, for the echo types. A tunnel that rides
    #: ICMP echo tends to hold one identifier and walk the sequence, which is
    #: only visible if both are read.
    echo_id: Optional[int]
    echo_seq: Optional[int]
    #: The quoted packet from an error: what was being sent when it failed.
    #: This is the whole reason errors are worth decoding — it names the
    #: destination and port rather than only the router that complained.
    quoted_dst: Optional[str]
    quoted_proto: Optional[int]
    quoted_dport: Optional[int]
    payload_len: int


def decode_icmp(proto: int, data: bytes) -> Optional[IcmpMessage]:
    """ICMP or ICMPv6, including the packet quoted inside an error.

    ICMP was dropped on the floor before this existed: `_handle_frame`
    handled TCP and UDP and returned nothing for everything else, so a
    capture full of "host unreachable" told the reader nothing at all. That
    matters most where the tool had just started reporting connection
    outcomes — "4 connections never answered" is a symptom, and the ICMP
    error is the diagnosis sitting in the same capture.
    """
    if len(data) < 8:
        return None
    try:
        kind, code = data[0], data[1]
        names = _ICMP4_NAMES if proto == PROTO_ICMP else _ICMP6_NAMES
        errors = _ICMP4_ERRORS if proto == PROTO_ICMP else _ICMP6_ERRORS

        name = names.get((kind, code)) or names.get((kind, None))
        if name is None:
            name = f"type {kind} code {code}"

        is_error = kind in errors
        echo_id = echo_seq = None
        if not is_error and kind in (0, 8, 128, 129):
            echo_id, echo_seq = struct.unpack(">HH", data[4:8])

        quoted_dst = quoted_proto = quoted_dport = None
        if is_error:
            quoted = _quoted_packet(proto, data[8:])
            if quoted is not None:
                quoted_dst, quoted_proto, quoted_dport = quoted

        return IcmpMessage(
            kind=kind,
            code=code,
            name=name,
            is_error=is_error,
            echo_id=echo_id,
            echo_seq=echo_seq,
            quoted_dst=quoted_dst,
            quoted_proto=quoted_proto,
            quoted_dport=quoted_dport,
            payload_len=max(0, len(data) - 8),
        )
    except (struct.error, IndexError, ValueError):
        return None


def _quoted_packet(
    proto: int, body: bytes
) -> Optional[Tuple[str, int, Optional[int]]]:
    """(destination, protocol, dport) of the packet an error is about.

    Only the header is quoted, so this reads the destination out of the IP
    header and the port out of the first 8 transport bytes. Both are present
    by specification; anything shorter is a truncated capture and declines
    rather than guessing.
    """
    try:
        if proto == PROTO_ICMP:
            if len(body) < 20:
                return None
            ihl = (body[0] & 0x0F) * 4
            if ihl < 20:
                return None
            inner_proto = body[9]
            dst = str(ipaddress.IPv4Address(body[16:20]))
            transport = body[ihl:ihl + 8]
        else:
            if len(body) < 40:
                return None
            inner_proto = body[6]
            dst = str(ipaddress.IPv6Address(body[24:40]))
            transport = body[40:48]

        dport = None
        if inner_proto in (PROTO_TCP, PROTO_UDP) and len(transport) >= 4:
            dport = struct.unpack(">H", transport[2:4])[0]
        return dst, inner_proto, dport
    except (struct.error, IndexError, ValueError):
        return None


def registrable_zone(qname: str) -> str:
    """Parent zone of a query name, as the Channel dimension for DNS.

    Uses the Public Suffix List. The previous label-count approximation made
    `a.foo.co.uk` and `b.bar.co.uk` share the zone `co.uk`, which pooled
    unrelated domains into one channel and diluted exactly the per-zone
    cardinality that tunnelling detection depends on — a tunnel under one
    zone was averaged against ordinary lookups under every other.

    NOTE: this value is part of the DNS `Channel.dims`, so it participates in
    baseline keys. Moving off the approximation changes the key for any name
    under a multi-part suffix, and prevalence history for those zones starts
    again. Simple suffixes are unaffected.
    """
    return party(qname)


#: Ranges reserved for documentation and examples (RFC 5737, RFC 3849).
#: Python reports these as "private" because they are not globally routable,
#: which is true but misleading: they are not somebody's LAN either.
_DOC_RANGES = (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)


def scope_of(address: str) -> str:
    """What kind of address this is, in words.

    `is_private` answers a yes/no question and the report was printing its
    answer as "private (RFC1918/link-local)" — which is wrong for a
    documentation address, wrong for loopback, and wrong for multicast.
    Python groups all of them under `is_private` because none is globally
    routable, and that grouping is useful for suppressing noise but not for
    telling a reader what they are looking at.

    Naming the actual reason costs nothing and is the difference between
    "this host is on a LAN" and "this host is 127.0.0.1".
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    if ip.is_loopback:
        return "loopback (this machine)"
    if ip.is_link_local:
        return "link-local (unrouted, autoconfigured)"
    if ip.is_multicast:
        return "multicast"
    if any(ip in ipaddress.ip_network(net) for net in _DOC_RANGES):
        return "reserved for documentation (RFC 5737/3849)"
    if ip.is_private:
        return "private (RFC1918 — a LAN address)"
    if ip.is_reserved:
        return "reserved"
    return "public"


def is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast


# --------------------------------------------------------------------------
# Cleartext service metadata: SSH, NTP, DHCP
#
# Three protocols that announce real facts before (or without) any
# encryption. An SSH connection encrypts everything AFTER both sides have
# exchanged a cleartext banner naming their software and version; NTP is
# never encrypted and its header says who is asking whom for time and from
# what stratum; DHCP is where a device introduces itself to the network,
# hostname included. None of this needs a key, and all of it is the kind of
# meaning this tool exists to surface.
# --------------------------------------------------------------------------


def ssh_banner(payload: bytes) -> Optional[str]:
    """The SSH identification string, if this payload starts with one.

    RFC 4253 §4.2: the first thing each side sends is
    `SSH-protoversion-softwareversion SP comments CRLF`, in the clear — the
    one part of an SSH session that names the implementation ("OpenSSH_9.6",
    "libssh_0.10.4", "paramiko_3.4.0") before encryption starts. Returned
    without the trailing CRLF, capped at the RFC's 255 bytes.
    """
    if not payload.startswith(b"SSH-"):
        return None
    line = payload.split(b"\n", 1)[0].rstrip(b"\r")
    if len(line) > 255:
        return None
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    # "SSH-2.0-" alone is not a banner, and a lone "SSH-" prefix in random
    # application data should not register as one.
    return text if len(text) > len("SSH-2.0-") else None


class NtpInfo(NamedTuple):
    version: int
    mode: str          # "client", "server", "broadcast", ...
    stratum: Optional[int]   # servers only; None on queries


_NTP_MODES = {1: "symmetric-active", 2: "symmetric-passive", 3: "client",
              4: "server", 5: "broadcast", 6: "control"}


def ntp_info(payload: bytes) -> Optional[NtpInfo]:
    """Version, mode and (for replies) stratum from an NTP header.

    NTP is cleartext by design, and its first byte already interprets the
    exchange: mode 3 is a client asking, mode 4 is a server answering, mode
    5 is a broadcast. Stratum is how far the answering clock is from a
    reference — 1 is attached to one, 15 is the far edge, and 0 in a reply
    is a "kiss-of-death" refusal. Only parsed when the shape is plausible,
    because port 123 alone does not make a datagram NTP.
    """
    if len(payload) < 48:
        return None
    first = payload[0]
    version = (first >> 3) & 0x07
    mode = first & 0x07
    if version not in (1, 2, 3, 4) or mode not in _NTP_MODES:
        return None
    stratum: Optional[int] = payload[1]
    if mode not in (2, 4, 5):      # only an answering side reports stratum
        stratum = None
    return NtpInfo(version=version, mode=_NTP_MODES[mode], stratum=stratum)


class DhcpInfo(NamedTuple):
    kind: str                 # DISCOVER / OFFER / REQUEST / ACK / ...
    hostname: Optional[str]   # option 12, the device's own name
    address: Optional[str]    # the address the exchange is about


_DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
               5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def dhcp_info(payload: bytes) -> Optional[DhcpInfo]:
    """Message type, hostname and subject address from a DHCP message.

    DHCP is where a device introduces itself: option 12 carries the name the
    device calls ITSELF — not a name somebody resolved for it — which makes
    it the best label a LAN host will ever volunteer. The subject address is
    the one the exchange is about: `yiaddr` when the server assigns one,
    option 50 when the client requests one, `ciaddr` when the client already
    has one. The 0.0.0.0 a still-unconfigured client sends from is never
    used for anything.
    """
    # Fixed BOOTP header (236 bytes) + the DHCP magic cookie.
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    op = payload[0]
    if op not in (1, 2):
        return None

    def _addr(offset: int) -> Optional[str]:
        raw = payload[offset:offset + 4]
        if len(raw) < 4 or raw == b"\x00\x00\x00\x00":
            return None
        return ".".join(str(b) for b in raw)

    ciaddr, yiaddr = _addr(12), _addr(16)

    kind = ""
    hostname: Optional[str] = None
    requested: Optional[str] = None
    pos = 240
    while pos + 2 <= len(payload):
        option = payload[pos]
        if option == 0xFF:
            break
        if option == 0x00:      # pad
            pos += 1
            continue
        length = payload[pos + 1]
        body = payload[pos + 2:pos + 2 + length]
        pos += 2 + length
        if option == 53 and body:
            kind = _DHCP_TYPES.get(body[0], f"type-{body[0]}")
        elif option == 12 and body:
            hostname = body.decode("ascii", "replace").strip("\x00") or None
        elif option == 50 and len(body) >= 4:
            requested = ".".join(str(b) for b in body[:4])

    if not kind:
        return None
    # The address this exchange is ABOUT, by who can know it: an assignment
    # (yiaddr) outranks a request (option 50) outranks a renewal's ciaddr.
    address = yiaddr or requested or ciaddr
    return DhcpInfo(kind=kind, hostname=hostname, address=address)


# --------------------------------------------------------------------------
# QUIC (HTTP/3's transport)
# --------------------------------------------------------------------------


class QuicInfo(NamedTuple):
    version: str       # "v1 (RFC 9000)", "negotiation", "draft-29", hex
    packet: str        # "initial", "0-rtt", "handshake", "retry", "long-header"


_QUIC_VERSIONS = {
    0x00000001: "v1 (RFC 9000)",
    0x6B3343CF: "v2 (RFC 9369)",
    0xFF00001D: "draft-29",
    0xFF00001C: "draft-28",
}

_QUIC_V1_TYPES = {0: "initial", 1: "0-rtt", 2: "handshake", 3: "retry"}


def quic_info(payload: bytes) -> Optional[QuicInfo]:
    """Version and packet type from a QUIC long header, or None.

    QUIC is the transport under HTTP/3, and it encrypts MORE than TLS over
    TCP does: even the Initial packet's contents — where the ClientHello and
    its SNI live — are sealed with AEAD keys (derived from public values,
    but deriving them still requires AES-GCM, which stdlib does not provide
    and this repository deliberately does not implement). So what is honestly
    readable without any crypto is the long-header envelope: the version,
    and the packet type. That is enough to say "this host speaks HTTP/3 to
    this endpoint" and to treat the rest as encrypted shape, exactly like a
    TLS 1.3 certificate: unreadable by design, and said so.

    Only LONG headers are parsed. A short-header packet starts with an
    unauthenticated two-bit pattern that random payloads match one time in
    four, so claiming QUIC from it would be guessing; long headers carry a
    version field to check against.
    """
    if len(payload) < 7:
        return None
    first = payload[0]
    if not (first & 0x80):          # long-header form bit
        return None
    if not (first & 0x40):          # fixed bit: MUST be 1 in every version
        return None
    version = struct.unpack(">I", payload[1:5])[0]
    if version == 0:
        return QuicInfo(version="negotiation", packet="long-header")
    name = _QUIC_VERSIONS.get(version)
    if name is None:
        # Unknown version: only believe it if it at least looks like a QUIC
        # DCID length byte follows (0-20 per RFC 9000).
        if payload[5] > 20:
            return None
        name = f"0x{version:08x}"
    packet = "long-header"
    if version == 0x00000001:
        packet = _QUIC_V1_TYPES.get((first & 0x30) >> 4, "long-header")
    return QuicInfo(version=name, packet=packet)
