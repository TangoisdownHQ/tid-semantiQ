"""PcapSource — the v0.1 capture plugin.

Turns a pcap/pcapng file into `Observation`s for the `net` and `dns` domains.
TCP becomes application-data bursts via `BurstAssembler`; DNS queries are
already discrete exchanges and are emitted directly.

Live capture reuses everything below `_handle_frame`; only the frame source
differs. That is why the reader yields frames rather than owning the loop.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from capture.base import BurstAssembler, CaptureSource
from capture.decode import (
    DNS_RCODES,
    PROTO_ICMP,
    PROTO_ICMPV6,
    PROTO_TCP,
    PROTO_UDP,
    arp_info,
    client_hello,
    decode_icmp,
    decode_ip,
    decode_tcp,
    decode_udp,
    dhcp_info,
    ethernet_src_mac,
    ndp_pairings,
    dns_message,
    is_private,
    ntp_info,
    quic_info,
    registrable_zone,
    ssh_banner,
)
from capture.http1 import looks_like_http
from capture.httpobs import HttpTracker
from capture.pcapfile import read_frames
from capture.tlsinfo import (
    RecordWalker,
    cert_visibility,
    certificates,
    server_hello,
    version_name,
)
from core.model import Channel, Direction, Entity, Locus, Observation

__all__ = ["PcapSource"]

#: Per-flow cap on buffered server handshake bytes. A certificate chain over
#: 64 kB is not one this tool needs to read, and the cap is what bounds the
#: memory a capture full of half-open TLS flows can cost.
_HANDSHAKE_CAP = 64 * 1024


class _Flow:
    """Per-TCP-flow state: who opened it, its stream index, and its TLS identity.

    Also the handshake flags, which are tracked for every flow whether or not
    it ever carries payload. That is the whole point: a connection that was
    refused or never answered has no application data at all, so a parser
    that only looks at payload-bearing packets cannot see a failed connection
    — and the narrator was asserting "name resolution, not connectivity, is
    the dominant failure" with nothing behind the second half of the claim.
    """

    __slots__ = ("initiator", "initiator_port", "stream", "sni", "fingerprint",
                 "tls", "inferred", "responder", "syn", "synack", "rst", "fin",
                 "payload_bytes", "tls_version", "tls_cipher", "cert",
                 "handshake", "handshake_overflow", "http",
                 "walk_out", "walk_in",
                 "client_grease", "client_alpn", "client_ciphers",
                 "client_exts", "ssh_client", "ssh_server")

    def __init__(self, initiator: str, initiator_port: int, stream: int,
                 responder: str = "", inferred: bool = False):
        self.initiator = initiator
        self.initiator_port = initiator_port
        self.responder = responder
        self.stream = stream
        self.sni: Optional[str] = None
        self.fingerprint: Optional[str] = None
        self.tls = False
        #: ClientHello shape, read once at the first egress handshake. These
        #: feed the client-family reading in the narrator; they say which
        #: library, never the intent. See capture/tlsfp.py.
        self.client_grease: Optional[bool] = None
        self.client_alpn: tuple = ()
        self.client_ciphers = 0
        self.client_exts = 0
        #: SSH identification strings, read in the clear at session start —
        #: the one moment SSH names its software before encrypting.
        self.ssh_client: Optional[str] = None
        self.ssh_server: Optional[str] = None
        #: True when no SYN was seen and the initiator was guessed from the
        #: first packet — a capture started mid-connection. Carried onto
        #: every Observation so a consumer knows the direction is inferred.
        self.inferred = inferred
        self.syn = False
        self.synack = False
        self.rst = False
        self.fin = False
        self.payload_bytes = 0
        #: Negotiated version, from the ServerHello — not the client's offer.
        #: A client advertising 1.3 that lands on 1.0 is a fact about the
        #: server, and the ClientHello cannot tell you it happened.
        self.tls_version: Optional[int] = None
        self.tls_cipher: Optional[int] = None
        self.cert = None
        #: Server-side handshake bytes, accumulated until the certificate is
        #: parsed or the cap is hit. Set to None to stop buffering, which is
        #: what keeps this from becoming a per-flow memory leak on a long
        #: capture — the buffer exists for a handshake, not for a session.
        self.handshake: Optional[bytearray] = bytearray()
        self.handshake_overflow = False
        #: Tri-state: None = not yet judged, True/False = is/is not HTTP.
        #: Decided once from the first payload-bearing segment, so a flow is
        #: not re-tested on every segment and a stream whose later bytes
        #: happen to start with "GET " is not misread as a new request.
        self.http: Optional[bool] = None
        #: Record walkers, one per direction. Stateful because records
        #: span TCP segments: a 16 kB record crosses eleven 1460-byte
        #: segments, so a segment beginning mid-record has no header at its
        #: start. Each walker is a counter, not a buffer.
        self.walk_out = RecordWalker()
        self.walk_in = RecordWalker()

    @property
    def outcome(self) -> str:
        """How this connection ended up, as far as the capture shows.

        The order of these tests is the meaning. A RST *before* any SYN-ACK is
        a refusal — nothing was ever listening, or a filter rejected it. A RST
        *after* one is an abort of a working connection, which is ordinary at
        the end of many sessions and says nothing about reachability. Reading
        them as one number would merge "could not connect" with "finished
        rudely", which are opposite facts.

        `mid_stream` exists because a capture started partway through a
        connection shows neither handshake nor refusal, and calling that
        "unanswered" would invent a failure out of a capture-start artefact.
        """
        if not self.syn:
            return "mid_stream"
        if not self.synack:
            return "refused" if self.rst else "unanswered"
        if self.rst:
            return "reset"
        if self.fin:
            return "closed"
        return "open"


class PcapSource(CaptureSource):
    """Read a capture file into Observations.

    `retain_payloads` is off by default. Payload bytes are only needed by
    `Entropy`, which only runs on cleartext, and carrying them otherwise
    means a findings file can leak the traffic it describes.
    """

    domain = "net"  # emits both "net" and "dns" channels; see observations()

    def __init__(
        self,
        path: Path | str,
        burst_gap_s: float = 0.050,
        retain_payloads: bool = False,
        parse_http: bool = True,
    ):
        self.path = Path(path)
        self.retain_payloads = retain_payloads
        #: Native cleartext-HTTP parsing. On by default because it needs no
        #: keys and no tshark; `parse_http=False` restores the pure
        #: behavioural read for anyone who wants only transport metadata.
        self._http = HttpTracker(self.path.name) if parse_http else None
        self._assembler = BurstAssembler(gap_s=burst_gap_s)
        self._flows: Dict[Tuple, _Flow] = {}
        self._streams: Dict[Tuple, int] = {}
        self._icmp_errors: List[Dict[str, object]] = []
        from capture.integrity import IntegrityTracker
        self._integrity = IntegrityTracker()
        from capture.neighbor import NeighborTable
        self._neighbors = NeighborTable()
        #: UDP 4-tuples that produced a valid QUIC long header. A QUIC
        #: connection sends long headers only during its handshake; the
        #: bulk that follows is short-header packets, which carry no
        #: version field to verify — so membership here is what lets them
        #: be counted as the encrypted traffic they are.
        self._quic_flows: set = set()
        #: private address -> the source MAC seen for it, for offline
        #: device-vendor naming. Public addresses are never recorded — see
        #: _handle_frame for why.
        self._host_macs: Dict[str, str] = {}
        #: address -> its TCP SYN fingerprint, for passive OS inference.
        self._os_fp: Dict[str, dict] = {}
        self.stats = {"frames": 0, "decoded": 0, "tcp": 0, "udp": 0, "dns": 0,
                      "http": 0, "icmp": 0}

    # -- plugin interface --------------------------------------------------

    def frames(self) -> Iterator[Tuple[int, float, int, bytes]]:
        """Where frames come from. Overridden by the live source.

        Extracted so that live capture reuses this entire class — TCP flow
        tracking, TLS, HTTP, DNS, ICMP, connection outcomes — rather than
        reimplementing any of it against a different frame source. The only
        thing that differs between a file and an interface is where the
        bytes arrive from.
        """
        yield from read_frames(self.path)

    def observations(self) -> Iterator[Observation]:
        # Size of the capture file at open, to tell afterwards whether it
        # grew while we read it — i.e. a running capture is still appending
        # and this is a partial view. None for the live pseudo-path.
        try:
            self._size_at_open: Optional[int] = os.stat(self.path).st_size
        except (OSError, ValueError):
            self._size_at_open = None
        for frame_no, ts, linktype, frame in self.frames():
            self.stats["frames"] += 1
            # Fed the raw frame, before any decode: the whole point is to
            # notice what decoding will silently tolerate — truncation,
            # duplication, a clock running backwards.
            self._integrity.frame(ts, linktype, frame)
            for obs in self._handle_frame(frame_no, ts, linktype, frame):
                yield obs
        # Drain bursts still open at end of capture. Omitting this loses the
        # final observation of every channel, which on a short capture can be
        # a meaningful fraction of the evidence.
        for obs in self._assembler.flush():
            yield obs
        # Connection outcomes are only complete once every frame is seen —
        # a flow looks "unanswered" until its SYN-ACK arrives — so this is
        # computed here rather than incrementally.
        self.stats["connections"] = self.connection_outcomes()
        self.stats["icmp_errors"] = self.icmp_errors()
        integrity = self._integrity.report()
        # Was the file still being written while we read it? A growing or
        # just-written capture means this is a partial snapshot — merged into
        # the integrity dict so it narrates in the CAPTURE ARTEFACTS section.
        from capture.integrity import capture_liveness
        liveness = capture_liveness(str(self.path),
                                    getattr(self, "_size_at_open", None))
        if liveness:
            integrity.setdefault("frames", self.stats["frames"])
            integrity.update(liveness)
        self.stats["integrity"] = integrity
        # ARP/NDP pairings are authoritative on-link statements, so they
        # override the MAC inferred from IP-packet source addresses.
        macs = dict(self._host_macs)
        macs.update(self._neighbors.pairings())
        self.stats["host_macs"] = macs
        self.stats["neighbors"] = self._neighbors.report()
        self.stats["os_fingerprints"] = dict(self._os_fp)
        if self._http is not None:
            self.stats["http"] = (
                self._http.stats["requests"] + self._http.stats["responses"]
            )

    def connection_outcomes(self) -> Dict[str, object]:
        """Per-outcome connection counts, plus the peers that failed.

        Reported as counts AND as the specific addresses, because the two
        answer different questions: "is this network healthy" is a count, and
        "what could this host not reach" is a list. The second is what an
        operator does something with.
        """
        counts: Dict[str, int] = {}
        failed: Dict[str, Dict[str, int]] = {}
        for flow in self._flows.values():
            outcome = flow.outcome
            counts[outcome] = counts.get(outcome, 0) + 1
            if outcome in ("refused", "unanswered") and flow.responder:
                bucket = failed.setdefault(outcome, {})
                bucket[flow.responder] = bucket.get(flow.responder, 0) + 1
        return {"counts": counts, "failed": failed, "flows": len(self._flows)}

    # -- per-frame ---------------------------------------------------------

    def _handle_frame(
        self, frame_no: int, ts: float, linktype: int, frame: bytes
    ) -> List[Observation]:
        # ARP first: it is not IP (EtherType 0x0806), so decode_ip would drop
        # it, and with it the LAN's authoritative IP<->MAC statements. Not a
        # scored channel — a capture-level fact, like connection outcomes.
        arp = arp_info(linktype, frame)
        if arp is not None:
            self._neighbors.observe(arp.sender_ip, arp.sender_mac,
                                    source="arp", ts=ts)
            if arp.opcode == "reply":
                self._neighbors.observe(arp.target_ip, arp.target_mac,
                                        source="arp", ts=ts)
            return []

        packet = decode_ip(linktype, frame)
        if packet is None:
            return []
        self.stats["decoded"] += 1

        # Remember the source MAC of each PRIVATE address — that is the one
        # case a frame's source MAC names the host itself. For a public
        # source the MAC is the gateway's (the last hop onto this segment),
        # not the remote endpoint's, so recording it would let the narrator
        # label every internet host with the router's vendor. Captured here,
        # before protocol dispatch, so it covers every frame type.
        if packet.src not in self._host_macs and is_private(packet.src):
            mac = ethernet_src_mac(linktype, frame)
            if mac is not None:
                self._host_macs[packet.src] = mac

        if packet.proto == PROTO_TCP:
            return self._handle_tcp(frame_no, ts, packet, frame)
        if packet.proto == PROTO_UDP:
            return self._handle_udp(frame_no, ts, packet, frame)
        if packet.proto in (PROTO_ICMP, PROTO_ICMPV6):
            return self._handle_icmp(frame_no, ts, packet, frame)
        return []

    def _handle_icmp(self, frame_no, ts, packet, frame) -> List[Observation]:
        """ICMP: echo as a measurable channel, errors as diagnosis.

        Two different things share this protocol and they are handled
        differently on purpose.

        ECHO becomes an Observation, because it is a conversation with a
        cadence — and ICMP echo is a real covert channel, so a periodic
        exchange with an unchanging identifier is something the timing
        primitives should be able to see. Treating it as a mere statistic
        would put it beyond their reach.

        ERRORS become capture-level facts, because a "host unreachable" is
        not a conversation with the router that sent it — it is an
        explanation of a conversation with somebody else. The quoted packet
        says which one. This is the half of the connectivity story TCP flags
        cannot tell: a SYN with no reply and a SYN answered by
        "administratively prohibited" are identical at the TCP layer and
        mean entirely different things.
        """
        # IPv6 neighbour discovery rides ICMPv6 and carries the same
        # authoritative IP<->MAC pairings ARP does for v4 — recorded before
        # the echo/error split below, which only concerns the other ICMP
        # types.
        for pair_ip, pair_mac in ndp_pairings(packet.proto, packet.payload,
                                              packet.src):
            self._neighbors.observe(pair_ip, pair_mac, source="ndp", ts=ts)

        message = decode_icmp(packet.proto, packet.payload)
        if message is None:
            return []
        self.stats["icmp"] += 1

        if message.is_error:
            self._icmp_errors.append({
                "reported_by": packet.src,
                "about": message.quoted_dst or "?",
                "dport": message.quoted_dport,
                "reason": message.name,
                "frame": frame_no,
                "ts": ts,
            })
            return []

        version = "icmpv6" if packet.proto == PROTO_ICMPV6 else "icmp"
        channel = Channel(
            domain="icmp",
            # Keyed by message name, so echo request and reply are separate
            # channels with their own cadence rather than one interleaved
            # series whose intervals are meaningless.
            dims={"proto": version, "type": message.name},
            initiator=Entity("ip", packet.src,
                             labels={"private": is_private(packet.src)}),
            responder=Entity("ip", packet.dst,
                             labels={"private": is_private(packet.dst)}),
        )
        attrs = {
            "encrypted": False,
            "icmp_type": str(message.kind),
            "icmp_code": str(message.code),
            "icmp_name": message.name,
            "payload_len": str(message.payload_len),
        }
        if message.echo_id is not None:
            # A tunnel riding ICMP echo tends to hold one identifier and walk
            # the sequence; both are needed for Fanout to tell a steady
            # tunnel from ordinary diagnostic pings.
            attrs["echo_id"] = str(message.echo_id)
            attrs["echo_seq"] = str(message.echo_seq)

        return [
            Observation(
                ts=ts,
                channel=channel,
                direction=Direction.EGRESS,
                size=message.payload_len,
                kind=f"icmp_{message.kind}",
                wire_size=len(frame),
                attrs=attrs,
                payload=packet.payload[8:] if self.retain_payloads else None,
                locus=Locus(source=self.path.name, frames=(frame_no,)),
            )
        ]

    def icmp_errors(self) -> Dict[str, object]:
        """ICMP errors grouped by (destination, reason).

        Grouped rather than listed: forty identical "port unreachable" for
        one address is one fact about that address, not forty facts.
        """
        grouped: Dict[Tuple[str, Optional[int], str], Dict[str, object]] = {}
        for error in self._icmp_errors:
            key = (error["about"], error["dport"], error["reason"])
            entry = grouped.get(key)
            if entry is None:
                entry = grouped[key] = {
                    "about": error["about"],
                    "dport": error["dport"],
                    "reason": error["reason"],
                    "reporters": set(),
                    "count": 0,
                    "first_frame": error["frame"],
                }
            entry["count"] = int(entry["count"]) + 1
            assert isinstance(entry["reporters"], set)
            entry["reporters"].add(error["reported_by"])

        return {
            "total": len(self._icmp_errors),
            "groups": [
                {**entry, "reporters": sorted(entry["reporters"])}
                for entry in sorted(
                    grouped.values(), key=lambda e: -int(e["count"])
                )
            ],
        }

    def _handle_tcp(self, frame_no, ts, packet, frame) -> List[Observation]:
        segment = decode_tcp(packet.payload)
        if segment is None:
            return []
        self.stats["tcp"] += 1

        flow_key = _flow_key(packet.src, segment.sport, packet.dst, segment.dport)
        flow = self._flows.get(flow_key)

        if flow is None:
            # A bare SYN names the initiator unambiguously. Without one — a
            # capture started mid-connection — fall back to the first packet
            # seen, and record that the direction is inferred rather than
            # observed so a later consumer is not misled.
            inferred = not (segment.syn and not segment.ack)
            stream = self._streams.setdefault(flow_key, len(self._streams))
            flow = _Flow(packet.src, segment.sport, stream,
                         responder=packet.dst, inferred=inferred)
            self._flows[flow_key] = flow

        # ADDRESS AND PORT, not address alone. When a host talks to itself
        # both endpoints share an IP, so an address-only comparison makes
        # every packet look outbound: the SYN-ACK is never recognised, every
        # connection reports "unanswered", and all the response bytes are
        # counted as egress. Loopback is where this shows up, and the first
        # live capture on `lo` reported 8 of 8 connections failing while
        # eight HTTP requests were plainly succeeding in the same report.
        direction = (
            Direction.EGRESS
            if (packet.src, segment.sport) == (flow.initiator,
                                               flow.initiator_port)
            else Direction.INGRESS
        )

        # Recorded BEFORE the payload check below. A refused or unanswered
        # connection never carries application data, so anything gated behind
        # `segment.payload` is blind to exactly the connections that failed.
        if segment.syn and not segment.ack:
            flow.syn = True
        elif segment.syn and segment.ack and direction is Direction.INGRESS:
            flow.synack = True
        # Passive OS fingerprint: a SYN or SYN-ACK is where a stack states its
        # defaults (TTL, window, options). Keyed on the sender (packet.src),
        # first-seen wins — a host's stack does not change between its SYNs.
        if segment.syn and packet.src not in self._os_fp:
            from capture.osfp import tcp_signature
            self._os_fp[packet.src] = tcp_signature(
                packet.ttl, segment.window, segment.options)
        if segment.rst:
            flow.rst = True
        if segment.fin:
            flow.fin = True
        flow.payload_bytes += len(segment.payload)

        if not segment.payload:
            return []

        # TLS identity is read from the ClientHello, which is the first
        # application-data burst, so every burst on the flow carries it and
        # the channel key stays stable for the flow's lifetime.
        if direction is Direction.EGRESS and flow.fingerprint is None:
            hello = client_hello(segment.payload)
            if hello is not None:
                flow.tls = True
                flow.sni = hello.sni
                flow.fingerprint = hello.fingerprint
                flow.client_grease = hello.uses_grease
                flow.client_alpn = hello.alpn
                flow.client_ciphers = hello.cipher_count
                flow.client_exts = len(hello.extensions)

        # SSH announces itself in the clear before encrypting: each side's
        # first bytes are an identification string naming its software. Read
        # once per side; everything after the banners is encrypted and is
        # shape, exactly like TLS application data.
        if not flow.tls:
            if direction is Direction.EGRESS and flow.ssh_client is None:
                flow.ssh_client = ssh_banner(segment.payload)
            elif direction is Direction.INGRESS and flow.ssh_server is None:
                flow.ssh_server = ssh_banner(segment.payload)

        # The server's half of the handshake: negotiated version always, and
        # the certificate only up to TLS 1.2. Read on the first ingress
        # segment that carries one, so an earlier egress burst on the same
        # flow will not have it yet — the narrator aggregates over the whole
        # series, which is where the facts come back together.
        #
        # BUFFERED ACROSS SEGMENTS, which is not optional. A certificate chain
        # is routinely 2-4 kB against a ~1460-byte MSS, so parsing each
        # segment alone found the small ServerHello and never once found a
        # Certificate: every TLS 1.2 flow in a real capture reported "no
        # certificate observed" while the bytes were right there, split over
        # three segments. Bounded at _HANDSHAKE_CAP per flow and released the
        # moment it succeeds or overflows, so a long-lived or hostile flow
        # cannot grow it without limit.
        if direction is Direction.INGRESS and flow.handshake is not None:
            flow.handshake += segment.payload
            if flow.tls_version is None:
                answer = server_hello(bytes(flow.handshake))
                if answer is not None:
                    flow.tls = True
                    flow.tls_version = answer.version
                    flow.tls_cipher = answer.cipher
            chain = certificates(bytes(flow.handshake))
            if chain:
                flow.cert = chain[0]
                flow.handshake = None
            elif len(flow.handshake) > _HANDSHAKE_CAP:
                # Reported rather than silently abandoned: "gave up reading"
                # and "there was nothing to read" are different facts.
                flow.handshake_overflow = True
                flow.handshake = None
            elif flow.tls_version is not None and flow.tls_version > 0x0303:
                # TLS 1.3 encrypts the Certificate message, so there is
                # nothing further to wait for. Stop buffering immediately
                # rather than accumulating application data to the cap.
                flow.handshake = None

        # Encrypted-record shape. Readable without any key, because a TLS
        # record header is cleartext — and informative, because a sender
        # filling 16 kB records is moving bulk data while one emitting
        # 40-byte records is sending individual small messages.
        if flow.tls:
            walker = (flow.walk_out if direction is Direction.EGRESS
                      else flow.walk_in)
            walker.feed(segment.payload)

        # Cleartext HTTP, parsed natively. Emitted IN ADDITION to the net
        # burst below, not instead of it: the two describe the same bytes at
        # different layers and answer different questions — `net` carries
        # cadence and asymmetry for the connection, `http` carries the
        # content facts the inspectors read. The CAPTURE section reports a
        # per-domain breakdown so the overlap is visible rather than implied.
        extra: List[Observation] = []
        if self._http is not None and not flow.tls:
            if flow.http is None:
                flow.http = looks_like_http(segment.payload)
            if flow.http:
                client, server = (
                    (packet.src, packet.dst) if direction is Direction.EGRESS
                    else (packet.dst, packet.src)
                )
                extra = self._http.feed(
                    stream=flow.stream,
                    from_client=direction is Direction.EGRESS,
                    payload=segment.payload,
                    frame=frame_no,
                    ts=ts,
                    client=client,
                    server=server,
                    dport=_responder_port(segment, flow, direction),
                )

        channel = self._net_channel(packet, segment, flow, direction)
        obs = self._assembler.feed(
            ts=ts,
            channel=channel,
            direction=direction,
            payload_len=len(segment.payload),
            wire_len=len(frame),
            kind="tcp_burst",
            source=self.path.name,
            frame=frame_no,
            stream=flow.stream,
            payload=segment.payload if self.retain_payloads else None,
            encrypted=flow.tls,
            sni=flow.sni or "",
            tls_fingerprint=flow.fingerprint or "",
            ssh_client=flow.ssh_client or "",
            ssh_server=flow.ssh_server or "",
            dport=str(_responder_port(segment, flow, direction)),
            direction_inferred=flow.inferred,
            **_tls_attrs(flow),
        )
        return extra + ([obs] if obs else [])

    def _handle_udp(self, frame_no, ts, packet, frame) -> List[Observation]:
        segment = decode_udp(packet.payload)
        if segment is None:
            return []
        self.stats["udp"] += 1

        if 53 in (segment.sport, segment.dport):
            message = dns_message(segment.payload)
            if message is not None:
                self.stats["dns"] += 1
                return [self._dns_observation(frame_no, ts, packet, segment, message)]

        # mDNS (5353) and LLMNR (5355) are DNS wire format on other ports —
        # the LAN's name gossip. Same parser, same zone/qname semantics, but
        # tagged with the service so the narrator can say which naming system
        # was speaking: a query to the multicast group is discovery, not a
        # lookup a resolver failed.
        for port, service in ((5353, "mdns"), (5355, "llmnr")):
            if port in (segment.sport, segment.dport):
                message = dns_message(segment.payload)
                if message is not None:
                    self.stats["dns"] += 1
                    return [self._dns_observation(
                        frame_no, ts, packet, segment, message,
                        service=service)]

        # NTP and DHCP announce real facts in cleartext; parsed when the
        # shape is plausible, because a port number alone is a rumour.
        extra_attrs: Dict[str, str] = {}
        quic_encrypted = False
        if 443 in (segment.sport, segment.dport):
            flow_key = tuple(sorted(((packet.src, segment.sport),
                                     (packet.dst, segment.dport))))
            quic = quic_info(segment.payload)
            if quic is not None:
                # QUIC is HTTP/3's transport and it is encrypted from the
                # first packet — even the SNI is sealed, unlike TLS over
                # TCP. The envelope is the readable part; the rest of this
                # channel is shape, and the encrypted flag is what routes
                # it to the shape language rather than the cleartext one.
                extra_attrs["quic_version"] = quic.version
                extra_attrs["quic_packet"] = quic.packet
                quic_encrypted = True
                self._quic_flows.add(flow_key)
            elif (flow_key in self._quic_flows and segment.payload
                  and segment.payload[0] & 0x40):
                # Short-header packet on a connection whose handshake was
                # seen: no version field to verify, but the flow already
                # proved itself QUIC, and this is where the bulk of the
                # connection's bytes live.
                quic_encrypted = True
        if 123 in (segment.sport, segment.dport):
            ntp = ntp_info(segment.payload)
            if ntp is not None:
                extra_attrs["ntp_mode"] = ntp.mode
                extra_attrs["ntp_version"] = str(ntp.version)
                if ntp.stratum is not None:
                    extra_attrs["ntp_stratum"] = str(ntp.stratum)
        elif {segment.sport, segment.dport} & {67, 68}:
            dhcp = dhcp_info(segment.payload)
            if dhcp is not None:
                extra_attrs["dhcp_type"] = dhcp.kind
                if dhcp.hostname:
                    extra_attrs["dhcp_hostname"] = dhcp.hostname
                if dhcp.address:
                    # The address the exchange is ABOUT — what a hostname in
                    # this message is naming. The narrator's naming pass keys
                    # on this, never on the 0.0.0.0 source of a bare request.
                    extra_attrs["dhcp_addr"] = dhcp.address

        # Non-DNS UDP: a datagram is its own exchange, no burst assembly.
        client_is_src = segment.dport < segment.sport
        src_is_initiator = client_is_src
        _src, _dst = packet.src, packet.dst
        channel = Channel(
            domain="net",
            dims={"proto": "udp", "dport": str(min(segment.sport, segment.dport))},
            # Labels match the TCP path. Without them a LAN gateway reached
            # over DHCP carried no `private` flag and the narrator counted it
            # as a public address contacted with no name — a false alarm on
            # the most ordinary traffic there is.
            initiator=Entity(
                "ip", _src if src_is_initiator else _dst,
                labels={"private": is_private(_src if src_is_initiator else _dst)},
            ),
            responder=Entity(
                "ip", _dst if src_is_initiator else _src,
                labels={"private": is_private(_dst if src_is_initiator else _src)},
            ),
        )
        return [
            Observation(
                ts=ts,
                channel=channel,
                direction=Direction.EGRESS if src_is_initiator else Direction.INGRESS,
                size=len(segment.payload),
                kind="udp_datagram",
                wire_size=len(frame),
                attrs={"encrypted": quic_encrypted,
                       "dport": str(segment.dport),
                       **extra_attrs},
                payload=segment.payload if self.retain_payloads else None,
                locus=Locus(source=self.path.name, frames=(frame_no,)),
            )
        ]

    def _dns_observation(self, frame_no, ts, packet, segment, message,
                         service: str = "") -> Observation:
        qname, qtype = message.qname, message.qtype
        is_response, rcode = message.is_response, message.rcode
        client = packet.dst if is_response else packet.src
        server = packet.src if is_response else packet.dst

        # `service` tags mDNS/LLMNR, which share the DNS wire format but are
        # a different act: multicast name gossip on the local segment, not a
        # lookup sent to a resolver. The dim keeps their channels separate
        # from real resolver traffic so a failure-rate or cardinality signal
        # on one cannot bleed into the other.
        dims = {"proto": "udp", "qtype": qtype, "zone": registrable_zone(qname)}
        if service:
            dims["service"] = service
        channel = Channel(
            domain="dns",
            # Zone, not qname: the tunnelling signal is cardinality of names
            # BENEATH a zone, so the zone is the channel and the name is an
            # attribute for Fanout to count. Keying on qname would give every
            # query its own channel and the signal would vanish entirely.
            dims=dims,
            initiator=Entity("ip", client),
            responder=Entity("ip", server),
        )
        return Observation(
            ts=ts,
            channel=channel,
            direction=Direction.INGRESS if is_response else Direction.EGRESS,
            size=len(segment.payload),
            kind="dns_response" if is_response else "dns_query",
            wire_size=None,
            attrs={
                "qname": qname,
                "qtype": qtype,
                "encrypted": False,
                "label_count": str(qname.count(".") + 1),
                "qname_length": str(len(qname)),
                # Only meaningful on a response; a query always reads 0, so
                # the attribute is set only where it means something and
                # consumers can tell "NOERROR" from "not a response".
                **({"rcode": str(rcode),
                    "rcode_name": DNS_RCODES.get(rcode, f"rcode {rcode}")}
                   if is_response else {}),
                **({"dns_service": service} if service else {}),
                **self._answer_attrs(message),
            },
            payload=qname.encode() if self.retain_payloads else None,
            locus=Locus(source=self.path.name, frames=(frame_no,)),
        )

    @staticmethod
    def _answer_attrs(message) -> Dict[str, str]:
        """Answer-section facts, flattened onto the observation.

        `resolved_ips` is what lets the narrator put a name on an endpoint
        that never spoke TLS. Space-joined rather than structured because
        `attrs` is a flat string map by design — the scorer treats attribute
        values as opaque labels, and giving one of them nested structure
        would make it the exception every consumer has to special-case.

        `ttl_min` is carried because a very low TTL across many distinct
        addresses is the shape of fast-flux hosting. No rule reads it yet;
        it is reported, not judged.
        """
        if not message.answers:
            # Distinguish "answered with nothing" from "answers not visible".
            return {"answers_truncated": "1"} if message.truncated else {}

        addresses = [r.value for r in message.answers
                     if r.rtype in ("A", "AAAA") and r.value]
        cnames = [r.value for r in message.answers
                  if r.rtype == "CNAME" and r.value]
        ttls = [r.ttl for r in message.answers]

        attrs = {
            "answers": str(len(message.answers)),
            "answer_types": " ".join(
                sorted({r.rtype for r in message.answers})
            ),
        }
        if addresses:
            attrs["resolved_ips"] = " ".join(addresses)
            attrs["resolved_count"] = str(len(addresses))
        if cnames:
            attrs["cname_target"] = cnames[-1]
            attrs["cname_depth"] = str(len(cnames))
        if ttls:
            attrs["ttl_min"] = str(min(ttls))
        if message.truncated:
            attrs["answers_truncated"] = "1"
        return attrs

    def _net_channel(self, packet, segment, flow, direction) -> Channel:
        if direction is Direction.EGRESS:
            initiator, responder = packet.src, packet.dst
        else:
            initiator, responder = packet.dst, packet.src

        dims = {
            "proto": "tcp",
            "dport": str(_responder_port(segment, flow, direction)),
        }
        # SNI joins the channel identity when known. Two different services
        # behind one CDN IP are different behaviours and must not average
        # together; without SNI they would share a channel.
        if flow.sni:
            dims["sni"] = flow.sni

        return Channel(
            domain="net",
            dims=dims,
            initiator=Entity("ip", initiator, labels={"private": is_private(initiator)}),
            responder=Entity("ip", responder, labels={"private": is_private(responder)}),
        )


def _tls_attrs(flow: _Flow) -> Dict[str, str]:
    """Server-side TLS facts for a burst's attrs.

    `cert_visible` is always set on a TLS flow, including when there is no
    certificate to report. That is the point of it: TLS 1.3 encrypts the
    Certificate message, so its absence is a protocol property, and a
    consumer that sees only a missing field cannot tell that from a server
    that presented nothing. One is normal and the other is strange.

    SNI MISMATCH is computed here rather than left to the reader. The client
    asked for a name and the server presented a certificate for some set of
    names; whether the first is in the second is a mechanical check, and it
    is the single most useful thing the certificate can tell you.
    """
    if not flow.tls:
        return {}

    attrs: Dict[str, str] = {}
    # ClientHello shape, for the narrator's client-family reading. Known at
    # the moment `flow.tls` first becomes true (both are set from the same
    # ClientHello), so unlike the server-side facts below these are safe to
    # stamp on every burst of the flow.
    if flow.client_grease is not None:
        attrs["tls_client_grease"] = "1" if flow.client_grease else "0"
        attrs["tls_client_ciphers"] = str(flow.client_ciphers)
        attrs["tls_client_exts"] = str(flow.client_exts)
        if flow.client_alpn:
            attrs["tls_client_alpn"] = ",".join(flow.client_alpn)
    if flow.tls_version is not None:
        attrs["tls_version"] = version_name(flow.tls_version)
    if flow.tls_cipher is not None:
        attrs["tls_cipher"] = f"0x{flow.tls_cipher:04x}"
    # ONLY STAMPED ONCE THE ANSWER IS SETTLED. Bursts are immutable and carry
    # the flow state as it stood when they were fed, so a progressive value
    # here becomes a contradiction later: the ClientHello burst predates any
    # ServerHello, and the first server burst predates the rest of a
    # multi-segment certificate. Stamping those produced one channel
    # simultaneously reporting "no server handshake observed", "not observed
    # in the captured bytes" and "visible" — three claims describing nothing
    # but the order packets arrived in.
    #
    # `flow.handshake is None` is exactly the "done deciding" signal: it is
    # released when the certificate is parsed, when the cap is hit, or when
    # the version turns out to be 1.3. While it is still a buffer, the honest
    # answer is to say nothing yet.
    if flow.handshake_overflow and flow.cert is None:
        attrs["cert_visible"] = (
            f"not read — handshake exceeded {_HANDSHAKE_CAP // 1024} kB"
        )
    elif flow.cert is not None or flow.handshake is None:
        attrs["cert_visible"] = cert_visibility(
            flow.tls_version, flow.cert is not None
        )

    for label, walker in (("out", flow.walk_out), ("in", flow.walk_in)):
        shape = walker.shape
        if not shape.count:
            continue
        attrs[f"tls_rec_{label}"] = str(shape.count)
        attrs[f"tls_rec_{label}_max"] = str(shape.largest)
        attrs[f"tls_rec_{label}_mean"] = f"{shape.mean:.0f}"
        attrs[f"tls_rec_{label}_full"] = str(shape.full)
        attrs[f"tls_rec_{label}_small"] = str(shape.small)
        if walker.desynced:
            # Said, not hidden. The count is a floor rather than a total
            # once the record stream could no longer be followed.
            attrs[f"tls_rec_{label}_partial"] = "1"

    cert = flow.cert
    if cert is None:
        return attrs

    if cert.subject:
        attrs["cert_subject"] = cert.subject
    if cert.issuer:
        attrs["cert_issuer"] = cert.issuer
    if cert.not_before:
        attrs["cert_not_before"] = cert.not_before
    if cert.not_after:
        attrs["cert_not_after"] = cert.not_after
    if cert.sans:
        attrs["cert_sans"] = " ".join(cert.sans)
        attrs["cert_san_count"] = str(len(cert.sans))
    if cert.self_signed:
        attrs["cert_self_signed"] = "1"

    if flow.sni:
        covered = _name_covered(flow.sni, cert)
        attrs["cert_covers_sni"] = "1" if covered else "0"
    return attrs


def _name_covered(sni: str, cert) -> bool:
    """Does the certificate name the host the client asked for?

    Wildcards match one label only, which is what the specification says and
    what a lenient implementation gets wrong: `*.example.com` covers
    `a.example.com` and must NOT cover `a.b.example.com`. Getting that
    backwards would turn a real mismatch into a pass.

    Falls back to the subject CN when there are no SANs — deprecated for
    years, but still what some internal and appliance certificates carry,
    and reporting those as a mismatch would be wrong.
    """
    target = sni.lower().rstrip(".")
    candidates = [name.lower().rstrip(".") for name in cert.sans]
    if not candidates and cert.subject:
        candidates = [cert.subject.lower().rstrip(".")]

    for candidate in candidates:
        if candidate == target:
            return True
        if candidate.startswith("*."):
            suffix = candidate[2:]
            if not target.endswith("." + suffix):
                continue
            label = target[: -(len(suffix) + 1)]
            if label and "." not in label:
                return True
    return False


def _flow_key(src: str, sport: int, dst: str, dport: int) -> Tuple:
    """Direction-independent flow key, so both halves map to one flow."""
    a, b = (src, sport), (dst, dport)
    return (a, b) if a <= b else (b, a)


def _responder_port(segment, flow, direction) -> int:
    return segment.dport if direction is Direction.EGRESS else segment.sport
