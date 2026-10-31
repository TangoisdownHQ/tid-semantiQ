"""The report, explaining its own vocabulary.

The narration is written for an operator, so it uses the words an operator
uses: NXDOMAIN, SNI, asymmetry, a connection that was *refused* versus one
*never answered*. Those words carry the meaning — replacing them with
paragraphs would make the report longer and vaguer at once. But a reader who
is not fluent in them is then reading a report in a language they only half
speak, and the tool's whole claim is that its output can be *checked*, not
taken on trust.

So this module is a glossary the report assembles for itself. It holds an
extensive, plain-language definition for each technical term the narration
can emit, and `glossary_section` scans the narration that was actually
produced and prints definitions for only the terms that appeared in it. The
result is contextual: a capture with no TLS prints no TLS entries, and a DNS
flood prints the DNS vocabulary and little else.

TWO PROPERTIES THIS KEEPS.

  1. It is ordinary code, like every other sentence in the report. No model
     writes these definitions and none can edit them, so the explanation of a
     term cannot drift from what the term means the way a generated gloss
     could. `--explain` (the optional, model-written layer) is a different
     thing entirely and says so.

  2. It is not specific to the capture, and says so at the top. A definition
     of "NXDOMAIN" is true of every NXDOMAIN; the report's *claims* about this
     capture live in the narration above it. Keeping the two visibly separate
     is what stops a glossary entry from reading like a finding.

A term is INCLUDED when any of its trigger patterns matches the narration
text, and entries print in the order the terms first appeared — so the
glossary reads as a key to the report, top to bottom, rather than as an
alphabetised dump the reader has to cross-reference by hand.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = ["Term", "GLOSSARY", "terms_in", "glossary_section"]


class Term:
    """One definable term: how to detect it, and what to say about it.

    `triggers` are regular expressions tested case-insensitively against the
    narration text. A term with no matching trigger is simply never printed,
    which is the whole mechanism behind the section being contextual.
    """

    __slots__ = ("term", "triggers", "short", "long", "see")

    def __init__(
        self,
        term: str,
        triggers: Sequence[str],
        short: str,
        long: str,
        see: Sequence[str] = (),
    ) -> None:
        self.term = term
        self.triggers = [re.compile(t, re.IGNORECASE) for t in triggers]
        self.short = short
        self.long = long
        self.see = list(see)

    def first_match(self, text: str) -> Optional[int]:
        """Lowest character offset at which any trigger matches, or None.

        Used to order the printed glossary by where each term first appears in
        the report, so the definitions follow the reader's eye down the page.
        """
        best: Optional[int] = None
        for pattern in self.triggers:
            m = pattern.search(text)
            if m is not None and (best is None or m.start() < best):
                best = m.start()
        return best


# --------------------------------------------------------------------------
# The vocabulary. Each `long` is written to answer three questions: what the
# term is, why it shows up in a capture at all, and what its presence does or
# does not let you conclude — the last being the one a bare dictionary omits
# and the one this tool is about.
# --------------------------------------------------------------------------

GLOSSARY: List[Term] = [
    # ---- capture framing --------------------------------------------------
    Term(
        "host-side capture",
        [r"host-side capture", r"originated every exchange"],
        "A capture taken at one machine, seeing only its own traffic.",
        "A capture made on one host sees the packets that host sent and "
        "received, and nothing else. That one fact shapes every claim below "
        "it: the tool can describe what this machine did, but it cannot see a "
        "conversation between two other parties on the same network, because "
        "those packets never reached the capturing interface. It is the "
        "opposite of a capture taken at a span port or tap, which sees a "
        "whole segment. When a report says a single address 'originated every "
        "exchange', that is the signature of a host-side capture, and it is "
        "why the report will not claim anything about traffic the host was "
        "not a party to.",
    ),
    Term(
        "exchange",
        [r"\bexchanges?\b"],
        "One request-and-reply unit of traffic, the report's counting unit.",
        "The report counts traffic in exchanges rather than raw packets. An "
        "exchange is one logical back-and-forth — a query and its answer, a "
        "request and its response — which is a more honest unit than the "
        "packet, because a single request can be split across many packets by "
        "the network and counting packets would then inflate busy transfers. "
        "Exchange counts are what the volume, timeline and cadence figures "
        "are built from.",
    ),
    Term(
        "channel",
        [r"\bchannels?\b"],
        "A single conversation between two endpoints over one protocol.",
        "A channel is the tool's name for one ongoing conversation: a given "
        "source and destination talking over a given transport and port, "
        "grouped so its behaviour can be measured over time. Cadence, volume "
        "asymmetry and burstiness are all properties of a channel, not of a "
        "single packet — which is why a channel, not a message, is the unit "
        "the behavioural analysis scores.",
    ),
    # ---- transport (TCP) --------------------------------------------------
    Term(
        "TCP",
        [r"\bTCP\b", r"\btcp/\d"],
        "The connection-oriented transport most application traffic rides on.",
        "TCP (Transmission Control Protocol) is the transport that sets up a "
        "connection before any data flows and guarantees the bytes arrive in "
        "order. The setup is a three-step handshake (SYN, SYN-ACK, ACK), and "
        "because that handshake is visible in the clear even when the "
        "contents are encrypted, the tool can tell whether a connection "
        "succeeded, was refused, or was never answered without reading a "
        "single byte of payload.",
        see=["SYN", "port"],
    ),
    Term(
        "port",
        [r"\b(tcp|udp)/\d+", r"\bdport\b", r"\bport\b"],
        "The numeric address of a service on a host (e.g. tcp/443).",
        "A port number identifies which service on a machine a connection is "
        "for: 443 is HTTPS, 80 is cleartext HTTP, 53 is DNS, and so on. The "
        "report writes it as transport/number, such as tcp/443 or udp/53. The "
        "port is a strong hint about what an encrypted channel is doing — "
        "tcp/443 is almost certainly TLS — but it is only a convention, so "
        "the tool treats it as evidence joined to behaviour, never as proof "
        "of the application.",
    ),
    Term(
        "SYN",
        [r"\bSYN\b", r"opening SYN"],
        "The first packet of a TCP connection attempt.",
        "A SYN is the opening packet a client sends to start a TCP "
        "connection. What happens next is diagnostic on its own: a SYN-ACK "
        "back means the service accepted the attempt, a RST back means it "
        "actively refused, and silence means nothing was listening or a "
        "firewall dropped it. The report uses exactly these outcomes to "
        "classify connections, which is possible because the handshake is "
        "never encrypted.",
        see=["TCP", "reset (RST)", "refused", "never answered"],
    ),
    Term(
        "established",
        [r"\bestablish", r"\bcompleted and closed"],
        "A TCP connection that completed its handshake.",
        "An established connection is one where the three-way handshake "
        "finished, so application data could flow. The report separates "
        "connections that established and closed cleanly from those that "
        "established and were then reset, because the two describe different "
        "events: a clean close is an ordinary end, while a reset mid-stream "
        "can mark an error, a timeout, or a deliberate teardown.",
        see=["TCP", "reset (RST)"],
    ),
    Term(
        "reset (RST)",
        [r"\breset\b", r"\bRST\b"],
        "An abrupt TCP teardown — the connection was cut, not closed.",
        "A reset (the TCP RST flag) ends a connection immediately rather than "
        "through the orderly four-step close. Sent in answer to an opening "
        "SYN it means the port actively refused the connection; sent in the "
        "middle of an established connection it means one side tore the "
        "conversation down abruptly, which can be an application error, a "
        "timeout, an idle-connection cleanup, or an intentional cut. The "
        "report counts resets on established connections separately from "
        "refusals for exactly that reason.",
        see=["refused", "established"],
    ),
    Term(
        "refused",
        [r"\brefused\b"],
        "The SYN was answered with a reset — nothing was listening there.",
        "A refused connection is one where the opening SYN got an immediate "
        "reset back: the host was reachable and replied, but no service was "
        "accepting connections on that port. It is a precise and useful "
        "signal — the network path worked, so the failure is the service, not "
        "connectivity — and it is distinct from a connection that was never "
        "answered at all.",
        see=["reset (RST)", "never answered", "SYN"],
    ),
    Term(
        "never answered",
        [r"never answered", r"no reply to the opening SYN"],
        "The opening SYN got no reply at all — silence, not a refusal.",
        "A never-answered connection is one whose opening SYN drew no "
        "response of any kind. That silence is different from a refusal: a "
        "refusal is an active 'no' from a reachable host, while silence means "
        "the host is down, the address is unused, or a firewall is dropping "
        "the packets without reply. The report keeps the two apart because "
        "they point at different causes, and it lists the destinations each "
        "happened to so the operator can tell which.",
        see=["refused", "SYN"],
    ),
    # ---- names (DNS) ------------------------------------------------------
    Term(
        "DNS",
        [r"\bDNS\b", r"name resolution", r"\blookups?\b"],
        "The system that turns a name into an address before you connect.",
        "DNS (the Domain Name System) is the lookup step that happens before "
        "most connections: a client asks a resolver for the address behind a "
        "name like example.com and connects to the address that comes back. "
        "Because the lookup is a separate, usually cleartext exchange, the "
        "tool can learn the intended name of a destination even when the "
        "connection to it is fully encrypted — and it can see when name "
        "resolution, rather than the network, is what failed.",
        see=["resolver", "NXDOMAIN"],
    ),
    Term(
        "resolver",
        [r"\bresolver\b"],
        "The server a host asks to perform DNS lookups on its behalf.",
        "A resolver is the DNS server a host sends its name queries to — "
        "typically the local router or a configured public resolver. In a "
        "host-side capture the resolver shows up as the single peer that "
        "almost every lookup went to, which is why its channel can carry tens "
        "of thousands of exchanges while representing only the act of "
        "resolving names, not of talking to those names.",
        see=["DNS"],
    ),
    Term(
        "NXDOMAIN",
        [r"\bNXDOMAIN\b"],
        "A DNS answer meaning the name does not exist.",
        "NXDOMAIN is the DNS response code for 'this name does not exist'. A "
        "high rate of it means a host is repeatedly asking for names that "
        "cannot resolve, which has innocent causes — a resolver appending a "
        "search-domain suffix to an unqualified name, a typo, stale "
        "configuration — and less innocent ones, such as malware cycling "
        "through generated names looking for a live command host. The shape "
        "of the failures, not the code alone, is what separates those, and "
        "the report describes the shape rather than guessing the cause.",
        see=["DNS", "root zone", "search-domain list"],
    ),
    Term(
        "root zone",
        [r"root zone", r"top-level domain", r"\bTLD\b"],
        "The top of the DNS tree; defines which top-level domains exist.",
        "The root zone is the authoritative top of the DNS hierarchy, and it "
        "defines exactly which top-level domains (the final label — .com, "
        ".org, .uk) actually exist. A lookup for a name under a TLD that is "
        "not in the root zone cannot succeed no matter how healthy the "
        "network is, so when the report notes queries under suffixes that are "
        "not delegated TLDs, it is pointing out lookups that were doomed "
        "before they left the host.",
        see=["NXDOMAIN", "search-domain list"],
    ),
    Term(
        "search-domain list",
        [r"search-domain", r"search domain"],
        "Suffixes a resolver appends to an unqualified name, one by one.",
        "When a host looks up a bare name with no dot (like 'printer'), the "
        "resolver tries appending each suffix from a configured search-domain "
        "list — printer.corp.example, printer.example, and so on — until one "
        "resolves or all fail. That produces a very recognisable burst: the "
        "same leading name re-queried under a series of suffixes, most "
        "returning NXDOMAIN. The tool calls this shape out because it looks "
        "alarmingly like a generated-name lookup loop, and only context — "
        "which this capture may not contain — tells the two apart.",
        see=["NXDOMAIN", "root zone"],
    ),
    Term(
        "DNS record types (A, AAAA, CNAME, TTL)",
        [r"\bAAAA\b", r"\bCNAME\b", r"\bTTL\b", r"\bqtypes?\b"],
        "The kinds of answer a DNS lookup returns, and how long they live.",
        "A DNS answer has a type. An A record maps a name to an IPv4 address "
        "and an AAAA record to an IPv6 address — these are what let the tool "
        "attach a name to an address it only ever saw as a number. A CNAME is "
        "an alias pointing one name at another, so a lookup can walk a chain "
        "of CNAMEs before reaching an address. The TTL (time to live) is how "
        "many seconds the answer may be cached before it must be looked up "
        "again; a very short TTL means the mapping can change quickly, which "
        "is worth noting but is also ordinary for load-balanced services.",
        see=["DNS"],
    ),
    # ---- encryption (TLS) -------------------------------------------------
    Term(
        "encrypted traffic",
        [r"\bencrypted\b", r"encrypted-shape", r"content was never available"],
        "Traffic whose contents are unreadable — but whose shape is not.",
        "When a channel is encrypted the tool cannot read what was said, and "
        "no claim in the report about that channel depends on reading it. "
        "What encryption does not hide is the outside of the traffic: how "
        "big each message was, which direction it went, and how the messages "
        "were spaced in time. From that alone the tool can often tell a bulk "
        "download from an interactive session from a steady poller — a "
        "*shape*, reported as such, never as the identity of the application "
        "inside.",
        see=["TLS", "TLS record", "activity shape"],
    ),
    Term(
        "TLS",
        [r"\bTLS\b"],
        "The protocol that encrypts most modern traffic (the S in HTTPS).",
        "TLS (Transport Layer Security) is the encryption layer under HTTPS "
        "and most other secure protocols. It begins with a handshake that "
        "negotiates a version and a cipher and, in older versions, exchanges "
        "the server's certificate in the clear. After the handshake "
        "everything is encrypted. The tool reads what the handshake exposes — "
        "the negotiated version, the certificate where the version allows, "
        "and the requested name (SNI) — and treats the rest as shape.",
        see=["TLS record", "SNI", "certificate", "TLS 1.3"],
    ),
    Term(
        "TLS record",
        [r"TLS record", r"record shape", r"record sizes?", r"record header",
         r"byte records", r"kB records"],
        "The framing unit of TLS; its size and direction stay visible.",
        "TLS wraps the encrypted data into records, and each record carries a "
        "small cleartext header giving its length and type. That header is "
        "not encrypted, so even on traffic the tool cannot read, it can "
        "measure how large each record was and which way it flowed. A sender "
        "filling 16 kB records is moving bulk data; one emitting 48-byte "
        "records is sending individual little messages. This is the raw "
        "material behind every statement the report makes about an encrypted "
        "channel's shape.",
        see=["encrypted traffic", "TLS", "activity shape"],
    ),
    Term(
        "SNI",
        [r"\bSNI\b", r"\bsni=", r"server name indication"],
        "The server name a client requests, sent in the clear in the TLS handshake.",
        "SNI (Server Name Indication) is the hostname the client puts in its "
        "opening TLS message so a server hosting many sites on one address "
        "knows which certificate to present. In most of today's traffic the "
        "SNI is still sent in the clear, so it is often the only readable "
        "statement of what an encrypted connection was *for* — which is why "
        "the tool uses it to name a destination even when it could read "
        "nothing else about the exchange.",
        see=["TLS", "certificate"],
    ),
    Term(
        "certificate",
        [r"\bcertificate\b", r"\bcert\b"],
        "The server's signed identity document, presented during the handshake.",
        "A TLS certificate is the document a server presents to prove its "
        "identity: it carries the subject (who it is for), the issuer (who "
        "vouched for it), a validity window, and the list of names it covers "
        "(the SANs). The tool reports these facts where the protocol lets it "
        "see the certificate, and checks whether the certificate actually "
        "covers the name the client asked for in the SNI — a mismatch, an "
        "expired window, or a self-signed issuer are each worth a reader's "
        "attention.",
        see=["self-signed", "SNI", "TLS 1.3"],
    ),
    Term(
        "self-signed",
        [r"self-signed", r"self signed"],
        "A certificate vouched for by itself, not a recognised authority.",
        "A self-signed certificate is one whose issuer is the same as its "
        "subject — it vouches for itself rather than being signed by a "
        "certificate authority a client would already trust. That is normal "
        "and expected inside a lab, on internal tooling, or on a device's "
        "management interface, and abnormal on something claiming to be a "
        "public service. The tool reports the fact; whether it is a problem "
        "depends entirely on what the endpoint is supposed to be.",
        see=["certificate"],
    ),
    Term(
        "TLS 1.3",
        [r"TLS ?1\.3", r"unreadable by design"],
        "The current TLS version, which encrypts even the certificate.",
        "TLS 1.3 is the modern version of the protocol, and it encrypts more "
        "of the handshake than its predecessors — including the server's "
        "certificate. So on a TLS 1.3 connection the tool genuinely cannot "
        "read the certificate, and it says exactly that: 'unreadable by "
        "design'. This is deliberately distinct from 'the server presented "
        "nothing', because a certificate hidden by strong encryption and a "
        "certificate that was never sent are different facts about the "
        "server, and conflating them would be a lie about what was observed.",
        see=["certificate", "negotiated version"],
    ),
    Term(
        "TLS client fingerprint (GREASE, ALPN)",
        [r"\bGREASE\b", r"\bALPN\b", r"tls client", r"handshake shape",
         r"TLS stacks?", r"tls print"],
        "Reading which TLS library a client is, from its cleartext handshake.",
        "A client's opening TLS message is sent in the clear, and its shape — "
        "which cipher suites and extensions it offers, in what order, and "
        "with which options — differs between TLS libraries. Two readable "
        "details carry most of the signal. GREASE is a set of deliberately "
        "meaningless values browsers sprinkle into the handshake to keep "
        "middleboxes honest; browsers send it, most command-line and library "
        "stacks do not, so its presence or absence splits the two cleanly. "
        "ALPN is the list of application protocols the client offers — "
        "offering h2 (HTTP/2) is browser-like. The tool hashes the whole "
        "shape into a fingerprint so the same client software can be "
        "recognised across connections, and it reads the shape as a coarse "
        "family — browser-like, library-like — never as a product name. The "
        "standing caveat: this identifies the TLS *library*, not intent. "
        "Tools exist (utls) whose whole purpose is to present a browser's "
        "shape exactly, so 'consistent with a browser' is never 'benign'; "
        "the reading is description joined to other evidence, not a verdict.",
        see=["TLS", "SNI", "rarity / prevalence"],
    ),
    Term(
        "negotiated version",
        [r"negotiated", r"supported_versions", r"TLS ?1\.2"],
        "The TLS version the two sides actually agreed on, not merely offered.",
        "A client advertises the TLS versions it is willing to speak, and the "
        "server picks one; the version that matters is the one they settled "
        "on, not the client's wish-list. The tool reads the negotiated "
        "version from the correct field (supported_versions), so a TLS 1.3 "
        "connection is not misreported as 1.2 merely because 1.2 also "
        "appeared in the client's offer. The negotiated version decides what "
        "else is readable — notably whether the certificate is in the clear.",
        see=["TLS 1.3", "certificate"],
    ),
    # ---- behavioural measurements ----------------------------------------
    Term(
        "activity shape",
        [r"activity shape", r"\bshape\b", r"bulk transfer", r"\bpoller\b",
         r"interactive session"],
        "A channel's size-and-timing fingerprint, readable without decryption.",
        "The activity shape is what the tool infers from the sizes, "
        "directions and timing of a channel's exchanges alone — the pattern "
        "that survives encryption. A large one-directional flow is a bulk "
        "transfer; alternating small-then-large exchanges are request and "
        "response; small exchanges with human-scale pauses are an interactive "
        "session; evenly spaced tiny exchanges are a poller. The shape is "
        "reported as a possibility consistent with the numbers, with benign "
        "readings named alongside, never as a claim about the application.",
        see=["encrypted traffic", "TLS record", "periodicity", "asymmetry"],
    ),
    Term(
        "asymmetry",
        [r"\basymmetry\b"],
        "How lopsided a channel is between bytes sent and bytes received.",
        "Asymmetry measures the imbalance between what a host sent on a "
        "channel and what it received. A download is strongly asymmetric "
        "inbound; a steady upload is asymmetric outbound; a chat is roughly "
        "balanced. On its own asymmetry is just a description of flow "
        "direction, but combined with cadence and rarity it helps separate, "
        "say, a backup from a data exfiltration — the same raw direction, "
        "very different context.",
        see=["activity shape", "burstiness"],
    ),
    Term(
        "burstiness",
        [r"\bburstiness\b", r"\bbursty\b"],
        "Whether a channel's traffic clumps into bursts or flows evenly.",
        "Burstiness captures whether exchanges arrive in clumps separated by "
        "quiet gaps, or at a steady rate. Human-driven activity — loading a "
        "page, then reading it — tends to be bursty; an automated agent on a "
        "timer tends to be even. The measure is one input to the activity "
        "shape and, with periodicity, helps tell a person from a program "
        "without reading any content.",
        see=["activity shape", "periodicity"],
    ),
    Term(
        "periodicity",
        [r"\bperiodicity\b", r"\bperiod\b", r"\bcadence\b"],
        "How regular a channel's timing is — the heartbeat measurement.",
        "Periodicity measures how close a channel's exchanges come to a fixed "
        "interval. A score near 1.0 means a near-perfect heartbeat — an "
        "exchange every N seconds like clockwork. This is the headline signal "
        "for a beacon, but it is also exactly how NTP, update checkers, "
        "telemetry agents and keepalives behave, so the tool never alerts on "
        "regularity alone. High periodicity is interesting only once it is "
        "joined to rarity, which is the point of the next entry.",
        see=["jitter", "beacon", "rarity / prevalence"],
    ),
    Term(
        "jitter",
        [r"\bjitter\b"],
        "The variation around a channel's average interval.",
        "Jitter is how much the gaps between exchanges wander around their "
        "average. Zero jitter is a perfect metronome; high jitter is irregular "
        "timing. Malware authors deliberately add jitter to a beacon to break "
        "the metronome and hide among ordinary traffic, so the tool is built "
        "to still detect a periodic signal under substantial jitter rather "
        "than only catching the naive zero-jitter case.",
        see=["periodicity", "beacon"],
    ),
    Term(
        "cardinality / fanout",
        [r"\bcardinality\b", r"\bfanout\b", r"distinct (names?|values?|addresses?)"],
        "How many distinct things one channel or host touched.",
        "Cardinality (also called fanout) counts distinct values — how many "
        "different names a host looked up, how many addresses it reached, how "
        "many unit ids a Modbus master polled. A sudden high cardinality can "
        "mean a scan, a sweep, or a tunnel encoding data into the names it "
        "queries. What counts as high depends on the domain, so the tool "
        "sizes the threshold to the context: fifty distinct DNS names is "
        "unremarkable, fifty distinct industrial unit ids is an exhaustive "
        "sweep.",
        see=["DNS tunnel"],
    ),
    Term(
        "rarity / prevalence",
        [r"\brarity\b", r"\bprevalence\b", r"\bnovel\b", r"uncommon destination"],
        "How unusual a channel is relative to a baseline of normal traffic.",
        "Rarity asks whether a channel is something this environment has seen "
        "before. It is measured against a baseline built from traffic you "
        "believe is normal: a destination almost every host contacts is "
        "prevalent and uninteresting, while one seen on almost no host is "
        "rare and worth a look. Rarity is the gate that makes the tool "
        "usable — regular traffic is everywhere, so a beacon rule fires only "
        "when a periodic channel is *also* rare. Without a baseline there is "
        "no rarity, which is why the report warns loudly when one was not "
        "supplied.",
        see=["baseline", "periodicity", "beacon"],
    ),
    Term(
        "baseline",
        [r"\bbaseline\b"],
        "A record of normal traffic, used to judge what is unusual.",
        "A baseline is a saved history of channels from traffic you have "
        "judged to be normal, built by running the tool over known-good "
        "captures first. Rarity is measured against it, so without a baseline "
        "the rarity-gated rules cannot fire and the tool falls back to "
        "describing rather than flagging. A cold (empty) baseline makes the "
        "tool over-report badly, because everything looks rare at once — the "
        "report states this at the top rather than letting a flood of "
        "findings look authoritative.",
        see=["rarity / prevalence"],
    ),
    Term(
        "beacon",
        [r"\bbeacon\b", r"periodic (outbound )?callback", r"\bcallback\b"],
        "A host checking in to a controller on a regular schedule.",
        "A beacon is a channel that calls out to the same destination at "
        "regular intervals — the pattern of an implant checking in with a "
        "command-and-control server for instructions. The difficulty is that "
        "the pattern is indistinguishable in isolation from entirely benign "
        "periodic traffic, so the tool reports a beacon only when regular "
        "timing coincides with rarity and other supporting evidence, and it "
        "prints the arithmetic behind the confidence so the judgement can be "
        "checked rather than trusted.",
        see=["periodicity", "jitter", "rarity / prevalence"],
    ),
    Term(
        "exfiltration",
        [r"\bexfil", r"data exfiltration"],
        "Moving data out of a network to somewhere it should not go.",
        "Exfiltration is the covert movement of data out of an environment. "
        "In metadata alone its signature is an outbound-asymmetric channel to "
        "a rare destination, possibly paced to stay quiet. Because an "
        "ordinary backup or upload has the same raw shape, the tool treats "
        "the shape as a question and leans on rarity and destination to tell "
        "a leak from a legitimate transfer — it describes the flow and names "
        "what would confirm or refute the worry.",
        see=["asymmetry", "rarity / prevalence", "DNS tunnel"],
    ),
    Term(
        "DNS tunnel",
        [r"\btunnel", r"high[- ]cardinality zone"],
        "Smuggling data inside DNS queries, which are rarely inspected.",
        "A DNS tunnel encodes data into the names a host looks up, turning the "
        "resolver into an unwitting relay — a channel that gets through many "
        "networks because DNS is rarely filtered. Its signature is a single "
        "zone receiving a flood of distinct, often long and random-looking "
        "names (high cardinality under one zone). The same high cardinality "
        "can come from a CDN or a misbehaving client, so the tool measures "
        "the cardinality and the zone and lets the operator weigh it rather "
        "than declaring a tunnel outright.",
        see=["cardinality / fanout", "DNS", "exfiltration"],
    ),
    # ---- content & credentials -------------------------------------------
    Term(
        "JWT",
        [r"\bJWT\b", r"\bjwt\.", r"json web token"],
        "A signed, self-describing token used to carry identity or claims.",
        "A JWT (JSON Web Token) is a compact, signed token of three "
        "dot-separated parts — a header, a set of claims, and a signature — "
        "used to carry a user's identity or authorisation between services. "
        "Because the first two parts are only base64, not encrypted, the tool "
        "can read the algorithm and the claims and flag real weaknesses: a "
        "symmetric algorithm where an asymmetric one belongs (an RS/HS "
        "confusion risk), a missing expiry, or an identifier that also "
        "appears elsewhere in the capture. The token value itself is masked "
        "in output so the report does not leak a live credential.",
        see=["bearer token", "secret masking"],
    ),
    Term(
        "bearer token",
        [r"\bbearer\b"],
        "A credential that grants access to whoever holds it, no questions asked.",
        "A bearer token is an access credential with no binding to who "
        "presents it — possession is the whole of the authorisation, exactly "
        "like cash. That makes a bearer token leaking to the wrong "
        "destination serious: anyone who captures it can replay it until it "
        "expires. The tool watches for bearer tokens sent in cleartext or to "
        "a party unrelated to the one that issued them, and masks the value "
        "while keeping a fingerprint so the same token can be followed across "
        "requests.",
        see=["JWT", "secret masking", "cross-host correlation"],
    ),
    Term(
        "cookie flags (Secure, HttpOnly, SameSite)",
        [r"\bHttpOnly\b", r"\bSameSite\b", r"\bSecure\b(?!ly)", r"cookie\.flags"],
        "The attributes that decide how safely a browser cookie is handled.",
        "A cookie's security depends on three flags. Secure stops it being "
        "sent over cleartext HTTP; HttpOnly keeps it out of reach of "
        "JavaScript, blunting theft via cross-site scripting; SameSite limits "
        "whether it rides along on cross-site requests, which bears on "
        "cross-site request forgery. A session cookie missing these is a "
        "standard, real finding, so the tool reports which flags are absent — "
        "while masking the cookie's value so the report itself is not a theft "
        "risk.",
        see=["session fixation", "secret masking"],
    ),
    Term(
        "session fixation",
        [r"session fixation", r"\bfixation\b"],
        "A session identifier that survives login, so a planted one keeps working.",
        "Session fixation is a flaw where the identifier for a session does "
        "not change when a user authenticates. If an attacker can plant a "
        "known session id before login, it still identifies the session "
        "afterward, letting the attacker ride in on the victim's "
        "now-authenticated session. Detecting it requires knowing that a "
        "login actually succeeded — a heuristic the tool is explicit about, "
        "carrying the signal it used (a login path, a password field, a "
        "success status) alongside the finding so the boundary can be "
        "confirmed.",
        see=["cookie flags (Secure, HttpOnly, SameSite)"],
    ),
    Term(
        "CORS",
        [r"\bCORS\b", r"access-control-allow"],
        "The rules a server sets for which other sites may read its responses.",
        "CORS (Cross-Origin Resource Sharing) is the mechanism by which a "
        "server tells a browser which other origins are allowed to read its "
        "responses. Misconfigured, it can reflect any requesting origin back "
        "as allowed while also permitting credentials — effectively letting a "
        "hostile site make authenticated requests and read the answers. The "
        "tool reads these headers from cleartext or decrypted HTTP and flags "
        "the dangerous combinations.",
    ),
    Term(
        "cross-host correlation",
        [r"cross-host", r"unrelated host", r"third part(y|ies)",
         r"credential .*(sent|reached)"],
        "Catching a secret minted at one host and later sent to another.",
        "Some of the most important findings exist only between channels, not "
        "within any one of them: a bearer token or user identifier that one "
        "host issued and that later turns up being sent to an unrelated "
        "party. No single-request view can see this, because each request on "
        "its own looks fine. The tool fingerprints masked credentials so it "
        "can follow one across hosts and requests and report when it crossed "
        "a party boundary — using the Public Suffix List to decide what "
        "counts as 'unrelated'.",
        see=["bearer token", "public suffix / same-party", "secret masking"],
    ),
    Term(
        "secret masking",
        [r"\bmasked\b", r"sha256:", r"\bredact"],
        "Replacing credentials in output with a length and a fingerprint.",
        "Anything the tool emits — on screen or in a findings file that gets "
        "attached to a bug report — has its secrets masked by default: a "
        "cookie value, bearer token or API key is shown as a short prefix, a "
        "length, and a SHA-256 fingerprint rather than the live value. The "
        "analysis survives because the fingerprint keeps two copies of the "
        "same secret comparable, so a token can be tracked across the capture "
        "without ever being stored. Which fields are secret is declared by "
        "the inspector that produced them, not guessed from their names.",
        see=["JWT", "bearer token", "cross-host correlation"],
    ),
    # ---- analysis concepts ------------------------------------------------
    Term(
        "public suffix / same-party",
        [r"public suffix", r"registrable", r"same[- ]party", r"\bPSL\b"],
        "The rule for deciding whether two names belong to the same owner.",
        "Deciding whether two hostnames belong to the same party is not as "
        "simple as sharing a domain: foo.co.uk and bar.co.uk are different "
        "organisations, and two different buckets under s3.amazonaws.com are "
        "different parties. The Public Suffix List encodes exactly where one "
        "owner's control ends, letting the tool compute the registrable "
        "domain correctly and so judge, for a credential that moved between "
        "hosts, whether it stayed first-party or crossed to someone else — "
        "which is the whole finding.",
        see=["cross-host correlation"],
    ),
    Term(
        "confidence",
        [r"\bconfidence\b", r"weighted mean"],
        "A finding's score, shown as the arithmetic that produced it.",
        "Every finding carries a confidence between 0 and 1, and the report "
        "prints the calculation rather than only the result: each feature's "
        "measured value, the weight it was given, and the weighted mean they "
        "produce. This is deliberate — the tool's central claim is that no "
        "model writes a verdict and every score is auditable, so the "
        "confidence line exists to be checked by hand, not trusted because it "
        "looks precise.",
        see=["rarity / prevalence"],
    ),
    Term(
        "MTU",
        [r"\bMTU\b", r"\bMSS\b", r"~?1460", r"maximum (transmission|segment)"],
        "The largest packet a link carries; why big messages arrive in pieces.",
        "The MTU (maximum transmission unit) is the largest packet a network "
        "link will carry in one piece — typically around 1500 bytes on "
        "Ethernet, leaving an MSS of about 1460 bytes for TCP payload. "
        "Anything larger is split across several packets, which is why a "
        "certificate chain of a few kilobytes arrives in two to four segments "
        "and has to be reassembled before it can be read. The tool "
        "reassembles across segments rather than assuming one message fits in "
        "one packet.",
        see=["TCP", "certificate"],
    ),
    Term(
        "ASN / cloud attribution",
        [r"\bASN?\s?\d+\b", r"\bASN\b", r"announced by", r"autonomous system",
         r"the range's landlord"],
        "Who announces an address's route, and which cloud hosts the range.",
        "The internet routes between autonomous systems — networks under one "
        "administrative control, each with an AS number. Saying an address "
        "is 'announced by AS13335 CLOUDFLARENET' states who originates the "
        "route for it, which is a fact about network ownership, not about "
        "who runs the machine. Cloud range files go one layer further: the "
        "providers publish which prefixes belong to AWS, GCP or Azure and "
        "in which region — but an address inside AWS's ranges is a TENANT "
        "of AWS, who could be anyone with a credit card. Both attributions "
        "here are resolved from datasets on disk, offline by design: "
        "resolving a suspicious address against a live service tells the "
        "service what you are investigating, and a file leaks nothing. The "
        "answer is as current as the file, and the report names its "
        "sources.",
        see=["public suffix / same-party"],
    ),
    Term(
        "QUIC / HTTP/3",
        [r"\bQUIC\b", r"HTTP/3", r"\bh3\b", r"quic\.(version|packet)"],
        "The UDP-based transport under HTTP/3; encrypted from its first packet.",
        "QUIC is the transport protocol beneath HTTP/3, carried over UDP "
        "(usually port 443) instead of TCP, and now carrying a large share "
        "of web traffic. It encrypts more than TLS over TCP does: even the "
        "first packet's contents — where the ClientHello and its SNI live — "
        "are sealed, so on a QUIC connection this tool cannot read the "
        "server name the way it can from a TCP TLS handshake. What remains "
        "readable is the long-header envelope during the handshake (the "
        "QUIC version and packet type — enough to say 'this host speaks "
        "HTTP/3 to this endpoint') and, as always, the shape: datagram "
        "sizes, directions and timing survive any encryption. A QUIC "
        "channel is therefore reported like a TLS 1.3 certificate — what "
        "is unreadable is unreadable by design, and the report says which "
        "kind of silence it is.",
        see=["TLS 1.3", "encrypted traffic", "SNI", "activity shape"],
    ),
    # ---- industrial control and drone links --------------------------------
    Term(
        "Modbus (function codes, unit ids)",
        [r"\bModbus\b", r"function codes?\b", r"unit identifiers?\b",
         r"exception responses?", r"\bcoils?\b", r"holding registers?"],
        "The factory-floor protocol: commands a device obeys with no password.",
        "Modbus/TCP is one of the oldest and most widespread industrial "
        "protocols: a master polls devices, reads registers, writes coils "
        "and setpoints. It carries no authentication at all — a device obeys "
        "any correctly-formed command that reaches it, which is why WHO sent "
        "a command matters more than what it says. A function code names "
        "the operation (read, write, diagnostic); a unit identifier names "
        "the device behind a gateway. The behavioural tells are sweeps: one "
        "source stepping through many unit ids is mapping what exists, many "
        "function codes tried against one device is probing what it will "
        "obey, and a flood of exception responses is a device refusing "
        "operations something keeps requesting.",
        see=["cardinality / fanout", "rarity / prevalence"],
    ),
    Term(
        "802.11 / monitor mode / radiotap",
        [r"802\.11", r"monitor mode", r"\bradiotap\b", r"\bWi-?Fi\b",
         r"\bBSSID\b", r"\bSSID\b"],
        "Capturing Wi-Fi off the air, and the headers that wrap those frames.",
        "An ordinary Wi-Fi capture, taken while associated to an access "
        "point, arrives already stripped to Ethernet-looking frames — the "
        "tool reads it like any wired capture. Monitor mode is different: the "
        "adapter listens to raw 802.11 frames on a channel, including other "
        "devices' traffic and the management frames (beacons, probes, "
        "deauthentications) that never appear once a link is up. Those frames "
        "carry a radiotap header — the radio's own metadata, channel and "
        "signal strength, prepended by the capture — ahead of the 802.11 "
        "header proper. The tool parses both to reach the IP inside a data "
        "frame; but a data frame on a WPA network is encrypted, its payload "
        "ciphertext with no readable structure, exactly like a TLS record — "
        "so on a protected network the meaning is in the metadata (who is "
        "present, what networks devices look for, deauth floods) rather than "
        "the payload. Monitor-mode capture reaches other people's "
        "communications and is governed by different law than reading your "
        "own traffic.",
        see=["encrypted traffic", "MAC / OUI vendor"],
    ),
    Term(
        "ARP / NDP (neighbour resolution)",
        [r"\bARP\b", r"\bNDP\b", r"neighbour", r"neighbor",
         r"hardware address(es)?", r"cache poisoning", r"ADDRESS / HARDWARE"],
        "How a LAN maps an IP to a hardware address — and how that gets spoofed.",
        "Before two machines on the same network segment can exchange a "
        "packet, the sender must learn the recipient's hardware (MAC) "
        "address for its IP. ARP does this for IPv4 and NDP (neighbour "
        "discovery, over ICMPv6) for IPv6: a request asks 'who has this "
        "address?' and the owner replies 'it is at this MAC'. Those replies "
        "are the most authoritative IP-to-hardware statements on the wire, "
        "and the tool collects them into a neighbour table that names local "
        "devices. The same mechanism is a classic attack: because a host "
        "will believe any reply, an attacker can answer for an address that "
        "is not its own — usually the gateway's — and quietly sit in the "
        "middle of the victim's traffic (ARP cache poisoning, a form of "
        "adversary-in-the-middle). The tell is one IP resolving to more than "
        "one MAC, which the report surfaces — alongside the innocent causes "
        "(a reassigned DHCP lease, a replaced card, router redundancy) that "
        "produce the same shape.",
        see=["MAC / OUI vendor", "DHCP"],
    ),
    Term(
        "MAC / OUI vendor",
        [r"\bMAC\b", r"\bOUI\b", r"locally-administered", r"randomised",
         r"hardware vendor"],
        "Naming a LAN device by the vendor block of its hardware address.",
        "Every network interface has a MAC address, and its first half is an "
        "OUI (Organisationally Unique Identifier) assigned to the vendor who "
        "made the hardware — so a MAC beginning b8:27:eb is a Raspberry Pi, "
        "and one in Hikvision's block is probably a camera. The tool reads "
        "the source MAC a host puts on its own frames and names the device "
        "from an offline vendor table. Two honesty limits apply. First, a "
        "MAC only names the device for a host on the LOCAL segment: beyond "
        "the gateway, a frame's source MAC is the gateway's, so the tool "
        "attributes MACs only to private addresses and never to internet "
        "endpoints. Second, modern phones and laptops randomise their MAC "
        "for privacy — a randomised (locally-administered) address names no "
        "vendor, and the report says so rather than guessing.",
        see=["ASN / cloud attribution", "DHCP"],
    ),
    Term(
        "DNP3 / outstation",
        [r"\bDNP3\b", r"\boutstation\b", r"unsolicited", r"dnp3\.address"],
        "A SCADA protocol for utilities; the outstation is the field device.",
        "DNP3 (Distributed Network Protocol 3) supervises and controls "
        "equipment across electric, water and gas utilities. The master "
        "station issues commands; an outstation is the remote field device "
        "that carries them out and reports back — often on its own "
        "initiative, as unsolicited responses, so the master learns of a "
        "change without polling for it. Disabling that unsolicited reporting "
        "is a recognised attack step: it blinds the operator to what the "
        "equipment is doing while control continues, which is why the report "
        "flags it specifically. Like Modbus, base DNP3 authenticates "
        "nothing, so the signal is again provenance — a control command or a "
        "restart from a source with no established history.",
        see=["Modbus (function codes, unit ids)", "rarity / prevalence"],
    ),
    Term(
        "MAVLink",
        [r"\bMAVLink\b", r"mavlink\.", r"\bairframe\b", r"\bdisarm\b",
         r"ground[- ]station"],
        "The messaging protocol between a drone and its ground station.",
        "MAVLink is the lightweight message protocol that carries commands "
        "and telemetry between an uncrewed vehicle (a drone) and its ground "
        "control station: arm and disarm, mode changes, waypoints, parameter "
        "writes, and a stream of position reports. It identifies the sender "
        "by a numeric system id but, in its common form, authenticates "
        "nothing — so a disarm or a ground-station rebind from a system id "
        "with no prior history is the shape of a hijack attempt. The tool "
        "also checks telemetry against physics: a reported position that "
        "moved faster than the airframe could fly is either a spoofed GPS "
        "feed or a sensor fault, and either is worth knowing. Wireshark ships "
        "no MAVLink dissector, so this one is parsed natively.",
        see=["rarity / prevalence"],
    ),
    Term(
        "capture artefacts (snaplen, SPAN duplicates)",
        [r"\bsnaplen\b", r"CAPTURE ARTEFACTS", r"byte-identical",
         r"SPAN port", r"\btruncated\b", r"timestamp earlier"],
        "Defects the capture apparatus adds to the record of the traffic.",
        "A capture file is a record made by a tool, and the tool leaves "
        "marks. A snaplen is a per-frame byte limit many capture tools "
        "apply; frames above it are cut short, so the file holds the front "
        "of each message and silently lacks the rest — detectable because "
        "the IP header still states the full length. A SPAN (mirror) port "
        "fed from both directions of a link delivers many packets twice, "
        "byte-identical, inflating every volume figure; a genuine TCP "
        "retransmission differs in its IP header, so exact copies are the "
        "apparatus, not the network. Timestamps that run backwards or "
        "freeze poison every interval measurement, and a long silent gap "
        "usually means the capture stopped and resumed. The report lists "
        "these artefacts before the measurements they would otherwise "
        "quietly distort.",
        see=["MTU", "exchange"],
    ),
    # ---- cleartext service announcements ----------------------------------
    Term(
        "SSH banner",
        [r"\bSSH\b", r"ssh\.(client|server)", r"OpenSSH", r"identification string"],
        "The software name each side of an SSH session announces in the clear.",
        "SSH encrypts everything — after one revealing moment. The first "
        "bytes each side sends are a cleartext identification string naming "
        "its implementation and version: 'SSH-2.0-OpenSSH_9.6', "
        "'SSH-2.0-paramiko_3.4.0'. That single line says what software is "
        "running on each end before any key is exchanged, and it is all this "
        "tool reads of an SSH session — everything after the banners is "
        "encrypted and is described as shape, exactly like TLS. A server "
        "banner tells you what is listening; an unusual client banner (an "
        "automation library where only interactive use is expected) tells "
        "you what is connecting.",
        see=["encrypted traffic", "activity shape"],
    ),
    Term(
        "NTP / stratum",
        [r"\bNTP\b", r"\bstratum\b", r"ntp\.(mode|stratum)"],
        "The time-synchronisation protocol; stratum is distance from a true clock.",
        "NTP (Network Time Protocol) is how machines keep their clocks "
        "right, and it is never encrypted. Its header already interprets the "
        "exchange: a mode-3 message is a client asking, mode 4 is a server "
        "answering, mode 5 is a broadcast. Stratum is how many hops the "
        "answering clock is from a reference source — stratum 1 is attached "
        "to one, each relay adds one, and 0 in a reply is a refusal. NTP is "
        "ordinary and everywhere, which is precisely why it matters to a "
        "reader: it is among the most common legitimately periodic traffic, "
        "the kind a beacon detector must not confuse with a callback.",
        see=["periodicity", "rarity / prevalence"],
    ),
    Term(
        "DHCP",
        [r"\bDHCP\b", r"dhcp\.(message|hostname)", r"DISCOVER|OFFER|REQUEST|ACK"],
        "How a device joins a network — and introduces itself by name.",
        "DHCP (Dynamic Host Configuration Protocol) is the exchange a device "
        "performs to obtain an address when it joins a network: DISCOVER, "
        "OFFER, REQUEST, ACK. It is cleartext, and it carries something no "
        "other protocol here does — the hostname option, in which the device "
        "states the name it calls ITSELF. That self-reported name is the "
        "best label a LAN host will ever volunteer, so the report uses it to "
        "name local addresses nothing ever resolves — marked as lower "
        "authority than a name the network asserted, because a device can "
        "call itself anything it likes.",
        see=["DNS"],
    ),
    Term(
        "mDNS / LLMNR",
        [r"\bmDNS\b", r"\bLLMNR\b", r"dns\.service", r"name gossip"],
        "The LAN's serverless name systems — DNS format, multicast delivery.",
        "mDNS (multicast DNS, port 5353) and LLMNR (port 5355) answer the "
        "question 'who on this network is called X?' without any DNS server: "
        "a host multicasts the query and whoever owns the name replies. They "
        "use the DNS wire format but are a different act from a resolver "
        "lookup — discovery gossip confined to the local segment. They are "
        "also a classic abuse surface: a machine that answers LLMNR queries "
        "for names it does not own can harvest authentication attempts "
        "(responder-style poisoning), which is why who answered is as "
        "interesting as who asked. The report keeps their channels separate "
        "from real resolver traffic so the statistics of one cannot bleed "
        "into the other.",
        see=["DNS", "resolver"],
    ),
    # ---- streaming (--stream / live) --------------------------------------
    #
    # These appear only in the streaming report, which has no full narration —
    # it is the findings and a cross-window summary. The words below occur in
    # that summary and nowhere in a batch report, so these entries stay out of
    # a file analysis and print only when the tool was actually windowing.
    Term(
        "sliding window",
        [r"sliding window", r"\bwindows?\b", r"emit(ted|s)? every", r"--window"],
        "A moving span of recent traffic the live analysis runs over.",
        "A file can be read whole, but a live link never ends, so streaming "
        "mode runs the same analysis over a sliding window: the last N seconds "
        "of traffic, re-examined every few seconds as the window slides "
        "forward. The window is measured in event time — the timestamps in the "
        "traffic itself, not the wall clock — which is why replaying a saved "
        "file through the windower produces exactly what a live run would, and "
        "is how streaming is tested at all. Because each window re-emits the "
        "channels it still holds, a finding's evidence accumulates and its "
        "confidence can rise as it is seen again. The window has to be long "
        "enough to hold the cadence you want to catch: a 54-second beacon "
        "needs roughly 324 seconds of window to show the six repeats a cadence "
        "measurement requires, and a window too short for a cadence does not "
        "weaken that finding — it makes it absent, which the report says "
        "outright rather than leaving as a silent gap.",
        see=["persistent / TRANSIENT finding", "periodicity", "load shedding",
             "baseline"],
    ),
    Term(
        "persistent / TRANSIENT finding",
        [r"\bTRANSIENT\b", r"\bpersistent\b", r"across \d+ windows?"],
        "Whether a streamed finding held across windows or flickered in one.",
        "Streaming reports how each finding behaved over the run, because that "
        "is the extra information windowing buys. A finding seen across many "
        "windows is marked persistent: the evidence recurred, which is what a "
        "real condition does. A finding seen in only one window out of many is "
        "marked TRANSIENT — it may be genuine, but it may equally be an "
        "artefact of where a window boundary happened to fall, splitting one "
        "burst so a threshold was crossed once and never again. The tool "
        "cannot tell those apart from timing alone, so it flags the finding "
        "and leaves the judgement to the operator, who has the context it "
        "does not.",
        see=["sliding window", "confidence"],
    ),
    Term(
        "load shedding",
        [r"shed(ding)? load", r"load[- ]shed", r"\bevicted\b",
         r"late observations?"],
        "Deliberately dropping traffic to stay within a memory bound.",
        "A live capture off a flooded link can arrive faster than it can be "
        "held, so the windower is bounded: it caps how many channels and how "
        "many observations per channel it keeps, and it discards observations "
        "that arrive older than the current window. That dropping is load "
        "shedding, and it is never silent — the report counts what was shed "
        "and says so, because a quiet result off a saturated link has to "
        "distinguish 'nothing was happening' from 'the tool could not keep "
        "up'. Findings after load shedding are drawn from less traffic than "
        "the link actually carried, and the advisory saying so travels with "
        "them.",
        see=["sliding window"],
    ),
]


def terms_in(text: str) -> List[Tuple[int, Term]]:
    """Terms whose triggers appear in `text`, paired with first-appearance.

    Returned sorted by where each term first occurs, so a caller printing
    them walks the reader down the report in the order the jargon was used.
    Ties — two terms first appearing at the same offset — keep definition
    order, which groups related concepts the way the list above arranges them.
    """
    hits: List[Tuple[int, int, Term]] = []
    for order, term in enumerate(GLOSSARY):
        at = term.first_match(text)
        if at is not None:
            hits.append((at, order, term))
    hits.sort(key=lambda h: (h[0], h[1]))
    return [(at, term) for at, _, term in hits]


def _wrap(text: str, width: int = 70, indent: str = "      ") -> List[str]:
    """Greedy wrap with an explicit indent, matching the narrator's style."""
    words = text.split()
    lines: List[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent + word
        else:
            current = f"{current} {word}" if current.strip() else indent + word
    if current.strip():
        lines.append(current.rstrip())
    return lines


def glossary_section(narration: str, width: int = 70) -> List[str]:
    """The TERMS section for a rendered narration, or [] if nothing matched.

    Scans the narration the rest of the report produced and defines only the
    terms that actually appeared in it. Returns an empty list when none did,
    so the header is never printed over a capture whose vocabulary the
    glossary does not cover (a pure industrial capture, say).
    """
    found = terms_in(narration)
    if not found:
        return []

    out: List[str] = ["", "── TERMS IN THIS REPORT " + "─" * 45]
    out += _wrap(
        "Plain-language definitions for the technical terms this report used, "
        "in the order they first appeared. Nothing here is specific to your "
        "capture — these are definitions, not findings; the report's claims "
        "about this capture are in the sections above. No model writes any of "
        "this, so a definition cannot drift from what the term means.",
        width=width, indent="  ",
    )

    present = {term.term for _, term in found}
    for _, term in found:
        out.append("")
        out.append(f"  {term.term}")
        out += _wrap(term.long, width=width, indent="      ")
        # Only cross-reference terms that are themselves defined in THIS
        # section, so "see also" never points a reader at an entry that was
        # not printed because its term never came up in the capture.
        related = [name for name in term.see if name in present]
        if related:
            out += _wrap("see also: " + ", ".join(related),
                         width=width, indent="      ")
    return out
