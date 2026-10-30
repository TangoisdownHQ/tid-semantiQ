"""What a TLS ClientHello's shape says about the client — and what it doesn't.

A ClientHello is sent in the clear, before any encryption, and its shape —
whether it uses GREASE, how many ciphers and extensions it offers, what ALPN
protocols it advertises — differs between client families in ways that are
stable enough to be useful and weak enough to be honest about.

The honest part matters more than the clever part here, so this classifier is
built the opposite way round from a fingerprint database. It does NOT try to
name a product from an exact hash (we hold no such database, and could not
ship a license-clean one). It reports only coarse families that a few
high-signal, well-understood properties genuinely separate:

  - GREASE (RFC 8701) is the strongest single tell. Browsers (Chrome,
    Firefox, Edge) and browser-mimicking stacks (utls, cronet) send random
    GREASE values to keep middleboxes tolerant of unknowns; most
    command-line and library stacks (OpenSSL, curl, Go, Python, Java) do
    not. So GREASE present vs absent is a real fork.
  - ALPN offering `h2` is browser-like; a minimal client often offers
    nothing or only `http/1.1`.
  - A long cipher/extension list is browser-like; a short one is a minimal
    client.

Every reading carries the caveat the rest of the tool already states about
the fingerprint: this identifies the LIBRARY, not intent. A utls-based
implant presents Chrome's shape exactly, so "consistent with a browser" is
never "benign". The output is a rarity/description feature joined to other
evidence, never a verdict — which is why it lives here and in the narrator,
and has no primitive and fires no rule of its own.
"""

from __future__ import annotations

from typing import List, NamedTuple, Sequence


class ClientProfile(NamedTuple):
    #: A coarse, hedged family label, e.g. "a modern browser or a
    #: browser-mimicking client". Never a product name.
    family: str
    #: The observable properties the label rests on, each a short phrase, so
    #: the reader sees the evidence and not just the conclusion.
    signals: List[str]


#: Below this many offered ciphers, a ClientHello looks like a minimal client
#: rather than a browser. Browsers offer ~13-16 after GREASE removal; OpenSSL
#: s_client and Go's stdlib offer far fewer by default. A soft boundary, used
#: only to colour a reading GREASE has not already decided.
_SPARSE_CIPHERS = 8


def classify_client(
    uses_grease: bool,
    alpn: Sequence[str] = (),
    cipher_count: int = 0,
    ext_count: int = 0,
) -> ClientProfile:
    """A coarse client-family reading from ClientHello shape.

    Deliberately conservative: when the signals do not clearly separate the
    families, it says so rather than guessing a product.
    """
    alpn = [a for a in alpn if a]
    signals: List[str] = []
    if uses_grease:
        signals.append("sends GREASE (RFC 8701)")
    else:
        signals.append("no GREASE")
    if alpn:
        signals.append("ALPN offers " + ", ".join(alpn))
    if cipher_count:
        signals.append(f"{cipher_count} cipher suites")
    if ext_count:
        signals.append(f"{ext_count} extensions")

    has_h2 = any(a == "h2" for a in alpn)

    if uses_grease and has_h2:
        family = ("a modern browser or a browser-mimicking client "
                  "(e.g. utls, cronet)")
    elif uses_grease:
        family = "a GREASE-using client — a modern browser or a utls-based tool"
    elif has_h2:
        family = ("an HTTP/2-capable non-browser client — it offers h2 but "
                  "sends no GREASE, unlike a browser")
    elif cipher_count and cipher_count <= _SPARSE_CIPHERS:
        family = ("a command-line or library TLS client (e.g. OpenSSL, curl, "
                  "Go, Python, Java) — no GREASE and a short cipher list")
    else:
        family = ("an unspecified client — the shape does not clearly "
                  "separate a browser from a library stack")

    return ClientProfile(family=family, signals=signals)


#: The fixed caveat the narrator prints under any client reading. One place,
#: so the honesty cannot be edited out of one call site and left in another.
CAVEAT = (
    "This reads the TLS library from handshake shape, not the application or "
    "intent: a tool using utls presents a browser's shape exactly. It is a "
    "description joined to other evidence, never a verdict."
)
