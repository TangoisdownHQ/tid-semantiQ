"""Secret redaction for anything that leaves the process.

THE PROBLEM THIS SOLVES. The moment the inspectors work, `findings.json`
contains live session cookies, bearer tokens and API keys — pulled out of
real traffic and written to disk in plain text. That file then gets attached
to a bug report, pasted into a ticket, or committed to a notes repo. A tool
that leaks the credentials it was auditing is worse than no tool. The
terminal counts too: reports get screenshotted and scrolled past in shared
sessions.

WHEN. At serialisation, never at capture. An inspector must see the real
value to analyse it — you cannot tell whether a JWT is unsigned, or measure a
session token's entropy, from a masked string. Real values live in memory;
masked values go to disk and to the screen.

WHAT. Only what the inspector DECLARED as secret, via
`InspectionResult.secret_facts`, plus a high-entropy backstop.

The first version of this module guessed from key names against a deny-list
of substrings ("token", "key", "cookie", "secret"). It masked `cookie.domain`
(`.example.com` — the finding), `cookie.path` (`/`), and `jwt.issues` (the
human-readable list of defects), because each key contains one of those
substrings. A redactor that destroys the report while still missing any key
nobody enumerated is the worst of both. The inspector knows which field holds
the credential; it says so.

WHAT SURVIVES. The analysis, which is the part worth reading:

    jwt.alg        "none"
    jwt.issues     "alg=none — unsigned token accepted; no exp claim"
    cookie.name    "session"
    cookie.domain  ".example.com"
    cookie.flags   "missing Secure, missing HttpOnly"
    cookie.value   "7f3a2b…5f6a (len 16, sha256:5fc2ce72)"   <- masked

The fingerprint is what keeps a masked value useful: two findings carrying
the same `sha256:` prefix are the same credential, so one token can be
followed across hosts and requests without ever being stored.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Mapping, Sequence

__all__ = [
    "Redactor", "redact_secrets", "passthrough",
    "fingerprint", "mask", "looks_secret",
]


_OPAQUE = re.compile(r"^[A-Za-z0-9_\-+/=]{28,}$")


def fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:8]


def mask(value: str, keep_head: int = 6, keep_tail: int = 4) -> str:
    """Mask a secret while leaving it identifiable and comparable.

    Short values are masked entirely — showing 6 of 10 characters of a PIN or
    a short key is a leak, not a redaction.
    """
    if len(value) <= keep_head + keep_tail + 4:
        return f"[redacted len={len(value)} {fingerprint(value)}]"
    return (
        f"{value[:keep_head]}…{value[-keep_tail:]} "
        f"(len {len(value)}, {fingerprint(value)})"
    )


def looks_secret(value: str) -> bool:
    """Backstop for an inspector that forgot to declare a secret.

    Deliberately narrow — 28+ characters, opaque alphabet, no spaces, not a
    URL or path. Narrow because this runs on fields the inspector said were
    safe, and over-reaching here is what wrecked the first implementation.
    """
    if len(value) < 28 or " " in value:
        return False
    if value.startswith(("http://", "https://", "/", ".")):
        return False
    return bool(_OPAQUE.match(value))


#: A redactor takes the facts AND the keys their inspector declared secret.
#: Both arguments are needed at the call site, so the declaration cannot be
#: accidentally dropped on the way to serialisation.
Redactor = Callable[[Mapping[str, Any], Sequence[str]], dict]


def redact_secrets(facts: Mapping[str, Any], secret_keys: Sequence[str] = ()) -> dict:
    """Mask the declared keys, plus anything the backstop catches."""
    declared = set(secret_keys)
    out: dict = {}
    for key, value in facts.items():
        if not isinstance(value, str):
            out[key] = value
        elif key in declared or looks_secret(value):
            out[key] = mask(value)
        else:
            out[key] = value
    return out


def passthrough(facts: Mapping[str, Any], secret_keys: Sequence[str] = ()) -> dict:
    """No redaction. Reached only via an explicit `--unsafe-show-secrets`.

    Named to be uncomfortable to type and uncomfortable to read in a diff.
    """
    return dict(facts)
