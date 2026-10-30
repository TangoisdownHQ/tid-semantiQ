"""Public Suffix List — where does one party's control end?

WHAT THIS REPLACES. Four call sites approximated the registrable domain by
counting two labels from the right, and each said so in its docstring. The
approximation is wrong wherever the suffix is multi-part, and wrong in the
direction that matters:

    foo.co.uk, bar.co.uk     label count -> both "co.uk"   -> SAME party
                             PSL        -> foo/bar.co.uk  -> different parties

So a credential shared between two unrelated UK or Australian organisations
read as first-party plumbing and was suppressed. Every target under a
multi-part ccTLD had the cross-party gate silently disabled.

It is also wrong the other way for cloud suffixes, which is arguably worse
for this tool:

    a.s3.amazonaws.com       label count -> "amazonaws.com" -> SAME party
    b.s3.amazonaws.com                                         as every other
                                                               S3 bucket
    PSL (private section)    -> a / b.s3.amazonaws.com       -> distinct

Two different S3 buckets, two different GitHub Pages sites, two different
Azure blob containers are different parties, and the PSL's private section is
what says so. For a tool whose headline finding is "a credential reached a
host it should not have", that distinction is the finding.

THE ALGORITHM, per publicsuffix.org, is small but has three traps:

  1. WILDCARDS. `*.ck` means every label under `ck` is a suffix.
  2. EXCEPTIONS. `!www.ck` overrides the wildcard; exceptions win outright,
     and the suffix is the exception rule MINUS its leftmost label.
  3. LONGEST MATCH. Both `com` and `s3.amazonaws.com` can match; the rule
     with more labels prevails. Taking the first match found is the classic
     bug here.

If no rule matches at all, the prevailing rule is `*` — the rightmost label
is the suffix. The registrable domain is then the suffix plus one more label,
and a host that IS exactly a public suffix has no registrable domain.
"""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

__all__ = [
    "PublicSuffixList",
    "default_list",
    "public_suffix",
    "registrable_domain",
    "same_party",
    "DEFAULT_PATH",
    "ICANN",
    "PRIVATE",
]

ICANN = "icann"
PRIVATE = "private"

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "public_suffix_list.dat"

_BEGIN_PRIVATE = "===BEGIN PRIVATE DOMAINS==="
_END_PRIVATE = "===END PRIVATE DOMAINS==="


class PublicSuffixList:
    """Rules loaded from a `public_suffix_list.dat`.

    Stdlib only. Lookup is a handful of set probes per query, walking the
    candidate suffixes from the right, so there is no need for a trie.
    """

    def __init__(self, path: Optional[Path] = None, text: Optional[str] = None):
        #: rule -> section
        self._rules: Dict[str, str] = {}
        #: the part after "*." -> section
        self._wildcards: Dict[str, str] = {}
        #: the part after "!" -> section
        self._exceptions: Dict[str, str] = {}
        self.stats = {
            "rules": 0, "wildcards": 0, "exceptions": 0,
            "punycode_added": 0, "punycode_failed": 0,
        }
        self.source = str(path) if path else "<inline>"

        if text is None:
            path = path or DEFAULT_PATH
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise RuntimeError(
                    f"public suffix list not readable at {path}: {exc}. "
                    "Refresh it with: curl -o data/public_suffix_list.dat "
                    "https://publicsuffix.org/list/public_suffix_list.dat"
                ) from exc
        self._parse(text)

    # -- loading -----------------------------------------------------------

    def _parse(self, text: str) -> None:
        section = ICANN
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("//"):
                if _BEGIN_PRIVATE in line:
                    section = PRIVATE
                elif _END_PRIVATE in line:
                    section = ICANN
                continue

            rule = line.lower()
            self._add(rule, section)

            # The published list carries ~500 rules with unicode labels, but
            # hostnames in a capture arrive as punycode, so those rules would
            # never match anything. Both forms are stored where the
            # conversion succeeds; failures are counted rather than hidden,
            # because a silently unmatched rule degrades to the parent-domain
            # answer with no sign that it did.
            if not rule.isascii():
                punycode = self._to_punycode(rule)
                if punycode is None:
                    self.stats["punycode_failed"] += 1
                elif punycode != rule:
                    self._add(punycode, section)
                    self.stats["punycode_added"] += 1

    def _add(self, rule: str, section: str) -> None:
        if rule.startswith("!"):
            self._exceptions.setdefault(rule[1:], section)
            self.stats["exceptions"] += 1
        elif rule.startswith("*."):
            self._wildcards.setdefault(rule[2:], section)
            self.stats["wildcards"] += 1
        else:
            self._rules.setdefault(rule, section)
            self.stats["rules"] += 1

    @staticmethod
    def _to_punycode(rule: str) -> Optional[str]:
        """Per-label IDNA encoding.

        Per label rather than whole-name because the stdlib codec applies
        nameprep to the entire string and rejects names containing a `*` or
        a `!`, which rules routinely do.
        """
        out = []
        for label in rule.split("."):
            if label in ("*", "") or label.startswith("!") or label.isascii():
                out.append(label)
                continue
            try:
                out.append(label.encode("idna").decode("ascii"))
            except (UnicodeError, UnicodeDecodeError):
                return None
        return ".".join(out)

    def describe(self) -> str:
        return (
            f"{self.stats['rules']} rules, {self.stats['wildcards']} wildcards, "
            f"{self.stats['exceptions']} exceptions "
            f"(+{self.stats['punycode_added']} punycode forms, "
            f"{self.stats['punycode_failed']} unconvertible) from {self.source}"
        )

    def is_delegated(self, host: str) -> bool:
        """Does this name's top-level label actually exist in the root zone?

        The PSL algorithm's default `*` rule means `public_suffix()` happily
        answers "a" for `ridemcts.a` — correct for the algorithm, useless for
        deciding whether a name could ever have resolved. This asks the
        different and more interesting question: is the TLD one the list has
        heard of?

        A no is a strong, cheap explanation for an NXDOMAIN flood. A host
        querying thousands of names under undelegated TLDs is almost always a
        resolver appending a search-domain list to an unqualified name, and
        saying so turns "90% of lookups failed" into something an operator can
        act on. It is also how a DGA aiming at a non-existent TLD would look,
        which is why the narrator reports the shape and not a cause.
        """
        label = _normalise(host).rsplit(".", 1)[-1]
        if not label:
            return False
        return label in self._rules or label in self._exceptions

    # -- lookup ------------------------------------------------------------

    def _allowed(self, section: str, include_private: bool) -> bool:
        return include_private or section == ICANN

    def public_suffix(
        self, host: str, include_private: bool = True
    ) -> Optional[str]:
        """The public suffix of `host`, or None for an IP or empty input.

        `include_private=False` restricts to the ICANN section, which is the
        right choice when the question is "which registry delegated this"
        rather than "who controls it".
        """
        host = _normalise(host)
        if not host or _is_ip(host):
            return None

        labels = host.split(".")
        best: Optional[str] = None

        # Walk candidate suffixes from the right, shortest first, keeping the
        # longest match. An exception wins outright, so it returns early.
        for index in range(len(labels) - 1, -1, -1):
            candidate = ".".join(labels[index:])

            section = self._exceptions.get(candidate)
            if section is not None and self._allowed(section, include_private):
                # The suffix is the exception rule minus its leftmost label.
                return ".".join(candidate.split(".")[1:]) or None

            section = self._rules.get(candidate)
            if section is not None and self._allowed(section, include_private):
                best = candidate

            # Wildcard: `*.ck` is stored as `ck`, and matches when there is
            # at least one more label to the left to absorb the `*`.
            if index > 0:
                parent = ".".join(labels[index:])
                section = self._wildcards.get(parent)
                if section is not None and self._allowed(section, include_private):
                    best = ".".join(labels[index - 1:])

        if best is not None:
            return best
        # No rule matched: the implicit `*` rule makes the rightmost label
        # the suffix.
        return labels[-1]

    def registrable_domain(
        self, host: str, include_private: bool = True
    ) -> Optional[str]:
        """Public suffix plus one label — the unit one party controls.

        None when there is no such thing: an IP address, or a host that is
        itself exactly a public suffix (`co.uk`, `s3.amazonaws.com`). Callers
        comparing parties should use `same_party`, or fall back to the host.
        """
        host = _normalise(host)
        if not host or _is_ip(host):
            return None

        suffix = self.public_suffix(host, include_private=include_private)
        if suffix is None:
            return None
        if host == suffix:
            return None

        suffix_labels = suffix.split(".")
        labels = host.split(".")
        if len(labels) <= len(suffix_labels):
            return None
        return ".".join(labels[-(len(suffix_labels) + 1):])

    def party(self, host: str, include_private: bool = True) -> str:
        """The comparison key for "is this the same party?".

        Falls back to the host itself for an IP, or for a host that is a bare
        public suffix. Never returns a value shared between two unrelated
        organisations, which is the failure the label-count approximation
        had.
        """
        host = _normalise(host)
        return self.registrable_domain(host, include_private=include_private) or host


# --------------------------------------------------------------------------
# module-level convenience
# --------------------------------------------------------------------------


_default: Optional[PublicSuffixList] = None
_lock = threading.Lock()


def default_list() -> PublicSuffixList:
    """The vendored list, parsed once per process."""
    global _default
    if _default is None:
        with _lock:
            if _default is None:
                _default = PublicSuffixList()
    return _default


def public_suffix(host: str, include_private: bool = True) -> Optional[str]:
    return default_list().public_suffix(host, include_private=include_private)


def registrable_domain(host: str, include_private: bool = True) -> Optional[str]:
    return default_list().registrable_domain(host, include_private=include_private)


def party(host: str, include_private: bool = True) -> str:
    """Comparison key for same-party decisions. See `PublicSuffixList.party`."""
    return default_list().party(host, include_private=include_private)


def same_party(a: str, b: str, include_private: bool = True) -> bool:
    return party(a, include_private=include_private) == party(
        b, include_private=include_private
    )


# --------------------------------------------------------------------------


def _normalise(host: str) -> str:
    """Lower-case, trailing-dot-free, and PORT-FREE.

    THE PORT IS THE PART THAT MATTERED. A `Host` header carries one whenever
    it is non-default, so `127.0.0.1:18080` reached here intact: the IP check
    below failed on it, the suffix walk then treated `1:18080` as a top-level
    label, and `party()` answered `0.1:18080`. That appeared in a report as a
    cookie's domain, which is how it was noticed.

    The consequence was not cosmetic. `party()` decides SAME-PARTY questions
    for the credential correlator, so `a.shop.test:8443` and `a.shop.test`
    computed different registrable domains — a credential sent to one host on
    two ports would have read as having leaked to a third party.
    """
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        return host

    # Bracketed IPv6 with an optional port: "[::1]:8443" -> "::1".
    if host.startswith("["):
        end = host.find("]")
        if end > 0:
            return host[1:end]
        return host

    # A hostname cannot contain a colon, so a single trailing ":digits" is a
    # port. More than one colon means a bare IPv6 literal, which must be
    # left alone — it has no port to strip without brackets.
    if host.count(":") == 1:
        name, _, port = host.partition(":")
        if port.isdigit():
            return name
    return host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Bracketed IPv6 as it appears in a Host header.
        if host.startswith("[") and host.endswith("]"):
            try:
                ipaddress.ip_address(host[1:-1])
                return True
            except ValueError:
                return False
        return False
