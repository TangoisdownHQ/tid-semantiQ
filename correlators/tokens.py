"""Session token quality — entropy, predictability, and structure.

The clearest thing this tool can do that a request-by-request tool cannot. A
proxy shows you one session token and it looks like noise. Twelve tokens from
twelve logins show you that eighteen of their thirty-two characters never
change, or that consecutive values differ by one, or that the "random" token
is base64 of the user's email. None of that is visible in a single sample.

A NOTE ON STATISTICAL HONESTY, because this is where a tool like this
normally lies.

With n samples you can observe at most n distinct values at any character
position, so the measured entropy of a position is capped at log2(n) bits
NO MATTER HOW GOOD the generator is. Twelve samples can never measure more
than 3.58 bits per position. Reporting a measured total as "this token has
48 bits of entropy" would therefore condemn a perfectly good 128-bit token
on the strength of having seen it twelve times.

So the scoring here rests only on what few samples can actually PROVE:

    provable      a position that never varied across n samples
    provable      consecutive values whose numeric span is a vanishing
                  fraction of the nominal keyspace
    provable      a decoded token containing an identifier seen elsewhere
    NOT provable  "the entropy of this generator is X bits"

Measured entropy is still reported, labelled as a lower bound with the
measurement ceiling beside it, so an operator can see the difference between
"weak" and "we only looked twelve times".
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl

from core.correlate import Correlator, CorrelationOutput, observations_of
from core.suffixes import party
from core.model import Channel, Context, InspectionResult, Locus, Observation, Series

__all__ = ["SessionTokenQuality"]


#: Distinct values needed before any analysis is attempted. Below this the
#: correlator reports what is missing instead of guessing — see
#: `insufficient` in the emitted facts.
MIN_SAMPLES = 8

#: OWASP/NIST guidance for session identifiers. Used only as a reporting
#: threshold against a LOWER BOUND, never against a measured estimate.
TARGET_BITS = 64

_SESSION_NAMES = (
    "sess", "sid", "auth", "token", "login", "remember", "identity",
    "jsession", "phpsessid", "asp.net_sessionid", "connect.sid",
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _registrable(host: str) -> str:
    """Registrable domain via the Public Suffix List — see core/suffixes.py."""
    return party(host)


def _host_of(channel: Channel) -> str:
    return channel.dims.get("host") or (
        channel.responder.value if channel.responder else "?"
    )


def _looks_like_session(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SESSION_NAMES)


# --------------------------------------------------------------------------
# analysis primitives
# --------------------------------------------------------------------------


def positional_entropy(values: Sequence[str]) -> Tuple[float, float, int, int]:
    """(measured bits, measurable ceiling, constant positions, length).

    Only equal-length values are analysed positionally; varying length is
    reported separately by the caller because it changes what the positions
    mean.
    """
    n = len(values)
    length = len(values[0])
    ceiling_per_position = math.log2(n)
    measured = 0.0
    constant = 0

    for index in range(length):
        column = [value[index] for value in values]
        counts = Counter(column)
        if len(counts) == 1:
            constant += 1
            continue
        entropy = -sum(
            (count / n) * math.log2(count / n) for count in counts.values()
        )
        measured += entropy

    return measured, ceiling_per_position * length, constant, length


def _base_of(values: Sequence[str]) -> Optional[int]:
    """The smallest numeric base every value parses in, or None."""
    for base in (10, 16, 36):
        try:
            for value in values:
                int(value, base)
            return base
        except ValueError:
            continue
    return None


def sequential_span(values: Sequence[str]) -> Optional[Tuple[int, float, int]]:
    """(span, span/keyspace, base) when values are numerically clustered.

    This is the provable counter test, and it does not rely on the values
    arriving in order — observation order in a capture is not generation
    order. A generator with a real keyspace of base**length will not produce
    twelve values spanning a millionth of it by chance; a counter will.
    """
    base = _base_of(values)
    if base is None:
        return None
    numbers = sorted(int(value, base) for value in values)
    span = numbers[-1] - numbers[0]
    length = max(len(value) for value in values)
    keyspace = float(base) ** length
    if keyspace <= 0:
        return None
    return span, (span / keyspace), base


#: Clock values are only credible inside a plausible epoch window.
_EPOCH_LOW, _EPOCH_HIGH = 1_577_836_800, 2_000_000_000     # 2020-01-01 .. 2033
#: One capture session spans hours, not years. A real embedded clock shows a
#: tight spread; coincidental matches scatter across the whole window.
_CLOCK_MAX_SPAN_S = 86_400


def embedded_timestamp(values: Sequence[str]) -> Optional[str]:
    """A plausible epoch second at a FIXED OFFSET across every sample.

    THE LOOSE VERSION OF THIS TEST FIRES ON EVERYTHING. An arbitrary 8-hex
    window falls inside the 2020-2033 epoch range about 9.8% of the time, and
    a 64-character hex token contains 57 such windows — so "some sample has
    an in-range window somewhere" is near-certain for any strong token. The
    first implementation did exactly that and flagged 16 samples of
    `secrets.token_hex(32)`.

    Three conditions make the claim sound, and all three are required:

      1. the SAME offset in every sample parses inside the epoch window
         (0.098**n per offset on random hex — about 1e-16 at n=16)
      2. the values there span less than a day, as one capture session must
      3. at least two are distinct, or it is fixed framing and not a clock
    """
    if not values:
        return None

    for width, base, label in ((10, 10, "decimal"), (8, 16, "hex")):
        longest = min(len(value) for value in values)
        for offset in range(0, longest - width + 1):
            candidates: List[int] = []
            for value in values:
                chunk = value[offset:offset + width]
                try:
                    number = int(chunk, base)
                except ValueError:
                    break
                if not (_EPOCH_LOW <= number <= _EPOCH_HIGH):
                    break
                candidates.append(number)
            else:
                if len(set(candidates)) < 2:
                    continue
                if max(candidates) - min(candidates) > _CLOCK_MAX_SPAN_S:
                    continue
                return (
                    f"{label} at offset {offset}, spanning "
                    f"{max(candidates) - min(candidates)}s across samples"
                )
    return None


def decoded_structure(value: str) -> Optional[str]:
    """Printable plaintext hiding inside the token, if any.

    Tries base64 and base64url with the padding browsers omit. A token that
    decodes to readable text is a token an attacker can read, and usually one
    they can forge.
    """
    candidates = [value]
    stripped = value.rstrip("=")
    candidates.append(stripped + "=" * (-len(stripped) % 4))
    for candidate in candidates:
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(candidate, validate=False)
            except (ValueError, TypeError):
                continue
            if len(raw) < 4:
                continue
            printable = sum(1 for byte in raw if 32 <= byte < 127)
            if printable / len(raw) >= 0.85:
                return raw.decode("ascii", "replace")
    return None


# --------------------------------------------------------------------------
# the correlator
# --------------------------------------------------------------------------


class SessionTokenQuality(Correlator):
    """Group every session-looking token by name, then analyse the group.

    Grouped per registrable domain and token name, because different cookies
    come from different generators and averaging them would hide a weak one
    behind a strong one.

    Attributed to the channel where the token was SET — the host whose
    generator is at fault — so the finding lands on the right service when a
    token is minted on one host and used on several.
    """

    name = "auth.token_quality"
    domains = ("http",)

    def correlate(
        self, series: Sequence[Series], ctx: Context
    ) -> Iterable[CorrelationOutput]:
        relevant = self.relevant(series)
        identifiers = _identifiers_in(relevant)

        # (registrable domain, token name) -> ordered distinct values
        groups: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        where: Dict[Tuple[str, str], Tuple[Channel, List[Locus]]] = {}
        sightings: Dict[Tuple[str, str], int] = defaultdict(int)

        for one, obs in observations_of(relevant):
            host = _host_of(one.channel)
            domain = _registrable(host)
            for name, value in _tokens_in(obs):
                if not _looks_like_session(name) or len(value) < 8:
                    continue
                if _JWT.match(value):
                    # A JWT's structure is public by design; judging its
                    # entropy is meaningless. `JwtWeakness` handles those.
                    continue
                key = (domain, name)
                sightings[key] += 1
                if value not in groups[key]:
                    groups[key].append(value)
                entry = where.get(key)
                if entry is None:
                    where[key] = (one.channel, [obs.locus] if obs.locus else [])
                elif obs.locus and obs.locus not in entry[1]:
                    entry[1].append(obs.locus)

        for key, values in groups.items():
            channel, loci = where[key]
            result = self._judge(
                key, values, sightings[key], identifiers, loci
            )
            if result is not None:
                yield channel, result

    # -- scoring -----------------------------------------------------------

    def _judge(
        self,
        key: Tuple[str, str],
        values: List[str],
        sightings: int,
        identifiers: Set[str],
        loci: List[Locus],
    ) -> Optional[InspectionResult]:
        domain, name = key
        n = len(values)

        if n < MIN_SAMPLES:
            # Say what is missing rather than guessing from too few samples.
            # Scored at zero so no rule can fire on it; it reaches the
            # operator as an advisory and in `--out json`.
            return InspectionResult(
                name=self.name,
                score=0.0,
                facts={
                    "token.name": name,
                    "domain": domain,
                    "distinct_values": str(n),
                    "observations": str(sightings),
                    "insufficient": (
                        f"{n} distinct value(s); quality analysis needs "
                        f"{MIN_SAMPLES}. Log in {MIN_SAMPLES - n} more time(s) "
                        "and re-capture."
                    ),
                },
                features={"distinct_values": float(n), "assessable": 0.0},
                occurrences=sightings,
                loci=tuple(loci[:4]),
                notes=("not assessed — too few distinct values",),
            )

        issues: List[str] = []
        score = 0.0
        facts: Dict[str, str] = {
            "token.name": name,
            "domain": domain,
            "distinct_values": str(n),
            "observations": str(sightings),
        }
        features: Dict[str, float] = {
            "distinct_values": float(n),
            "assessable": 1.0,
        }

        lengths = {len(value) for value in values}
        facts["length"] = (
            str(next(iter(lengths))) if len(lengths) == 1
            else f"varies {min(lengths)}-{max(lengths)}"
        )

        # --- decoded structure: the most serious and the most provable ----
        for value in values:
            decoded = decoded_structure(value)
            if not decoded:
                continue
            leaked = sorted(i for i in identifiers if i and i in decoded)
            if leaked:
                issues.append(
                    "token decodes to plaintext containing an identifier "
                    f"seen elsewhere in the capture ({', '.join(leaked[:2])})"
                )
                score += 0.85
                facts["decoded_contains"] = ", ".join(leaked[:3])
            else:
                issues.append("token decodes to printable plaintext")
                score += 0.35
            facts["decoded_sample"] = decoded[:120]
            break

        # --- counter / clustered keyspace ---------------------------------
        sequential = sequential_span(values)
        if sequential is not None:
            span, fraction, base = sequential
            facts["numeric_base"] = str(base)
            facts["numeric_span"] = str(span)
            facts["span_fraction_of_keyspace"] = f"{fraction:.3e}"
            features["span_fraction"] = fraction
            if fraction < 1e-6:
                issues.append(
                    f"all {n} values fall within {span} of each other in a "
                    f"base-{base} keyspace — consistent with a counter"
                )
                score += 0.80
            elif fraction < 1e-3:
                issues.append(
                    f"values cluster in {fraction:.1e} of the nominal keyspace"
                )
                score += 0.40

        # --- embedded clock -----------------------------------------------
        clock = embedded_timestamp(values)
        if clock:
            issues.append(f"an epoch timestamp varies inside the token ({clock})")
            score += 0.35
            facts["embedded_timestamp"] = clock

        # --- positional structure (equal-length only) ---------------------
        if len(lengths) == 1:
            measured, ceiling, constant, length = positional_entropy(values)
            varying = length - constant
            facts["constant_positions"] = f"{constant} of {length}"
            facts["measured_bits_lower_bound"] = f"{measured:.1f}"
            facts["measurable_ceiling_bits"] = f"{ceiling:.1f}"
            features.update({
                "constant_positions": float(constant),
                "varying_positions": float(varying),
                "measured_bits": measured,
                "ceiling_bits": ceiling,
            })

            if constant and varying:
                fraction_constant = constant / length
                issues.append(
                    f"{constant} of {length} characters never varied across "
                    f"{n} samples — fixed framing, not entropy"
                )
                score += min(0.45, 0.6 * fraction_constant)

            # NOMINAL capacity of the varying region: how many bits COULD
            # live there given the alphabet, regardless of how many samples
            # were seen. Sample-independent, so comparing it to the target is
            # sound.
            #
            # The first version compared `varying * log2(n)` to the target
            # instead — but that quantity is the MEASUREMENT CEILING, which
            # shrinks with sample size. At n=8 it condemns a genuinely
            # 64-bit 16-hex token as "48 bits". Comparing a requirement
            # against a ceiling imposed by one's own sample size is the exact
            # error this module's header warns about.
            alphabet = len(set("".join(values)))
            bits_per_position = math.log2(alphabet) if alphabet > 1 else 0.0
            nominal_bits = varying * bits_per_position
            features["nominal_bits"] = nominal_bits
            facts["nominal_bits_in_varying_region"] = f"{nominal_bits:.1f}"
            facts["alphabet_size"] = str(alphabet)

            if varying == 0:
                issues.append("every sample is identical — the token is static")
                score += 0.60
            elif nominal_bits < TARGET_BITS:
                issues.append(
                    f"only {varying} of {length} characters vary, over a "
                    f"{alphabet}-symbol alphabet — a {nominal_bits:.0f}-bit "
                    f"keyspace at most, under the {TARGET_BITS}-bit guidance "
                    "for session identifiers"
                )
                score += 0.30

        charset = _charset(values)
        facts["charset"] = charset
        if charset == "digits":
            issues.append("decimal digits only")
            score += 0.20

        if not issues:
            return None

        facts["issues"] = "; ".join(issues)
        facts["sample"] = values[0]   # masked on output

        return InspectionResult(
            name=self.name,
            score=min(1.0, score),
            facts=facts,
            secret_facts=("sample", "decoded_sample"),
            features=features,
            occurrences=sightings,
            loci=tuple(loci[:8]),
            notes=(
                f"measured from {n} distinct values; entropy figures are "
                "lower bounds capped by sample size, never generator strength",
                "scoring rests only on constant positions, keyspace "
                "clustering and decoded structure — all provable at this n",
            ),
        )


def _charset(values: Sequence[str]) -> str:
    alphabet = set("".join(values))
    if alphabet <= set("0123456789"):
        return "digits"
    if alphabet <= set("0123456789abcdefABCDEF"):
        return "hex"
    if alphabet <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/"
    ):
        return "base64-ish"
    return f"mixed ({len(alphabet)} symbols)"


def _tokens_in(obs: Observation) -> List[Tuple[str, str]]:
    """(name, value) for every cookie or credential-ish parameter."""
    found: List[Tuple[str, str]] = []

    for raw in obs.attrs.get("set_cookie") or ():
        head = str(raw).split(";")[0]
        name, _, value = head.partition("=")
        if name.strip() and value.strip():
            found.append((name.strip(), value.strip()))

    cookie = str(obs.attrs.get("cookie", ""))
    if cookie:
        for pair in cookie.split(";"):
            name, _, value = pair.partition("=")
            if name.strip() and value.strip():
                found.append((name.strip(), value.strip()))

    query = str(obs.attrs.get("query", ""))
    if query:
        for name, value in parse_qsl(query, keep_blank_values=True):
            if value:
                found.append((name, value))

    return found


def _identifiers_in(series: Sequence[Series]) -> Set[str]:
    """Emails and user ids visible anywhere in the capture.

    Used to decide whether a decoded token is merely readable or actually
    discloses who it belongs to — the difference between a sloppy token and a
    forgeable one.
    """
    found: Set[str] = set()
    for one in series:
        for obs in one.observations:
            for blob in (
                str(obs.attrs.get("query", "")),
                str(obs.attrs.get("body_text", "")),
            ):
                if not blob:
                    continue
                found.update(_EMAIL.findall(blob)[:20])
            query = str(obs.attrs.get("query", ""))
            if query:
                for name, value in parse_qsl(query, keep_blank_values=True):
                    if name.lower() in (
                        "uid", "user_id", "userid", "user", "sub",
                        "account_id", "customer_id", "email",
                    ) and len(value) >= 4:
                        found.add(value)
    return found
