"""Structural primitives: asymmetry, fanout, rarity, entropy, sequence.

Where the timing primitives read the clock, these read volume, cardinality,
history, content, and order.

A NOTE ON FANOUT, because it exposed a real constraint in the model. Fanout
is naturally a cross-channel question ("how many destinations does this host
touch?"), and the interface deliberately gives a primitive one Series and
nothing else. Rather than widen the interface, fanout counts distinct values
of a named *attribute* inside the series — which means the question is asked
by choosing the channel's `dims` coarsely enough to contain it:

    DNS tunnelling    dims {"zone": "example.com"}, Fanout(attr="qname")
    port sweep        dims {"proto": "tcp"},        Fanout(attr="dport")
    peer sprawl       dims {"proto": "tcp"},        Fanout(attr="dst")

This is the concrete reason `Channel.dims` is the most consequential decision
when onboarding a domain: dims determine which questions are even askable.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import FrozenSet, Optional, Tuple

from core.model import Context, Direction, PrimitiveResult, Series
from core.primitives.base import Primitive, clamp, saturating

__all__ = ["Asymmetry", "Fanout", "Rarity", "Entropy", "SequenceOrder", "FailureRate"]


class Asymmetry(Primitive):
    """Which way does volume flow on this channel, and how hard?

    `features["asymmetry"]` is (egress - ingress) / (egress + ingress), in
    [-1, 1]: +1 is pure upload, -1 is pure download, 0 is balanced. Strong
    positive asymmetry over meaningful volume is the exfiltration shape;
    strong negative is download/staging.

    `score` multiplies the magnitude by a volume significance factor, because
    a six-byte exchange can be perfectly asymmetric and mean nothing. The
    factor is logarithmic — the difference between 1KB and 10KB matters more
    than between 1GB and 10GB.
    """

    name = "asymmetry"
    min_observations = 2

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        out_bytes = series.bytes_egress
        in_bytes = series.bytes_ingress
        total = out_bytes + in_bytes
        if total <= 0:
            return None

        # Broadcast domains have no pair semantics, so the ratio is undefined
        # rather than zero. Declining to answer is the correct outcome.
        if all(o.direction is Direction.BROADCAST for o in series):
            return None

        ratio = (out_bytes - in_bytes) / total

        sat_bytes = float(ctx.tunable("asymmetry.volume_saturation_bytes", 10_000_000))
        significance = clamp(math.log10(total + 1) / math.log10(sat_bytes + 1))

        return self._result(
            score=abs(ratio) * significance,
            features={
                "asymmetry": ratio,
                "egress_bytes": float(out_bytes),
                "ingress_bytes": float(in_bytes),
                "total_bytes": float(total),
                "volume_significance": significance,
            },
            sample_size=series.count,
            method="log-weighted-ratio",
        )


class Fanout(Primitive):
    """How many distinct values of one attribute appear on this channel?

    Two numbers matter and the score needs both. A high unique *count* alone
    is ordinary for a busy channel; a high unique *fraction* alone is
    ordinary for a quiet one. DNS tunnelling is the clean case: hundreds of
    queries where nearly every name is unique, under one parent zone.
    """

    name = "fanout"
    min_observations = 4

    def __init__(
        self,
        attr: str,
        name: Optional[str] = None,
        kind: Optional[str] = None,
        saturation: float = 50.0,
    ):
        self.attr = attr
        # Distinct instances coexist in one run, so each needs its own
        # ledger name — "fanout.qname" and "fanout.dport" are separate
        # evidence, and narrative citations must be able to tell them apart.
        self.name = name or f"fanout.{attr}"
        # `kind` restricts counting to one side of a request/response
        # protocol. Without it, Modbus unit-id scanning measured 24 unique
        # values over 80 messages — because responses echo the unit id, so
        # every scan looked half as concentrated as it was. Counting only
        # requests asks the question actually meant: how many distinct
        # things did the CLIENT address.
        self.kind = kind
        # Saturation is domain-dependent and cannot sensibly default once:
        # 50 distinct DNS names under a zone is unremarkable, 50 distinct
        # Modbus unit ids is an exhaustive sweep of a network that normally
        # has three. Overridable per deployment via the tunable below.
        self.saturation = saturation

    def applies_to(self, series: Series, ctx: Context) -> bool:
        if self.kind is not None:
            series = series.filter(kind=self.kind)
        if not super().applies_to(series, ctx):
            return False
        return any(self.attr in o.attrs for o in series)

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        if self.kind is not None:
            series = series.filter(kind=self.kind)

        values = [o.attrs[self.attr] for o in series if self.attr in o.attrs]
        if not values:
            return None

        counts = Counter(str(v) for v in values)
        unique = len(counts)
        total = len(values)
        unique_fraction = unique / total

        saturation = float(
            ctx.tunable(f"{self.name}.saturation", self.saturation)
        )
        score = saturating(unique, saturation) * unique_fraction

        return self._result(
            score=score,
            features={
                "unique_values": float(unique),
                "total_values": float(total),
                "unique_fraction": unique_fraction,
                "most_common_count": float(counts.most_common(1)[0][1]),
            },
            sample_size=total,
            method="exact-cardinality",
            notes=(f"attribute={self.attr}",),
        )


class Rarity(Primitive):
    """How new and how uncommon is this channel?

    THIS IS THE PRIMITIVE THAT MAKES THE TOOL USABLE. Periodic traffic is
    everywhere; periodic traffic to a destination nothing else on the estate
    has ever contacted is not. Without rarity, a beacon detector surfaces
    every update checker and telemetry agent on the network and the operator
    stops reading it.

    Requires a `BaselineStore` in Context. In SOC mode that is backed by the
    SOC's own history; in standalone mode by a local SQLite file, which is
    why the store protocol is deliberately three read methods wide.

    Scoring blends two independent signals — global uncommonness and recency
    of first observation — because either alone has a known blind spot: a
    long-lived but estate-unique channel is interesting, and so is a
    brand-new channel that happens to be common elsewhere.
    """

    name = "rarity"
    min_observations = 1
    requires_baseline = True

    def applies_to(self, series: Series, ctx: Context) -> bool:
        if not super().applies_to(series, ctx):
            return False
        # A store with no history answers "never seen, prevalence zero" to
        # every query, which scores as maximally rare. Declining is correct;
        # scoring would gate nothing and surface everything.
        return getattr(ctx.baseline, "available", False)

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        store = ctx.baseline
        if store is None:
            return None

        channel = series.channel
        # History is asked of the full key (this host, this destination);
        # prevalence of the profile key (this destination, by anyone). See
        # Channel.profile_key for why conflating them breaks rarity.
        first_seen = store.first_seen(channel)
        prevalence = store.prevalence(channel)
        global_count = store.observation_count(channel)

        notes = []
        if first_seen is None:
            age = 0.0
            recency = 1.0
            notes.append("first observation of this channel")
        else:
            age = max(0.0, ctx.now - first_seen)
            horizon = float(ctx.tunable("rarity.recency_horizon_s", 7 * 86400))
            recency = clamp(1.0 - age / horizon) if horizon > 0 else 0.0

        uncommonness = clamp(1.0 - prevalence)

        w_prev = float(ctx.tunable("rarity.weight_uncommonness", 0.6))
        score = w_prev * uncommonness + (1.0 - w_prev) * recency

        return self._result(
            score=score,
            features={
                "age_s": age,
                "recency": recency,
                "prevalence": prevalence,
                "uncommonness": uncommonness,
                # NOVELTY, separate from the blended score and from recency.
                #
                # Neither of the other two can answer "has this exact channel
                # ever been seen before". `prevalence` deliberately drops the
                # initiator (see Channel.profile_key), so a NEW SOURCE
                # reaching a known destination scores as common — on a Modbus
                # network with one master, "something talks to this PLC" is
                # 100% prevalent and a second master is invisible to it.
                # `recency` is measured against a multi-day horizon, so
                # inside one capture a channel first seen on the previous run
                # and one seen for the first time both score ~1.0.
                #
                # This is the exact signal for "first contact", and it is
                # what the ICS rules gate on.
                "novel": 1.0 if global_count == 0 else 0.0,
                "historical_observations": float(global_count),
            },
            sample_size=series.count,
            method="prevalence-recency-blend",
            notes=tuple(notes),
        )


class Entropy(Primitive):
    """How compressible is the payload?

    APPLICABILITY IS THE WHOLE POINT HERE. Shannon entropy over TLS
    ciphertext is ~8 bits/byte by construction. Reporting that as a finding
    reports that encryption works, and a tool that does it loses credibility
    with the first analyst who reads the output. So this primitive runs only
    where the answer can be informative:

      - channels the parser marked cleartext, where high entropy means
        something is encrypted or compressed inside a protocol that should
        not carry it (tunnelling, DNS TXT exfil, encoded payload in an HTTP
        body)
      - assisted mode, where operator-supplied keys have yielded real
        plaintext

    `score` is normalised entropy (bits per byte / 8), so it reads directly
    as "how random does this look".
    """

    name = "entropy"
    min_observations = 1
    requires_fields = ("payload",)

    def applies_to(self, series: Series, ctx: Context) -> bool:
        if not super().applies_to(series, ctx):
            return False
        # Refuse to measure entropy on a channel the parser knows is
        # encrypted, unless keys gave us the plaintext underneath.
        encrypted = any(o.attrs.get("encrypted") for o in series)
        return (not encrypted) or ctx.mode == "assisted"

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        blob = b"".join(o.payload for o in series if o.payload)
        if not blob:
            return None

        counts = Counter(blob)
        n = len(blob)
        bits = -sum((c / n) * math.log2(c / n) for c in counts.values())

        return self._result(
            score=clamp(bits / 8.0),
            features={
                "bits_per_byte": bits,
                "sampled_bytes": float(n),
                "distinct_bytes": float(len(counts)),
            },
            sample_size=series.count,
            method="shannon",
            notes=("measured on cleartext only; see applies_to",),
        )


class SequenceOrder(Primitive):
    """Does the exchange order violate the protocol's grammar?

    The least universal of the eight, because the grammar comes from
    somewhere else — the ontology supplies it per domain. The *mechanism* is
    generic: a set of permitted (previous_kind, next_kind) transitions, and
    the score is the observed violation rate.

    This is where domains with a real specification pay off. Modbus
    request/response pairing, a TLS handshake ordering, MAVLink heartbeat
    presence, and CAN frame-id scheduling are all expressible as permitted
    transitions, and a violation in a specified protocol is a far stronger
    signal than a statistical outlier in general-purpose traffic.
    """

    name = "sequence"
    min_observations = 3

    def __init__(self, allowed: FrozenSet[Tuple[str, str]], grammar_id: str = ""):
        self.allowed = allowed
        self.grammar_id = grammar_id

    def applies_to(self, series: Series, ctx: Context) -> bool:
        if not super().applies_to(series, ctx):
            return False
        # AN EMPTY GRAMMAR PERMITS NOTHING, so every transition counts as a
        # violation and the score pins at 1.0 on perfectly valid traffic.
        # The modbus stack shipped with `allowed=frozenset()` as a
        # placeholder; it was inert only because no rule referenced it, and
        # would have fired on everything the moment one did. Declining is
        # the correct reading of "no grammar configured".
        return bool(self.allowed)

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        kinds = [o.kind for o in series]
        transitions = list(zip(kinds, kinds[1:]))
        if not transitions:
            return None

        violations = [t for t in transitions if t not in self.allowed]
        rate = len(violations) / len(transitions)

        offending = Counter(f"{a}->{b}" for a, b in violations)

        return self._result(
            score=clamp(rate),
            features={
                "violation_rate": rate,
                "violations": float(len(violations)),
                "transitions": float(len(transitions)),
            },
            sample_size=len(transitions),
            method=f"transition-grammar/{self.grammar_id or 'unnamed'}",
            notes=tuple(f"{k} x{v}" for k, v in offending.most_common(3)),
        )


class FailureRate(Primitive):
    """What share of the answered exchanges came back as a failure?

    WHY THIS EXISTS. Running the narrator against twenty minutes of real
    browsing surfaced 11,859 NXDOMAIN responses against 1,338 NOERROR — 90%
    of every answered DNS query in the capture failed — and no primitive
    could see it, because the parser was discarding the response code and
    nothing measured outcome at all. A failure rate is not DNS-specific:

        DNS resolution failure   attr "rcode_name", failure {"NXDOMAIN", ...}
        HTTP error rate          attr "status",     failure 4xx/5xx
        Modbus exception rate    attr "exception",  failure any present

    so it lands here as a generic statistic rather than in a DNS inspector.

    THE DENOMINATOR IS THE SUBTLE PART. It is the observations that carry
    `attr` at all — i.e. the ones that were *answered* — not every
    observation in the series. Counting unanswered requests as successes
    would make a channel look healthier the more of it went missing, which
    is backwards: silence is a different signal (see `Asymmetry`) and must
    not dilute this one.

    THE SCORE IS A LOWER BOUND, NOT THE OBSERVED SHARE. Two failures out of
    two is a 100% observed failure rate and means nothing; a hundred out of
    a hundred means a great deal. Scoring the raw share would rank them
    identically and hand the loudest findings to the thinnest evidence. So
    the score is the Wilson 95% lower bound on the true rate, which reads as
    "the rate I am confident is at least this high" — 2/2 scores 0.34, while
    100/100 scores 0.96. This is the same discipline that caps measured
    entropy at log2(n): a claim whose truth depends on sample size is not
    allowed to be stated as though it did not.

    A high score says resolution is failing, and nothing about why. Benign
    causes (a mistyped DNS search suffix, decommissioned infrastructure) are
    at least as common as hostile ones (DGA lookups hunting for a live
    rendezvous, a dead C2). Which is why this is evidence to be joined to
    other evidence, never a verdict on its own.
    """

    name = "failure_rate"
    min_observations = 2

    #: Wilson bound z for a 95% one-sided interval.
    Z = 1.96

    def __init__(
        self,
        attr: str,
        failure_values: FrozenSet[str] = frozenset(),
        success_values: FrozenSet[str] = frozenset(),
        failure_when_present: bool = False,
        label: Optional[str] = None,
    ):
        self.attr = attr
        self.failure_values = frozenset(failure_values)
        #: Alternative to enumerating failures: anything answered that is
        #: not a listed success counts as one. Preferred where the failure
        #: set is open-ended — DNS has 16 assigned rcodes and room for more,
        #: and a rcode this build has never heard of is certainly not a
        #: successful resolution, so listing the one success is both shorter
        #: and correct as the protocol grows.
        self.success_values = frozenset(success_values)
        #: When set, *any* value of `attr` counts as a failure and the
        #: denominator is the whole series. Suits protocols that carry an
        #: error field only on errors (Modbus exceptions) rather than an
        #: outcome field on every reply.
        self.failure_when_present = failure_when_present
        if label:
            self.name = label

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        if self.failure_when_present:
            answered = list(series)
            failures = [o for o in answered if o.attrs.get(self.attr)]
        else:
            answered = [o for o in series if o.attrs.get(self.attr)]
            if self.success_values:
                failures = [
                    o for o in answered
                    if str(o.attrs.get(self.attr)) not in self.success_values
                ]
            else:
                failures = [
                    o for o in answered
                    if str(o.attrs.get(self.attr)) in self.failure_values
                ]

        # No answers means no opinion. Returning a zero here would assert
        # "nothing failed" about a channel we never saw a reply on.
        if not answered:
            return None

        n = len(answered)
        failed = len(failures)
        share = failed / n

        breakdown = Counter(str(o.attrs.get(self.attr)) for o in answered)

        return self._result(
            score=clamp(_wilson_lower(failed, n, self.Z)),
            features={
                "failure_share": share,
                "failures": float(failed),
                "answered": float(n),
                "distinct_outcomes": float(len(breakdown)),
            },
            sample_size=n,
            method=f"wilson-lower-95/{self.attr}",
            notes=tuple(
                f"{value} x{count}" for value, count in breakdown.most_common(4)
            ),
        )


def _wilson_lower(successes: int, n: int, z: float) -> float:
    """Wilson score interval, lower bound. Returns 0.0 for an empty sample.

    Used instead of the raw proportion so that a rate measured from a
    handful of samples cannot outrank the same rate measured from hundreds.
    """
    if n <= 0:
        return 0.0
    p = successes / n
    denom = 1.0 + (z * z) / n
    centre = p + (z * z) / (2 * n)
    margin = z * math.sqrt(max(0.0, p * (1 - p) / n + (z * z) / (4 * n * n)))
    return max(0.0, (centre - margin) / denom)
