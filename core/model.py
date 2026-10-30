"""tid-semantiQ core data model.

Everything above the capture plugins speaks only this vocabulary. A capture
plugin's job is to turn frames, records, or bus traffic into `Observation`s;
once it has, no layer above it knows or cares which domain the data came from.

The five types, in dependency order:

    Entity       a thing that emits or receives  (IP, MAC, CAN node, sysid)
    Channel      a named conversation between entities, at some granularity
    Observation  one discrete exchange on a channel, at a point in time
    Series       all observations on one channel, time-ordered  -> primitives eat this
    Evidence     what the primitives computed  -> scorer eats this

Two invariants hold this design together. Both are load-bearing; breaking
either collapses the abstraction that makes domain #4 cost a weekend:

  (1) Primitives consume `Series` and nothing else. They never see a frame, a
      socket, a parser, or a config file. A primitive that needs more context
      receives it through `Context`, explicitly.

  (2) `Finding.confidence` is computed by the scorer from `Evidence`. The
      explanation layer receives a finished Finding and may only produce a
      `Narrative`. There is deliberately no code path by which a language
      model can write a score, a severity, or a verdict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any, Dict, Iterator, List, Mapping, Optional, Protocol, Sequence, Tuple,
)

__all__ = [
    "Direction",
    "Severity",
    "Entity",
    "Channel",
    "Locus",
    "Observation",
    "Series",
    "PrimitiveResult",
    "Evidence",
    "Finding",
    "Narrative",
    "BaselineStore",
    "Context",
]


# --------------------------------------------------------------------------
# enums
# --------------------------------------------------------------------------


class Direction(str, Enum):
    """Direction relative to the channel's initiator, not to the observer.

    Defining it this way keeps the meaning stable across domains that have no
    client/server notion. A CAN frame or a BLE advertisement has no pair
    semantics at all and is BROADCAST.
    """

    EGRESS = "egress"        # initiator -> responder
    INGRESS = "ingress"      # responder -> initiator
    BROADCAST = "broadcast"  # no pair semantics


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_ORDER[severity]


# --------------------------------------------------------------------------
# entity / channel
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Entity:
    """Something that emits or receives on a channel.

    `kind` names the identifier space so that two domains can never collide:
    "ip", "mac", "can_node", "mavlink_sysid", "modbus_unit", "rpc_peer",
    "wallet". `value` is the canonical string form within that space.

    `labels` carries enrichment added after capture — hostname, owning
    process (joined from the SOC's endpoint collector), ASN, geo, threat-intel
    verdict. Labels never participate in identity: the same IP with and
    without a resolved process name is one entity.
    """

    kind: str
    value: str
    labels: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    def labelled(self, **new_labels: Any) -> "Entity":
        merged = dict(self.labels)
        merged.update(new_labels)
        return Entity(kind=self.kind, value=self.value, labels=merged)

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.key


@dataclass(frozen=True)
class Channel:
    """A conversation, at the granularity the domain makes meaningful.

    `dims` is the identity tuple — the fields whose combination defines "the
    same channel". It is domain-defined but uniformly shaped, so grouping,
    hashing, and baseline lookup are written once:

        net      {"proto": "tcp", "dport": "443", "sni": "cdn.example"}
        dns      {"proto": "udp", "qtype": "TXT", "zone": "example.com"}
        modbus   {"unit": "3", "fn": "3"}
        mavlink  {"sysid": "1", "compid": "1", "msgid": "0"}
        can      {"bus": "can0", "frame_id": "0x1A0"}
        ble      {"adv_type": "ADV_IND"}

    Choosing `dims` is the single most consequential decision when adding a
    domain: too coarse and distinct behaviours average into noise, too fine
    and no channel ever accumulates enough observations to score.

    `initiator`/`responder` are Optional because broadcast domains have one
    endpoint or none.
    """

    domain: str
    dims: Mapping[str, str] = field(default_factory=dict)
    initiator: Optional[Entity] = None
    responder: Optional[Entity] = None

    @property
    def key(self) -> str:
        """Stable identity string. Safe as a dict key, a DB key, and a
        cross-run baseline key — it must not change between versions for the
        same logical channel, so dims are sorted and rendered canonically."""
        parts = [
            self.domain,
            self.initiator.key if self.initiator else "-",
            self.responder.key if self.responder else "-",
            ",".join(f"{k}={self.dims[k]}" for k in sorted(self.dims)),
        ]
        return "|".join(parts)

    @property
    def profile_key(self) -> str:
        """Identity with the INITIATOR REMOVED — "this destination, reached
        this way, by anyone".

        Needed because `key` includes the initiator, which makes it unique to
        one host by construction. Asking "how much of the estate uses this
        channel?" against `key` therefore always answers "one host", and
        `rarity` would score every channel as maximally rare and become
        useless. Prevalence must be asked of the profile; history (first-seen,
        counts) is asked of the full key.
        """
        parts = [
            self.domain,
            self.responder.key if self.responder else "-",
            ",".join(f"{k}={self.dims[k]}" for k in sorted(self.dims)),
        ]
        return "|".join(parts)

    @property
    def fingerprint(self) -> str:
        """Short stable hash of `key`, for log lines and finding ids."""
        return hashlib.sha256(self.key.encode()).hexdigest()[:12]

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.key


# --------------------------------------------------------------------------
# observation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Locus:
    """Where an observation came from, so every finding can point back at the
    bytes that produced it.

    This is what makes `--out wireshark` and `--out pcapng` possible, and it
    is why it lives in the core model rather than in a plugin: a finding the
    analyst cannot open in Wireshark is a finding they cannot act on.
    """

    source: str                            # "capture.pcap", "can0", "session.har"
    frames: Tuple[int, ...] = ()           # 1-indexed frame numbers, as Wireshark counts
    stream: Optional[int] = None           # tcp.stream / udp.stream index when applicable
    #: What `frames` and `stream` MEAN. Only "pcap" indices are addressable
    #: by a Wireshark display filter.
    #:
    #: A HAR has entries, not frames. Numbering them 1..n and emitting
    #: `frame.number == 4` would produce a filter that looks right, opens a
    #: capture, and highlights an unrelated packet — the worst kind of wrong,
    #: because the analyst trusts it. So non-pcap sources decline to produce
    #: a filter and give a human reference instead.
    kind: str = "pcap"
    #: Human label for non-pcap loci: "entry 4", "frame 12 of hci0".
    label: str = ""

    def display_filter(self) -> Optional[str]:
        """The Wireshark display filter that selects this locus, if one can
        exist. None for sources Wireshark cannot address."""
        if self.kind != "pcap":
            return None
        if self.stream is not None:
            return f"tcp.stream eq {self.stream}"
        if self.frames:
            return _frame_set_filter(self.frames)
        return None

    def reference(self) -> str:
        """Where to look, in whatever terms the source understands."""
        filt = self.display_filter()
        if filt:
            return filt
        if self.label:
            return f"{self.source}: {self.label}"
        if self.frames:
            return f"{self.source}: entry {self.frames[0]}"
        return self.source


#: Frames to name before truncating a filter. A DNS channel can span hundreds
#: of frames, and a filter built by or-ing them all is thousands of characters
#: long — too wide for a terminal and awkward to paste. Set membership keeps
#: it compact; the cap keeps it usable.
MAX_FILTER_FRAMES = 40


def _frame_set_filter(frames: Sequence[int]) -> Optional[str]:
    """`frame.number in {1,2,3}` rather than a chain of `==` clauses.

    Truncation is announced inline rather than silent: a filter that quietly
    selects a third of the evidence would have the analyst conclude the
    finding was smaller than it is.
    """
    unique = sorted(set(frames))
    if not unique:
        return None
    if len(unique) == 1:
        return f"frame.number == {unique[0]}"
    if len(unique) <= MAX_FILTER_FRAMES:
        return "frame.number in {" + ",".join(map(str, unique)) + "}"
    shown = unique[:MAX_FILTER_FRAMES]
    return (
        "frame.number in {" + ",".join(map(str, shown)) + "}"
        f"  # first {MAX_FILTER_FRAMES} of {len(unique)} frames"
    )


@dataclass(frozen=True)
class Observation:
    """One discrete exchange on a channel, at a point in time.

    GRANULARITY — the rule that makes this work across domains:

        An Observation is the domain's smallest *meaningful exchange*, not a
        packet and not a connection.

    For datagram and frame domains the frame is the exchange: one CAN frame,
    one BLE advertisement, one DNS query, one MAVLink message.

    For stream domains (TCP, TLS, QUIC) the exchange is an *application-data
    burst*: a maximal run of same-direction payload with no direction change
    and no internal gap larger than `burst_gap` (see capture.base). This
    choice is deliberate and it is the reason this model can see modern C2
    that connection-level tooling misses:

        - a reconnect beacon (new TCP connection every 60s) yields one burst
          per connection, 60s apart
        - a websocket or HTTP/2 implant heartbeating inside ONE long-lived
          connection yields one burst per heartbeat, also 60s apart

      Both collapse to the same `Series`, so the periodicity primitive catches
      both without knowing they differ. A conn.log-shaped model sees the first
      and is blind to the second.

    `size` is application-layer payload bytes where the parser can determine
    them, and frame bytes otherwise; `wire_size` is always on-the-wire bytes.
    Primitives that care about the difference must check `size_is_payload`.

    `payload` is populated only in assisted mode (operator-supplied TLS keys,
    or natively cleartext traffic) and is never retained by default — see
    Context.retain_payloads.
    """

    ts: float                                  # epoch seconds, capture precision
    channel: Channel
    direction: Direction
    size: int                                  # see note above
    kind: str                                  # "tcp_burst", "dns_query", "can_frame"
    wire_size: Optional[int] = None
    size_is_payload: bool = True
    attrs: Mapping[str, Any] = field(default_factory=dict)
    payload: Optional[bytes] = field(default=None, repr=False)
    locus: Optional[Locus] = None

    def redacted(self) -> "Observation":
        """Drop payload bytes. Called before anything leaves the process."""
        if self.payload is None:
            return self
        return Observation(
            ts=self.ts,
            channel=self.channel,
            direction=self.direction,
            size=self.size,
            kind=self.kind,
            wire_size=self.wire_size,
            size_is_payload=self.size_is_payload,
            attrs=self.attrs,
            payload=None,
            locus=self.locus,
        )


# --------------------------------------------------------------------------
# series — the primitive input
# --------------------------------------------------------------------------


class Series:
    """All observations on one channel, time-ordered.

    This is the *only* thing a primitive is given. It owns the derived views
    primitives need — intervals, sizes, per-direction byte counts — so that
    eight primitives do not each re-implement them subtly differently.

    Construction sorts by timestamp. Observations are otherwise immutable, so
    a Series is safe to hand to several primitives concurrently.
    """

    __slots__ = ("channel", "observations", "_intervals")

    def __init__(self, channel: Channel, observations: Sequence[Observation]):
        self.channel = channel
        self.observations: Tuple[Observation, ...] = tuple(
            sorted(observations, key=lambda o: o.ts)
        )
        self._intervals: Optional[Tuple[float, ...]] = None

    # -- basics ------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.observations)

    def __iter__(self) -> Iterator[Observation]:
        return iter(self.observations)

    @property
    def count(self) -> int:
        return len(self.observations)

    @property
    def start(self) -> Optional[float]:
        return self.observations[0].ts if self.observations else None

    @property
    def end(self) -> Optional[float]:
        return self.observations[-1].ts if self.observations else None

    @property
    def duration(self) -> float:
        if len(self.observations) < 2:
            return 0.0
        return self.observations[-1].ts - self.observations[0].ts

    # -- derived views -----------------------------------------------------

    def timestamps(self) -> Tuple[float, ...]:
        return tuple(o.ts for o in self.observations)

    def intervals(self) -> Tuple[float, ...]:
        """Inter-arrival times between consecutive observations.

        Note this is over ALL directions. A primitive that wants one side only
        should call `filter(direction=...)` first — for beacon timing that is
        usually EGRESS, since the callback cadence is set by the client.
        """
        if self._intervals is None:
            ts = self.timestamps()
            self._intervals = tuple(
                ts[i] - ts[i - 1] for i in range(1, len(ts))
            )
        return self._intervals

    def sizes(self) -> Tuple[int, ...]:
        return tuple(o.size for o in self.observations)

    def bytes_in_direction(self, direction: Direction) -> int:
        return sum(o.size for o in self.observations if o.direction is direction)

    @property
    def bytes_egress(self) -> int:
        return self.bytes_in_direction(Direction.EGRESS)

    @property
    def bytes_ingress(self) -> int:
        return self.bytes_in_direction(Direction.INGRESS)

    def filter(self, direction: Optional[Direction] = None,
               kind: Optional[str] = None) -> "Series":
        """A narrowed Series on the same channel. Cheap; shares Observations."""
        picked = [
            o for o in self.observations
            if (direction is None or o.direction is direction)
            and (kind is None or o.kind == kind)
        ]
        return Series(self.channel, picked)

    def group_by(self, key) -> "Dict[str, Series]":
        """Sub-series of this channel, keyed by an attribute or a key function.

        `key` is either an `attrs` name or a callable taking an `Observation`
        and returning a group label (or None to exclude it).

        WHY THIS EXISTS, rather than finer `Channel.dims`. Some analyses need
        one endpoint at a time — response-time differentials, per-endpoint
        size distributions — while the channel must stay at host grain for
        everything else. Measured: moving http `dims` to endpoint grain turned
        2 findings into 24 on a twelve-endpoint fixture, because each endpoint
        became its own channel and one systemic defect was reported once per
        endpoint. See docs/ADR-001-endpoint-grain.md.

        So `dims` sets the COARSEST grain, at which findings are attributed,
        and this sets a finer grain for a specific question inside it. It is
        the same move `filter()` already makes, generalised: both narrow a
        channel without redefining it, and both return `Series`, so invariant
        I1 holds — a primitive still consumes a `Series` and nothing else.

        Observations whose key is missing or None are EXCLUDED, not collected
        under a null group. A missing key means the question does not apply to
        that observation, and grouping them together would invent a cohort out
        of unrelated messages.

        Groups preserve first-seen order, and each shares this channel, so a
        finding derived from one still attributes to the host.
        """
        getter = (
            key if callable(key)
            else (lambda obs: obs.attrs.get(key))  # type: ignore[arg-type]
        )
        buckets: Dict[str, List[Observation]] = {}
        for obs in self.observations:
            label = getter(obs)
            if label is None or label == "":
                continue
            buckets.setdefault(str(label), []).append(obs)
        return {
            label: Series(self.channel, group)
            for label, group in buckets.items()
        }

    def loci(self) -> Tuple[Locus, ...]:
        return tuple(o.locus for o in self.observations if o.locus is not None)

    def display_filter(self) -> Optional[str]:
        """One Wireshark filter covering every observation in the series.

        Only pcap-derived loci count. A HAR's entry indices are not frame
        numbers, and emitting `frame.number == 4` for one would produce a
        filter that opens a capture and highlights the wrong packet.
        """
        pcap_loci = [l for l in self.loci() if l.kind == "pcap"]
        if not pcap_loci:
            return None
        streams = sorted({l.stream for l in pcap_loci if l.stream is not None})
        if streams:
            if len(streams) == 1:
                return f"tcp.stream eq {streams[0]}"
            return "tcp.stream in {" + ",".join(map(str, streams)) + "}"
        frames = [n for l in pcap_loci for n in l.frames]
        return _frame_set_filter(frames)

    def reference(self) -> Optional[str]:
        """Where to look, in whatever terms the source understands."""
        filt = self.display_filter()
        if filt:
            return filt
        loci = self.loci()
        if not loci:
            return None
        labels = []
        for locus in loci[:6]:
            ref = locus.reference()
            if ref not in labels:
                labels.append(ref)
        more = f" (+{len(loci) - 6} more)" if len(loci) > 6 else ""
        return ", ".join(labels) + more

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"<Series {self.channel.fingerprint} n={self.count} dur={self.duration:.1f}s>"


# --------------------------------------------------------------------------
# evidence / findings
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PrimitiveResult:
    """What one primitive computed about one Series.

    `score` is a normalised 0..1 strength for THIS primitive's own question
    ("how periodic is this?"), never an overall suspicion. Combining scores
    into suspicion is the scorer's job and the ontology's decision.

    `features` are the named numbers the narrator is allowed to cite. Keep
    them human-meaningful and unit-suffixed (`period_s`, `jitter_ratio`,
    `egress_bytes`) — these strings appear verbatim in analyst-facing output.

    `method` records which estimator produced the result, so a series scored
    by MAD and one scored spectrally are distinguishable after the fact.
    """

    name: str
    score: float
    features: Mapping[str, float]
    sample_size: int
    method: str = ""
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"{self.name}: score {self.score!r} outside 0..1")


@dataclass(frozen=True)
class InspectionResult:
    """What one inspector found in the messages on a channel.

    Sibling of `PrimitiveResult`, deliberately structurally compatible with
    it — same `name`, `score` and `features` — so the rule engine's
    `Condition` works against either without knowing which it has.

    The difference is `facts`: inspections produce STRING evidence (a cookie
    name, a JWT algorithm, the parameter a token appeared in) where
    primitives produce numbers. That is also why redaction exists — `facts`
    is where secrets live, and it is the only field a redactor has to touch.

    `occurrences` and `loci` come from folding: a cookie missing `Secure`
    appears on every response that sets it, and emitting one finding per
    message would bury a real capture under hundreds of duplicates. Folding
    keeps the worst score, counts the repeats, and retains a bounded sample
    of places to look.
    """

    name: str
    score: float
    facts: Mapping[str, str] = field(default_factory=dict)
    #: Keys in `facts` whose values are credentials and must be masked on
    #: output. DECLARED BY THE INSPECTOR, which is the only layer that knows.
    #:
    #: The first implementation had the redactor guess from key names against
    #: a deny-list, and it masked `cookie.domain`, `cookie.path` ("/") and
    #: `jwt.issues` — the actual findings — because every one contains a
    #: substring like "cookie" or "key". Guessing destroys the report while
    #: still missing any key nobody thought of. Declaring is precise, and
    #: `looks_secret()` remains as a backstop for an inspector that forgets.
    secret_facts: Tuple[str, ...] = ()
    features: Mapping[str, float] = field(default_factory=dict)
    occurrences: int = 1
    loci: Tuple["Locus", ...] = ()
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"{self.name}: score {self.score!r} outside 0..1")

    def display_filter(self) -> Optional[str]:
        pcap_loci = [l for l in self.loci if l.kind == "pcap"]
        if not pcap_loci:
            return None
        streams = sorted({l.stream for l in pcap_loci if l.stream is not None})
        if streams:
            if len(streams) == 1:
                return f"tcp.stream eq {streams[0]}"
            return "tcp.stream in {" + ",".join(map(str, streams)) + "}"
        return _frame_set_filter([n for l in pcap_loci for n in l.frames])

    def reference(self) -> Optional[str]:
        """Where to look, whatever the source is."""
        filt = self.display_filter()
        if filt:
            return filt
        labels = []
        for locus in self.loci[:4]:
            ref = locus.reference()
            if ref not in labels:
                labels.append(ref)
        return ", ".join(labels) or None


@dataclass(frozen=True)
class Evidence:
    """Everything known about one channel after analysis.

    Two kinds of evidence, because two kinds of question are being asked:

        results      primitives — how does this channel BEHAVE over time?
        inspections  inspectors — what is wrong with the MESSAGES on it?

    Behavioural analysis is statistics over a Series; content analysis is a
    per-message fact. Forcing the second through the primitive interface
    would have meant pretending a cookie flag is a statistic, so they stay
    separate types and share everything downstream — scorer, frozen
    `Finding`, citation-verified `Narrative`, and every output sink.

    This is the complete input to the scorer, and — once a Finding exists —
    the complete input to the narrator. Nothing else is in scope for either.
    """

    channel: Channel
    series_count: int
    window: Tuple[float, float]
    results: Tuple[PrimitiveResult, ...]
    inspections: Tuple[InspectionResult, ...] = ()

    def by_name(self, name: str):
        """Look up either kind by name.

        Searching both is what lets one `Condition` express a threshold over
        a primitive or an inspection interchangeably, so the rule format did
        not have to grow a second syntax.
        """
        for r in self.results:
            if r.name == name:
                return r
        for i in self.inspections:
            if i.name == name:
                return i
        return None

    def score_of(self, name: str, default: float = 0.0) -> float:
        r = self.by_name(name)
        return r.score if r else default

    def feature(self, primitive: str, feature: str,
                default: Optional[float] = None) -> Optional[float]:
        r = self.by_name(primitive)
        if r is None:
            return default
        return r.features.get(feature, default)

    def to_ledger(self, redactor=None) -> Mapping[str, Any]:
        """The evidence ledger: a flat, JSON-serialisable record of every
        computed number. This is what `--out json` writes and what the
        narrator receives.

        `redactor` is applied to inspection `facts` on the way out. It is
        applied HERE, at serialisation, rather than at capture — inspectors
        need the real value to analyse a token, and only the written output
        needs it masked. Without this, `findings.json` is a credential file:
        live session cookies, bearer tokens and API keys, pasted into a bug
        report by whoever reads it next.
        """
        return {
            "channel": self.channel.key,
            "channel_id": self.channel.fingerprint,
            "domain": self.channel.domain,
            "observations": self.series_count,
            "window": {"start": self.window[0], "end": self.window[1]},
            "primitives": [
                {
                    "name": r.name,
                    "score": round(r.score, 4),
                    "method": r.method,
                    "sample_size": r.sample_size,
                    "features": {k: v for k, v in r.features.items()},
                    "notes": list(r.notes),
                }
                for r in self.results
            ],
            "inspections": [
                {
                    "name": i.name,
                    "score": round(i.score, 4),
                    "occurrences": i.occurrences,
                    "facts": (
                        redactor(i.facts, i.secret_facts)
                        if redactor else dict(i.facts)
                    ),
                    "features": {k: v for k, v in i.features.items()},
                    "display_filter": i.display_filter(),
                    "notes": list(i.notes),
                }
                for i in self.inspections
            ],
        }


@dataclass(frozen=True)
class Finding:
    """A named conclusion about a channel, produced by the scorer from an
    ontology rule plus Evidence.

    Frozen on purpose. `confidence` and `severity` are computed; there is no
    setter and no code path from the narrator back into this object.
    """

    rule_id: str                        # "net.beacon.periodic_callback"
    title: str
    channel: Channel
    severity: Severity
    confidence: float                   # 0..1, computed in core/score.py
    evidence: Evidence
    refs: Tuple[str, ...] = ()          # "attack:T1071.001", "cwe:598"
    display_filter: Optional[str] = None
    #: Where to look when `display_filter` is None — a HAR entry number, a
    #: bus frame index. Separate from the filter so a caller can never print
    #: a non-working Wireshark filter by mistake.
    reference: Optional[str] = None
    #: Evidence names the rule referenced (required, weighed or boosted).
    #: Needed because `Evidence` is per-CHANNEL while a finding is per-RULE:
    #: without it the report prints every inspection on the channel under
    #: every finding, so four findings on one host repeat the same three
    #: inspections twelve times and none of them is readable.
    cited: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"{self.rule_id}: confidence outside 0..1")

    @property
    def id(self) -> str:
        return f"{self.rule_id}:{self.channel.fingerprint}"

    def to_json(self, redactor=None) -> Mapping[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "refs": list(self.refs),
            "display_filter": self.display_filter,
            "reference": self.reference,
            "evidence": self.evidence.to_ledger(redactor=redactor),
        }


@dataclass(frozen=True)
class Narrative:
    """The one thing the language model is permitted to produce.

    It attaches to a Finding by id and carries prose only. `cited_features`
    exists so the narrator's claims can be checked against the ledger
    mechanically: every feature it names must exist in the Evidence, and a
    narrative citing a feature that was never computed is rejected rather
    than displayed. That check — not the prompt — is what keeps the
    explanation honest.
    """

    finding_id: str
    summary: str
    reasoning: str
    cited_features: Tuple[str, ...] = ()   # "periodicity.period_s"
    model: str = ""

    def verify_against(self, evidence: Evidence) -> Tuple[bool, Tuple[str, ...]]:
        """Return (ok, unknown_citations).

        SPLIT ON THE LAST DOT, not the first. Measurement names contain dots
        themselves — `fanout.qname`, `failure_rate.rcode`,
        `auth.cookie_security`, `web.timing_differential` — so partitioning
        on the first one read `failure_rate.rcode.failure_share` as the
        primitive `failure_rate` with a feature called `rcode.failure_share`,
        which exists nowhere.

        The effect was that every correctly-cited explanation of a
        dotted-name measurement was rejected, and dotted names are the
        majority: every inspector and every parameterised primitive has one.
        A verifier that rejects true statements is worse than no verifier,
        because it trains the reader to ignore it.
        """
        unknown = []
        for citation in self.cited_features:
            primitive, _, feature = citation.rpartition(".")
            if not primitive or evidence.feature(primitive, feature) is None:
                unknown.append(citation)
        return (not unknown, tuple(unknown))


# --------------------------------------------------------------------------
# context — what primitives are allowed to reach
# --------------------------------------------------------------------------


class BaselineStore(Protocol):
    """State the rarity/novelty primitive needs, and the only legitimate way
    for a primitive to learn anything beyond its own Series.

    Deliberately narrow. A primitive cannot query arbitrary history; it can
    ask how long a channel has been known, how often it occurs, and how much
    of the fleet exhibits it. Those three answers are what rarity scoring
    needs and they are cheap to serve from the SOC's Postgres or from a local
    SQLite file in standalone mode.

    Methods take a `Channel`, not a key string, so the store decides which
    identity each question is asked of: history against `Channel.key`,
    prevalence against `Channel.profile_key`. Passing a bare string made that
    distinction invisible at the call site and silently broke rarity.
    """

    #: False when the store holds no usable history. `Rarity` checks this and
    #: returns None rather than scoring, because a store that answers
    #: "never seen, prevalence zero" to every query is indistinguishable from
    #: one reporting that everything is maximally rare — which would turn the
    #: whole rarity-gated ruleset into a false-positive generator.
    available: bool

    def first_seen(self, channel: "Channel") -> Optional[float]: ...

    def observation_count(self, channel: "Channel") -> int: ...

    def prevalence(self, channel: "Channel") -> float:
        """Fraction of known initiators (0..1) that have ever used this
        channel profile. Low prevalence plus recent first_seen is the signal
        that separates a malicious beacon from the hundred legitimate ones on
        the network."""
        ...

    def record(self, series: "Series") -> None: ...


@dataclass
class Context:
    """Everything a primitive may use beyond its Series, passed explicitly.

    No primitive reads a global, an environment variable, or a config file.
    Anything a primitive needs arrives here, which is why primitives are
    trivially unit-testable with synthetic Series and no fixtures.
    """

    #: The reference instant for anything time-relative, chiefly
    #: `rarity.recency`.
    #:
    #: MUST be the capture's own end time when analysing a file, NOT
    #: wall-clock. A pcap recorded last year scored against `time.time()`
    #: makes every known channel look ancient, drives recency to zero, and
    #: collapses rarity onto prevalence alone — which happens to suppress
    #: findings, so the failure looks like the tool working. Live capture is
    #: the only case where wall-clock is correct.
    now: float
    baseline: Optional[BaselineStore] = None
    mode: str = "passive"                  # "passive" | "assisted"
    retain_payloads: bool = False
    config: Mapping[str, Any] = field(default_factory=dict)

    def tunable(self, name: str, default: Any) -> Any:
        """Primitive thresholds come from here so they are inspectable and
        overridable per deployment, the way the SOC's detection settings
        already are."""
        return self.config.get(name, default)
