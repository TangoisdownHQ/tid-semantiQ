"""The capture plugin interface, and the burst rule.

A capture plugin has one job: turn some source of traffic into an
`Observation` stream. It decides the channel `dims` for its domain, it names
the exchange `kind`, and it records a `Locus` so findings can point back at
the bytes. It does not score, does not threshold, and does not know what a
Finding is.

Adding a domain is therefore: implement `CaptureSource`, choose dims, pick a
primitive stack in `core/primitives/__init__.py`, and write ontology rules.
No new statistics.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import (
    Dict, Iterable, Iterator, List, Mapping, Optional, Tuple,
)

from core.model import Channel, Direction, Locus, Observation, Series

__all__ = ["CaptureSource", "BurstAssembler", "group_into_series"]


class CaptureSource(ABC):
    """A source of Observations.

    Implementations are generators, not batch readers, so live capture and
    pcap replay are the same code path to every layer above. A pcap source
    simply ends; a live source does not.
    """

    #: the domain string stamped onto every Channel this source produces;
    #: selects the primitive stack and the ontology ruleset
    domain: str = ""

    @abstractmethod
    def observations(self) -> Iterator[Observation]:
        """Yield Observations in capture order.

        Ordering need not be perfectly monotonic — `Series` sorts — but large
        reordering costs memory in windowing, so sources should stay close to
        time order.
        """
        raise NotImplementedError

    def close(self) -> None:
        """Release handles. Safe to call twice."""
        return None

    def __enter__(self) -> "CaptureSource":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------------------
# the burst rule
# --------------------------------------------------------------------------


@dataclass
class BurstAssembler:
    """Turns a packet stream into application-data bursts.

    THE RULE. A burst is a maximal run of same-direction application payload
    on one channel with no direction change and no internal gap larger than
    `gap_s`. Packets with no application payload (bare ACKs, window updates,
    keepalive probes) do not open or extend a burst.

    WHY THIS IS THE RIGHT UNIT. The two obvious alternatives both fail:

      per-packet     too fine. Segmentation, MTU, Nagle, and retransmits are
                     properties of the transport, not of the behaviour being
                     measured, and they inject timing noise that swamps the
                     cadence you are looking for.

      per-connection too coarse, and blind in exactly the modern case. A
                     reconnect beacon opens a connection per callback, so
                     connection records carry the cadence. A websocket or
                     HTTP/2 implant heartbeats *inside one long-lived
                     connection*, so connection records show a single
                     multi-hour flow and the cadence is gone. This is also
                     why the SOC's existing connection-polling detector is
                     inverted: a persistent connection is present at every
                     poll and reads as perfectly regular, while a short
                     60-second callback is almost never sampled at all.

    Bursts collapse both cases onto the same series. A 60-second reconnect
    beacon and a 60-second in-connection heartbeat produce identical
    inter-arrival times, and `Periodicity` catches both without knowing they
    differ.

    GAP TUNING. `gap_s` must be larger than a round of segmentation and
    smaller than the shortest cadence worth detecting. 50ms is a reasonable
    default on a LAN; raise it on high-latency or satellite links, where a
    single application message can span hundreds of milliseconds of wire
    time. Set it too low and one message fragments into several observations,
    manufacturing a fast false cadence — the most likely way to get this
    wrong.
    """

    gap_s: float = 0.050
    min_payload: int = 1

    #: open bursts, keyed by (channel key, direction)
    _open: Dict[Tuple[str, Direction], "_Burst"] = field(default_factory=dict, repr=False)

    def feed(
        self,
        ts: float,
        channel: Channel,
        direction: Direction,
        payload_len: int,
        wire_len: int,
        kind: str,
        source: str,
        frame: Optional[int] = None,
        stream: Optional[int] = None,
        payload: Optional[bytes] = None,
        **attrs,
    ) -> Optional[Observation]:
        """Feed one packet. Returns a completed Observation when this packet
        closes a burst, otherwise None. Call `flush()` at end of capture to
        drain the still-open ones.
        """
        if payload_len < self.min_payload:
            return None

        key = (channel.key, direction)
        completed: Optional[Observation] = None

        # A direction change on the same channel closes the opposite burst.
        other = (channel.key, _opposite(direction))
        if other in self._open:
            completed = self._open.pop(other).finish()

        current = self._open.get(key)
        if current is not None and ts - current.last_ts > self.gap_s:
            finished = current.finish()
            self._open.pop(key)
            current = None
            # At most one Observation can be returned per packet; the
            # direction-change case above is rarer, so prefer the gap close.
            completed = finished or completed

        if current is None:
            self._open[key] = _Burst(
                channel=channel,
                direction=direction,
                kind=kind,
                source=source,
                first_ts=ts,
                last_ts=ts,
                size=payload_len,
                wire_size=wire_len,
                frames=[frame] if frame is not None else [],
                stream=stream,
                payload=bytearray(payload) if payload else None,
                attrs=dict(attrs),
            )
        else:
            current.extend(ts, payload_len, wire_len, frame, payload, attrs)

        return completed

    def flush(self) -> List[Observation]:
        """Close every open burst. Call at end of capture, and periodically
        during live capture so long-idle channels do not pin memory."""
        out = [b.finish() for b in self._open.values()]
        self._open.clear()
        return [o for o in out if o is not None]


def _opposite(direction: Direction) -> Direction:
    if direction is Direction.EGRESS:
        return Direction.INGRESS
    if direction is Direction.INGRESS:
        return Direction.EGRESS
    return Direction.BROADCAST


@dataclass
class _Burst:
    channel: Channel
    direction: Direction
    kind: str
    source: str
    first_ts: float
    last_ts: float
    size: int
    wire_size: int
    frames: List[int]
    stream: Optional[int]
    payload: Optional[bytearray]
    attrs: dict

    def extend(self, ts, payload_len, wire_len, frame, payload, attrs) -> None:
        self.last_ts = ts
        self.size += payload_len
        self.wire_size += wire_len
        if frame is not None:
            self.frames.append(frame)
        if payload and self.payload is not None:
            self.payload.extend(payload)
        # First writer wins: a burst's identifying attributes (SNI, JA4,
        # qname) come from its opening packet and must not be overwritten by
        # continuation segments.
        for k, v in attrs.items():
            self.attrs.setdefault(k, v)

    def finish(self) -> Optional[Observation]:
        if self.size <= 0:
            return None
        return Observation(
            # The burst is timestamped at its FIRST packet. Cadence is set by
            # when a message starts, not when it finishes — timestamping at
            # the end would fold transfer duration into the interval series
            # and inflate apparent jitter on large messages.
            ts=self.first_ts,
            channel=self.channel,
            direction=self.direction,
            size=self.size,
            kind=self.kind,
            wire_size=self.wire_size,
            size_is_payload=True,
            attrs=dict(self.attrs, burst_duration_s=self.last_ts - self.first_ts),
            payload=bytes(self.payload) if self.payload is not None else None,
            locus=Locus(source=self.source, frames=tuple(self.frames), stream=self.stream),
        )


# --------------------------------------------------------------------------
# windowing
# --------------------------------------------------------------------------


def group_into_series(
    observations: Iterable[Observation],
    min_observations: int = 2,
    min_by_domain: Optional[Mapping[str, int]] = None,
) -> Iterator[Series]:
    """Group an Observation stream into one Series per channel.

    Batch form, for pcap. Live capture uses a sliding-window variant that
    emits and evicts on a timer; both produce `Series`, so nothing above
    this line changes between the two modes.

    `min_observations` prunes the long tail of one-shot channels. Measured on
    20 minutes of real browsing: 4,123 of 4,242 DNS channels held fewer than
    six observations, so 97% could never support a cadence finding while each
    still consumed a baseline row and a scoring pass.

    `min_by_domain` overrides the threshold per domain, and it is not
    optional nicety — the two kinds of domain need opposite answers:

        behaviour-only (net, dns)   a lone observation can say NOTHING, so
                                    pruning it is pure gain
        has inspectors (http,       a lone observation can BE the finding. One
        modbus, dnp3, mavlink)      injected MAVLink disarm is one message on
                                    its own channel, and pruning it would
                                    discard the most serious thing the tool
                                    detects

    The CLI derives the override from the inspector registry, so adding
    inspectors to a domain automatically stops its singletons being pruned.
    """
    buckets: Dict[str, List[Observation]] = {}
    channels: Dict[str, Channel] = {}
    for obs in observations:
        key = obs.channel.key
        buckets.setdefault(key, []).append(obs)
        channels.setdefault(key, obs.channel)

    overrides = dict(min_by_domain or {})
    for key, obs_list in buckets.items():
        channel = channels[key]
        threshold = overrides.get(channel.domain, min_observations)
        if len(obs_list) < threshold:
            continue
        yield Series(channel, obs_list)
