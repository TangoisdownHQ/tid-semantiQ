"""Sliding windows over an unbounded Observation stream.

`group_into_series` is the batch form: it buffers everything, groups by
channel, and yields. On a file that is correct and simple. On a live stream it
never returns and memory grows without bound.

This is the streaming form, and it produces the same `Series` — so every
primitive, inspector, correlator and rule works unchanged. That is the whole
reason the windowing lives here rather than inside the analysis.

EVENT TIME, NOT WALL CLOCK. Emission is driven by the timestamps in the
stream, not by `time.time()`. Two consequences, both wanted:

  - replaying a capture through the windower produces exactly the results a
    live run would have produced, which is the only way to test this
  - a stream that pauses does not emit empty windows, and a stream replayed
    faster than real time does not skip them

It is the same discipline as `Context.now`, and for the same reason: a
measurement that depends on when you looked is not a measurement.

WINDOWS SLIDE, THEY DO NOT TUMBLE. A channel is re-emitted every
`emit_every_s` carrying the last `window_s` of its observations, so an
analysis sees more evidence each time rather than a disjoint slice. A 60-second
beacon needs six callbacks before `Periodicity` will say anything; tumbling
windows short enough to be responsive would never accumulate them.

The cost is repetition: the same finding re-fires as the window slides. The
caller deduplicates — `Finding.id` is stable across emissions — and
`out.stream.FindingAggregator` does it by keeping the highest-confidence
instance.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from typing import Deque, Dict, Iterable, Iterator, List, Optional, Tuple

from core.model import Channel, Observation, Series

__all__ = ["SlidingWindower", "window_stream"]


class SlidingWindower:
    """Buffer an Observation stream and emit `Series` on an event-time clock.

    MEMORY IS A TOTAL BUDGET, not two independent caps. The first version had
    `max_channels=20_000` and `max_per_channel=10_000`, whose product is 200
    million observations — a bound so large it bounded nothing, while the
    per-channel cap bit hard on exactly the channels that mattered. Measured
    on a real capture: 273,000 of 300,000 observations were dropped, and on
    the busiest channel the buffer ended up covering 106 seconds of a
    requested 1200-second window. The cadence it then measured was of a
    period nobody asked for.

    So the primary bound is `max_observations` across all channels, and when
    it is exceeded a WHOLE CHANNEL is evicted rather than every channel being
    truncated. That choice is the point: truncating a channel silently
    corrupts its cadence measurement, whereas dropping one is honest, visible
    and reportable. `max_per_channel` remains only as a backstop against a
    single pathological channel consuming the entire budget.

    Every form of shedding is COUNTED and surfaced — a windower that
    discarded a flood quietly would make a quiet network out of a port scan.
    """

    def __init__(
        self,
        window_s: float = 300.0,
        emit_every_s: float = 60.0,
        min_observations: int = 2,
        max_channels: int = 20_000,
        max_observations: int = 400_000,
        max_per_channel: int = 200_000,
    ):
        if emit_every_s <= 0 or window_s <= 0:
            raise ValueError("window_s and emit_every_s must be positive")
        self.window_s = window_s
        self.emit_every_s = emit_every_s
        self.min_observations = min_observations
        self.max_channels = max_channels
        self.max_observations = max_observations
        self.max_per_channel = max_per_channel
        self._buffered = 0

        # Insertion-ordered so the least-recently-touched channel is cheap to
        # find when the channel cap is hit.
        self._buffers: "OrderedDict[str, Deque[Observation]]" = OrderedDict()
        self._channels: Dict[str, Channel] = {}
        # Cadence seen per channel across the WHOLE stream, not just the
        # current window — the point is to compare the window against what
        # the link actually carries, so eviction must not erase it.
        self._span: Dict[str, Tuple[float, float, int]] = {}
        self._mean_intervals: Dict[str, float] = {}
        # Narrowest effective window seen once the count cap bound.
        self._narrowest_span = float("inf")
        self._narrowest_channel = ""
        self._watermark: Optional[float] = None
        self._next_emit: Optional[float] = None

        self.stats = {
            "observations": 0,
            "windows": 0,
            "series_emitted": 0,
            "evicted_stale": 0,
            "evicted_overflow": 0,
            "dropped_per_channel": 0,
            "late": 0,
        }

    # -- feeding -----------------------------------------------------------

    def feed(self, obs: Observation) -> List[Series]:
        """Accept one observation, returning any Series its arrival completes.

        EAGER, not a generator. As a generator, acceptance only happened when
        the caller advanced the iterator — so `windower.feed(obs)` with the
        result discarded dropped the observation entirely and silently. One
        observation can also close several windows at once (a long gap jumps
        the watermark), so the return is a list rather than an optional.

        Flattens window boundaries away. Use `feed_windows` when the consumer
        needs them, which anything running correlators does.
        """
        self.stats["observations"] += 1
        return [series for batch in self._accept(obs) for series in batch]

    def _accept(self, obs: Observation) -> List[List[Series]]:
        key = obs.channel.key

        if self._watermark is None:
            self._watermark = obs.ts
            self._next_emit = obs.ts + self.emit_every_s
        elif obs.ts < self._watermark - self.window_s:
            # Older than anything still buffered. Counted rather than
            # silently dropped: a capture with badly reordered timestamps
            # should be visible as such, not as a thin result.
            self.stats["late"] += 1
            return []
        else:
            self._watermark = max(self._watermark, obs.ts)

        buffer = self._buffers.get(key)
        if buffer is None:
            if len(self._buffers) >= self.max_channels:
                self._evict_one_channel(protect=key)
            buffer = deque()
            self._buffers[key] = buffer
            self._channels[key] = obs.channel
        else:
            # Touch, so recency ordering stays meaningful for eviction.
            self._buffers.move_to_end(key)

        first, _last, count = self._span.get(key, (obs.ts, obs.ts, 0))
        self._span[key] = (first, obs.ts, count + 1)
        if count >= 1:
            self._mean_intervals[key] = (obs.ts - first) / count

        buffer.append(obs)
        self._buffered += 1

        # Budget first, and it evicts whole channels. A channel that loses
        # its oldest observations keeps reporting a cadence measured over a
        # window it no longer covers; a channel that is dropped reports
        # nothing, which is the truthful outcome.
        while self._buffered > self.max_observations and len(self._buffers) > 1:
            if not self._evict_one_channel(key):
                break

        if len(buffer) > self.max_per_channel:
            buffer.popleft()
            self._buffered -= 1
            self.stats["dropped_per_channel"] += 1
            # THE CONSEQUENCE THAT MATTERS, measured on a real capture: a
            # busy channel hits the count cap long before the time cutoff,
            # so the buffer stops covering `window_s` and starts covering
            # however many seconds the last `max_per_channel` observations
            # happen to span. The analysis then measures a window far
            # narrower than the one requested, and nothing in the output
            # would otherwise say so.
            span = buffer[-1].ts - buffer[0].ts
            if span < self._narrowest_span:
                self._narrowest_span = span
                self._narrowest_channel = key

        return self._emit_due()

    def feed_all(self, observations: Iterable[Observation]) -> Iterator[Series]:
        for obs in observations:
            yield from self.feed(obs)
        yield from self.flush()

    def feed_windows(
        self, observations: Iterable[Observation]
    ) -> Iterator[List[Series]]:
        """Yield one LIST per completed window, plus a final partial one.

        The batched form exists because correlators need a whole window at
        once: "this credential went to two hosts" cannot be answered one
        channel at a time. Scoring a window therefore has to see all of its
        series together, which `feed()` alone does not express.
        """
        for obs in observations:
            self.stats["observations"] += 1
            for batch in self._accept(obs):
                if batch:
                    yield batch
        final = list(self.flush())
        if final:
            yield final

    # -- emission ----------------------------------------------------------

    def _emit_due(self) -> List[List[Series]]:
        assert self._watermark is not None and self._next_emit is not None
        batches: List[List[Series]] = []
        while self._watermark >= self._next_emit:
            boundary = self._next_emit
            self._next_emit += self.emit_every_s
            self.stats["windows"] += 1
            batches.append(self._emit_window(boundary))
        return batches

    def _emit_window(self, boundary: float) -> List[Series]:
        """Every channel with enough recent observations, plus eviction.

        The cutoff is computed from the WINDOW BOUNDARY rather than from the
        current watermark, so a stream that races ahead between deadlines
        does not retroactively widen the window it already promised.
        """
        cutoff = boundary - self.window_s
        stale: List[str] = []
        out: List[Series] = []

        for key, buffer in self._buffers.items():
            while buffer and buffer[0].ts < cutoff:
                buffer.popleft()
                self._buffered -= 1
            if not buffer:
                stale.append(key)
                continue
            if len(buffer) < self.min_observations:
                continue
            self.stats["series_emitted"] += 1
            out.append(Series(self._channels[key], list(buffer)))

        for key in stale:
            dropped = self._buffers.pop(key, None)
            if dropped is not None:
                self._buffered -= len(dropped)
            self._channels.pop(key, None)
            self.stats["evicted_stale"] += 1

        return out

    def flush(self) -> Iterator[Series]:
        """Emit whatever is buffered. Call at end of stream.

        Without this the final partial window is lost, which on a short
        capture can be most of the evidence.
        """
        for key, buffer in list(self._buffers.items()):
            if len(buffer) < self.min_observations:
                continue
            self.stats["series_emitted"] += 1
            yield Series(self._channels[key], list(buffer))
        self._buffers.clear()
        self._channels.clear()
        self._buffered = 0

    # -- eviction ----------------------------------------------------------

    def _evict_one_channel(self, protect: Optional[str] = None) -> bool:
        """Drop the least-recently-touched channel. Returns False if none can.

        A port scan or a DNS flood creates channels faster than they age
        out, so this is what keeps memory bounded. It is counted, and
        `pressure()` reports it, because an operator reading a quiet result
        off a flooded link needs to know the tool was shedding load.

        `protect` is the channel currently being written, which must not be
        evicted — doing so would discard the observation that triggered the
        eviction and could loop.
        """
        for key in list(self._buffers.keys()):
            if key == protect:
                continue
            buffer = self._buffers.pop(key)
            self._buffered -= len(buffer)
            self._channels.pop(key, None)
            self.stats["evicted_overflow"] += 1
            return True
        return False

    # -- reporting ---------------------------------------------------------

    @property
    def watermark(self) -> Optional[float]:
        return self._watermark

    @property
    def active_channels(self) -> int:
        return len(self._buffers)

    @property
    def buffered_observations(self) -> int:
        return self._buffered

    def describe(self) -> str:
        return (
            "{observations} observations, {windows} windows, "
            "{series_emitted} series; evicted {evicted_stale} stale / "
            "{evicted_overflow} over cap, dropped {dropped_per_channel} "
            "over per-channel cap, {late} late".format(**self.stats)
        )

    #: Observations `Periodicity` needs before it will say anything. Mirrors
    #: `core.primitives.timing.Periodicity.min_observations`; duplicated as a
    #: constant rather than imported so `capture/` keeps no dependency on
    #: `core/primitives`.
    CADENCE_SAMPLES = 6

    def undersized_window(self) -> Optional[str]:
        """A warning when the window is too short to hold the cadences seen.

        THE FAILURE THIS CATCHES. `Periodicity` needs six observations, so a
        60-second beacon cannot be evidenced in a window shorter than about
        six minutes. Set the window below that and the analysis does not
        fail — it silently finds nothing, which reads as a clean link.

        Measured on the fixtures: a 54-second beacon over 40 callbacks is
        found in batch mode and MISSED at `--window 300`, because only five
        callbacks fit. The arithmetic is simple enough to just do, so the
        operator is told rather than left to infer it.
        """
        needed = 0.0
        culprit = ""
        for key, interval in self._mean_intervals.items():
            required = interval * self.CADENCE_SAMPLES
            if required > self.window_s and required > needed:
                needed, culprit = required, key
        if not culprit:
            return None
        return (
            f"--window {self.window_s:g}s is too short for the slowest cadence "
            f"observed: a channel averaging {needed / self.CADENCE_SAMPLES:.1f}s "
            f"between observations needs about {needed:.0f}s to show "
            f"{self.CADENCE_SAMPLES} of them. Periodicity findings on such "
            "channels are not weak — they are absent."
        )

    def pressure(self) -> Optional[str]:
        """A warning when the caps were reached, or None.

        Separate from `describe()` so the CLI can surface it as an advisory:
        dropped observations mean the analysis saw less than the link
        carried, and nothing else in the output would say so.
        """
        reasons = []
        if self.stats["evicted_overflow"]:
            reasons.append(
                f"{self.stats['evicted_overflow']} channel(s) evicted to stay "
                f"under the {self.max_channels} channel cap"
            )
        if self.stats["dropped_per_channel"]:
            detail = (
                f"{self.stats['dropped_per_channel']} observation(s) dropped "
                f"over the {self.max_per_channel} per-channel cap"
            )
            if self._narrowest_span < self.window_s:
                detail += (
                    f" — and on the busiest channel the cap binds so early "
                    f"that its buffer covers only {self._narrowest_span:.0f}s "
                    f"of the requested {self.window_s:g}s window, so cadence "
                    "there is measured over a fraction of the period asked "
                    f"for. Raise --max-per-channel or lower --window"
                )
            reasons.append(detail)
        if self.stats["late"]:
            reasons.append(
                f"{self.stats['late']} late observation(s) arrived older than "
                "the window and were not analysed"
            )
        if not reasons:
            return None
        return (
            "the windower shed load — " + "; ".join(reasons)
            + ". Findings are from less traffic than the link carried."
        )


def window_stream(
    observations: Iterable[Observation],
    **kwargs,
) -> Iterator[Tuple[Series, SlidingWindower]]:
    """Convenience: window a stream, yielding each Series with the windower.

    The windower comes back with every Series so a caller can read `stats`
    and `pressure()` at the point of use rather than keeping a reference.
    """
    windower = SlidingWindower(**kwargs)
    # feed_all flushes at end of stream, so no second flush here.
    for series in windower.feed_all(observations):
        yield series, windower
