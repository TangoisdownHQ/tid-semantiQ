"""BaselineStore implementations.

`rarity` is what makes the tool usable rather than noisy, and rarity is
entirely a function of what this store knows. A fresh store makes every
channel look maximally rare, so the first run of a deployment is the least
trustworthy one — stated plainly in `warm_up_notice()` because an operator
who does not know that will distrust the tool for the wrong reason.

Two backends, same protocol:

  SqliteBaseline   standalone / bug bounty. One file, no service.
  NullBaseline     explicitly no history, so `rarity` declines to answer
                   rather than inventing a score.

A database-backed implementation against a fleet's shared history is the
third, and it is the one that gives fleet-wide prevalence real meaning —
prevalence across one laptop is a much weaker denominator than prevalence
across every enrolled endpoint.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Optional

from core.model import Channel, Series

__all__ = ["SqliteBaseline", "NullBaseline"]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS channels (
    channel_key   TEXT PRIMARY KEY,
    profile_key   TEXT NOT NULL,
    initiator_key TEXT,
    domain        TEXT NOT NULL,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    observations  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_channels_profile ON channels (profile_key);
CREATE INDEX IF NOT EXISTS idx_channels_initiator ON channels (initiator_key);
"""


class SqliteBaseline:
    """Channel history in one SQLite file.

    Stores per-channel aggregates only — never payloads, never per-packet
    rows. That keeps the file small enough to carry between engagements and
    means a captured baseline is not itself sensitive material.
    """

    available = True

    def __init__(self, path: Path | str = "semantiq-baseline.db"):
        self.path = Path(path)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- reads -------------------------------------------------------------

    def first_seen(self, channel: Channel) -> Optional[float]:
        row = self._conn.execute(
            "SELECT first_seen FROM channels WHERE channel_key = ?",
            (channel.key,),
        ).fetchone()
        return float(row["first_seen"]) if row else None

    def observation_count(self, channel: Channel) -> int:
        row = self._conn.execute(
            "SELECT observations FROM channels WHERE channel_key = ?",
            (channel.key,),
        ).fetchone()
        return int(row["observations"]) if row else 0

    def prevalence(self, channel: Channel) -> float:
        """Distinct initiators on this profile / distinct initiators known.

        Asked of `profile_key`, not `key` — see Channel.profile_key.

        A single-host baseline can only ever answer 0 or 1, which is why
        fleet-wide history (the SOC's Postgres) is worth more here than a
        local file. The denominator is reported by `describe_denominator()`
        so an operator can see how much the number is worth.
        """
        total = self._conn.execute(
            "SELECT COUNT(DISTINCT initiator_key) AS n FROM channels "
            "WHERE initiator_key IS NOT NULL"
        ).fetchone()["n"]
        if not total:
            return 0.0
        on_profile = self._conn.execute(
            "SELECT COUNT(DISTINCT initiator_key) AS n FROM channels "
            "WHERE profile_key = ? AND initiator_key IS NOT NULL",
            (channel.profile_key,),
        ).fetchone()["n"]
        return on_profile / total

    def describe_denominator(self, now: Optional[float] = None) -> str:
        """`now` should be the capture's end time, not wall-clock — see
        Context.now. Defaults to wall-clock for live use."""
        now = time.time() if now is None else now
        row = self._conn.execute(
            "SELECT COUNT(*) AS channels, "
            "COUNT(DISTINCT initiator_key) AS hosts, "
            "MIN(first_seen) AS oldest FROM channels"
        ).fetchone()
        if not row["channels"]:
            return "empty baseline"
        age_days = (now - (row["oldest"] or now)) / 86400
        return (
            f"{row['channels']} channels, {row['hosts']} hosts, "
            f"{age_days:.1f} days of history"
        )

    def warm_up_notice(self, now: Optional[float] = None) -> Optional[str]:
        """A warning to print above findings when the baseline is too thin
        for `rarity` to mean anything.

        An operator who does not know the baseline is cold will read a page
        of 'uncommon destination' findings as a broken tool rather than as an
        empty denominator.
        """
        now = time.time() if now is None else now
        row = self._conn.execute(
            "SELECT COUNT(*) AS channels, COUNT(DISTINCT initiator_key) AS hosts, "
            "MIN(first_seen) AS oldest FROM channels"
        ).fetchone()
        channels = row["channels"] or 0
        hosts = row["hosts"] or 0
        span_days = (now - row["oldest"]) / 86400 if row["oldest"] else 0.0

        # Three independent ways a baseline can be too thin, reported
        # separately because they need different fixes: more channels, more
        # hosts, or more time.
        reasons = []
        if channels < 200:
            reasons.append(f"only {channels} channels")
        if hosts < 5:
            reasons.append(f"only {hosts} host(s) — prevalence can barely vary")
        if span_days < 1.0:
            reasons.append(f"only {span_days * 24:.1f}h of history")
        if not reasons:
            return None
        return (
            f"baseline is thin ({'; '.join(reasons)}) — channels will look "
            "rarer than they are, so rarity-gated findings will over-report"
        )

    # -- write -------------------------------------------------------------

    def record(self, series: Series) -> None:
        """Fold a Series into the aggregates.

        Called by the pipeline AFTER scoring, so a channel is never counted
        as evidence of its own prevalence on the run that discovered it.
        """
        channel = series.channel
        start = series.start or time.time()
        end = series.end or start
        initiator = channel.initiator.key if channel.initiator else None

        self._conn.execute(
            """
            INSERT INTO channels
                (channel_key, profile_key, initiator_key, domain,
                 first_seen, last_seen, observations)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(channel_key) DO UPDATE SET
                first_seen   = MIN(first_seen, excluded.first_seen),
                last_seen    = MAX(last_seen,  excluded.last_seen),
                observations = observations + excluded.observations
            """,
            (
                channel.key,
                channel.profile_key,
                initiator,
                channel.domain,
                start,
                end,
                series.count,
            ),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


class NullBaseline:
    """No history at all. `available` is False, so `rarity` declines to
    answer and every rarity-gated rule stays silent.

    This is the correct behaviour with no baseline. The tempting alternative
    — letting the reads return "never seen, prevalence zero" — scores every
    channel as maximally rare, which gates nothing and surfaces everything.
    The flag exists precisely because those two situations produce identical
    query results and opposite correct responses.
    """

    available = False

    def first_seen(self, channel: Channel) -> Optional[float]:
        return None

    def observation_count(self, channel: Channel) -> int:
        return 0

    def prevalence(self, channel: Channel) -> float:
        return 0.0

    def record(self, series: Series) -> None:
        return None
