"""Refresh-token rotation.

THE PROPERTY. A refresh token is long-lived by design, so the thing that
limits the damage of a stolen one is rotation: the authorisation server
returns a NEW refresh token on every use and invalidates the old one. Then a
stolen token works at most once, and the legitimate client's next refresh
fails — which is both the containment and the detection signal. OAuth 2.0
Security BCP and OAuth 2.1 require this for public clients; RFC 6749 §10.4
recommends it for everyone.

Without rotation a stolen refresh token is a permanent credential. It is
among the most valuable things to steal from a mobile app, and among the
least likely to be noticed, because nothing about the traffic looks wrong.

WHY A CORRELATOR. Two separate questions, neither visible in one message:

    not rotated   compare the token SENT in a request against the token
                  RETURNED in its response — two observations
    replayed      the same token accepted across two transactions — proof it
                  was never invalidated, which is strictly stronger than
                  "the response did not rotate it"

The second is the one worth having. "The server returned the same value" is
an inference about intent; "the server accepted it twice" is an observation
about behaviour.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl

from core.correlate import Correlator, CorrelationOutput
from core.model import Channel, Context, InspectionResult, Locus, Observation, Series

__all__ = ["RefreshTokenRotation"]


#: Paths that mint tokens. The grant type in the body is the real tell, so
#: this is a hint rather than a gate.
_TOKEN_PATHS = re.compile(
    r"(?:^|/)(?:oauth2?/token|token|connect/token|oauth2?/v2\.0/token"
    r"|as/token\.oauth2|auth/refresh|session/refresh)(?:/|$)",
    re.I,
)
#: A refresh token short enough to be a placeholder is not worth comparing.
MIN_TOKEN_LENGTH = 16
#: `expires_in` beyond this makes the access token itself a long-lived
#: credential, which undermines the point of having a refresh token.
LONG_LIVED_ACCESS_S = 24 * 3600


def _host_of(channel: Channel) -> str:
    return channel.dims.get("host") or (
        channel.responder.value if channel.responder else "?"
    )


def _form_or_json(body: str) -> Dict[str, str]:
    """Token endpoints take form encoding; some accept JSON. Try both.

    Returning a flat string map either way means the caller does not have to
    care which the client used — and clients in the wild use both against the
    same endpoint.
    """
    text = (body or "").strip()
    if not text:
        return {}
    if text.startswith("["):
        # A JSON array is neither form data nor an object. Falling through to
        # `parse_qsl` would turn it into a single garbage key.
        return {}
    if text.startswith("{"):
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if not isinstance(loaded, dict):
            return {}
        return {
            str(k): str(v) for k, v in loaded.items()
            if isinstance(v, (str, int, float))
        }
    return {k: v for k, v in parse_qsl(text, keep_blank_values=True)}


class RefreshTokenRotation(Correlator):
    """Does the authorisation server rotate refresh tokens on use?

    Attributed to the token endpoint's channel — the server whose behaviour
    is at fault, and the request a triager replays.
    """

    name = "oauth.refresh_rotation"
    domains = ("http",)

    def correlate(
        self, series: Sequence[Series], ctx: Context
    ) -> Iterable[CorrelationOutput]:
        # Refresh exchanges, in time order: (ts, channel, sent, returned,
        # expires_in, locus)
        exchanges: List[Tuple[float, Channel, str, Optional[str], Optional[int], Optional[Locus]]] = []

        for one in self.relevant(series):
            for txn, group in one.group_by("txn").items():
                request = next(
                    (o for o in group if o.kind == "http_request"), None
                )
                response = next(
                    (o for o in group if o.kind == "http_response"), None
                )
                if request is None:
                    continue

                sent = self._refresh_token_sent(request)
                if sent is None:
                    continue

                returned, expires = (None, None)
                if response is not None and str(
                    response.attrs.get("status", "")
                ).startswith("2"):
                    returned, expires = self._tokens_returned(response)
                elif response is not None:
                    # A rejected refresh says nothing about rotation — the
                    # server was never asked to issue a replacement.
                    continue

                exchanges.append((
                    request.ts, one.channel, sent, returned, expires,
                    request.locus,
                ))

        if not exchanges:
            return

        exchanges.sort(key=lambda item: item[0])
        yield from self._judge_replay(exchanges)
        yield from self._judge_rotation(exchanges)
        yield from self._judge_lifetime(exchanges)

    # -- extraction --------------------------------------------------------

    def _refresh_token_sent(self, request: Observation) -> Optional[str]:
        """The refresh token in a request, if this is a refresh grant.

        The grant type decides, not the path — a token endpoint also serves
        authorization_code and client_credentials grants, and neither says
        anything about rotation.
        """
        fields = _form_or_json(str(request.attrs.get("body_text", "")))
        if not fields:
            # Some clients put the grant in the query string.
            fields = dict(parse_qsl(str(request.attrs.get("query", ""))))

        grant = fields.get("grant_type", "")
        token = fields.get("refresh_token", "")
        if grant and grant != "refresh_token":
            return None
        if not token or len(token) < MIN_TOKEN_LENGTH:
            return None
        # With no grant_type at all, require the path to look like a token
        # endpoint before believing this is a refresh.
        if not grant and not _TOKEN_PATHS.search(
            str(request.attrs.get("path", ""))
        ):
            return None
        return token

    def _tokens_returned(
        self, response: Observation
    ) -> Tuple[Optional[str], Optional[int]]:
        fields = _form_or_json(str(response.attrs.get("body_text", "")))
        token = fields.get("refresh_token") or None
        expires: Optional[int] = None
        try:
            expires = int(float(fields["expires_in"]))
        except (KeyError, TypeError, ValueError):
            expires = None
        return token, expires

    # -- the strong signal -------------------------------------------------

    def _judge_replay(self, exchanges) -> Iterable[CorrelationOutput]:
        """The same refresh token accepted on more than one occasion.

        Stronger than any inference from the response body: the server
        demonstrably did not invalidate it. Two successful refreshes with
        one token means a stolen copy keeps working.
        """
        uses: Dict[str, List[Tuple[float, Channel, Optional[Locus]]]] = defaultdict(list)
        for ts, channel, sent, _returned, _expires, locus in exchanges:
            uses[sent].append((ts, channel, locus))

        for token, occurrences in uses.items():
            if len(occurrences) < 2:
                continue
            channel = occurrences[0][1]
            loci = [locus for _, _, locus in occurrences if locus]
            yield channel, InspectionResult(
                name=f"{self.name}.replayed",
                score=0.90,
                facts={
                    "host": _host_of(channel),
                    "successful_uses": str(len(occurrences)),
                    "span_s": f"{occurrences[-1][0] - occurrences[0][0]:.1f}",
                    "refresh_token": token,        # masked on output
                },
                secret_facts=("refresh_token",),
                features={"uses": float(len(occurrences))},
                occurrences=len(occurrences),
                loci=tuple(loci[:8]),
                notes=(
                    "the server accepted the same refresh token more than "
                    "once, so it was never invalidated — this is observed "
                    "behaviour, not an inference from the response body",
                    "a stolen copy of this token keeps working, and its use "
                    "cannot be distinguished from the legitimate client's",
                ),
            )

    # -- the weaker signal -------------------------------------------------

    def _judge_rotation(self, exchanges) -> Iterable[CorrelationOutput]:
        """The response did not return a new refresh token."""
        by_channel: Dict[str, List] = defaultdict(list)
        for item in exchanges:
            by_channel[item[1].key].append(item)

        for _key, group in by_channel.items():
            channel = group[0][1]
            unrotated = [
                item for item in group
                if item[3] is None or item[3] == item[2]
            ]
            if not unrotated:
                continue

            same_value = sum(1 for item in unrotated if item[3] == item[2])
            absent = len(unrotated) - same_value
            detail = []
            if same_value:
                detail.append(
                    f"{same_value} response(s) returned the SAME refresh token"
                )
            if absent:
                detail.append(
                    f"{absent} response(s) returned no refresh token at all, "
                    "so the one presented stays valid"
                )

            loci = [item[5] for item in unrotated if item[5]]
            yield channel, InspectionResult(
                name=f"{self.name}.not_rotated",
                score=0.70,
                facts={
                    "host": _host_of(channel),
                    "refresh_exchanges": str(len(group)),
                    "without_rotation": str(len(unrotated)),
                    "detail": "; ".join(detail),
                    "refresh_token": unrotated[0][2],      # masked on output
                },
                secret_facts=("refresh_token",),
                features={
                    "without_rotation": float(len(unrotated)),
                    "same_value_returned": float(same_value),
                },
                occurrences=len(unrotated),
                loci=tuple(loci[:8]),
                notes=(
                    "refresh tokens should rotate on use, so a stolen one "
                    "works at most once and the legitimate client's next "
                    "refresh fails — which is the detection signal",
                    "OAuth 2.0 Security BCP and OAuth 2.1 require rotation "
                    "for public clients",
                ),
            )

    def _judge_lifetime(self, exchanges) -> Iterable[CorrelationOutput]:
        """An access token long enough to be a credential in its own right.

        Reported quietly. A long `expires_in` is a design choice, not a
        defect, but it compounds everything above: if the access token lasts
        a day there is little left for rotation to protect.
        """
        longest: Dict[str, Tuple[int, Channel, Optional[Locus]]] = {}
        for _ts, channel, _sent, _returned, expires, locus in exchanges:
            if expires is None or expires < LONG_LIVED_ACCESS_S:
                continue
            current = longest.get(channel.key)
            if current is None or expires > current[0]:
                longest[channel.key] = (expires, channel, locus)

        for _key, (expires, channel, locus) in longest.items():
            yield channel, InspectionResult(
                name=f"{self.name}.long_lived_access",
                score=0.35,
                facts={
                    "host": _host_of(channel),
                    "expires_in_s": str(expires),
                    "expires_in_hours": f"{expires / 3600:.1f}",
                },
                features={"expires_in_s": float(expires)},
                occurrences=1,
                loci=(locus,) if locus else (),
                notes=(
                    "a design choice rather than a defect, but it compounds "
                    "a missing rotation: there is little left to protect if "
                    "the access token itself lasts this long",
                ),
            )
