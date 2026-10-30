"""Session fixation — does the session identifier survive authentication?

THE VULNERABILITY. If the session identifier a client presents before logging
in is still valid afterwards, anyone who could set that identifier keeps the
victim's authenticated session. The usual delivery is a planted cookie (via
XSS, or a cookie scoped to a sibling subdomain) or a session id accepted from
the URL. CWE-384.

WHY THIS IS A CORRELATOR AND NOT AN INSPECTOR. The defect is not in any
single message. It is the relationship between the cookie a client sent
before an authentication event and the one it sends after — two requests,
possibly on different hosts, with an event between them. Nothing examining
one message can see it.

THE HARD PART IS THE BOUNDARY, NOT THE COMPARISON. Comparing two cookie
values is trivial. Deciding that authentication happened is a heuristic, and
a wrong boundary produces a confident finding about nothing. So the signal
that identified the boundary is reported with every finding, and an
authentication attempt that did not clearly SUCCEED is never used — a failed
login is not expected to rotate anything.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl

from core.correlate import Correlator, CorrelationOutput, observations_of
from core.suffixes import party
from core.model import Channel, Context, InspectionResult, Locus, Observation, Series

__all__ = ["SessionFixation"]


#: Paths that usually mean "authenticate me".
_LOGIN_PATHS = re.compile(
    r"(?:^|/)(?:log[-_]?in|sign[-_]?in|signin|authenticate|auth|session|sessions"
    r"|token|oauth2?/token|users/sign_in|account/login|api/login)(?:/|$)",
    re.I,
)
#: Body or form field names that mean credentials are being submitted.
_PASSWORD_FIELD = re.compile(
    r'["\']?(?:password|passwd|pwd|pass|secret|credential)["\']?\s*[:=]', re.I
)
#: Cookie names treated as session identifiers. Narrow on purpose: a CSRF
#: token that fails to rotate is a different (and lesser) finding, and
#: lumping them in would make this fire on almost every application.
_SESSION_COOKIE = re.compile(
    r"^(?:.*sess(?:ion)?(?:id|_id)?|sid|jsessionid|phpsessid|asp\.net_sessionid"
    r"|connect\.sid|_session.*|auth(?:_token)?|remember(?:_me)?)$",
    re.I,
)
#: Query or path parameters that carry a session id — the fixation vector,
#: because a link can plant one.
_URL_SESSION_PARAM = re.compile(
    r"^(?:sess(?:ion)?(?:id|_id)?|sid|jsessionid|phpsessid|s)$", re.I
)


def _registrable(host: str) -> str:
    """Registrable domain via the Public Suffix List — see core/suffixes.py."""
    return party(host)


def _host_of(channel: Channel) -> str:
    return channel.dims.get("host") or (
        channel.responder.value if channel.responder else "?"
    )


def _request_cookies(obs: Observation) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for pair in str(obs.attrs.get("cookie", "")).split(";"):
        name, _, value = pair.partition("=")
        if name.strip() and value.strip():
            out.append((name.strip(), value.strip()))
    return out


def _set_cookies(obs: Observation) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for raw in obs.attrs.get("set_cookie") or ():
        head = str(raw).split(";")[0]
        name, _, value = head.partition("=")
        if name.strip() and value.strip():
            out.append((name.strip(), value.strip()))
    return out


class _Auth:
    """A point in the capture where authentication appears to have succeeded."""

    __slots__ = ("ts", "channel", "host", "path", "status", "signal", "locus")

    def __init__(self, ts, channel, host, path, status, signal, locus):
        self.ts = ts
        self.channel = channel
        self.host = host
        self.path = path
        self.status = status
        self.signal = signal
        self.locus = locus


class SessionFixation(Correlator):
    """Compare the session identifier either side of an authentication event.

    Also reports session identifiers accepted from the URL, which is the
    delivery mechanism for fixation and worth its own finding — a planted
    link is a far lower bar than planting a cookie.
    """

    name = "auth.session_fixation"
    domains = ("http",)

    def correlate(
        self, series: Sequence[Series], ctx: Context
    ) -> Iterable[CorrelationOutput]:
        relevant = self.relevant(series)

        auths = self._auth_events(relevant)
        # (registrable domain, cookie name) -> ordered (ts, value, locus) from
        # REQUESTS. Request-borne values are what the client actually presents
        # as its identity, which is the thing that must change.
        presented: Dict[Tuple[str, str], List[Tuple[float, str, Optional[Locus]]]] = (
            defaultdict(list)
        )
        issued: Dict[Tuple[str, str], List[Tuple[float, str]]] = defaultdict(list)

        for one, obs in observations_of(relevant):
            domain = _registrable(_host_of(one.channel))
            if obs.kind == "http_request":
                for name, value in _request_cookies(obs):
                    if _SESSION_COOKIE.match(name):
                        presented[(domain, name)].append((obs.ts, value, obs.locus))
            elif obs.kind == "http_response":
                for name, value in _set_cookies(obs):
                    if _SESSION_COOKIE.match(name):
                        issued[(domain, name)].append((obs.ts, value))

        for key in presented:
            presented[key].sort(key=lambda item: item[0])

        yield from self._judge_fixation(auths, presented, issued)
        yield from self._judge_url_session_ids(relevant)

    # -- boundary detection ------------------------------------------------

    def _auth_events(self, series: Sequence[Series]) -> List[_Auth]:
        """Requests that look like a SUCCESSFUL authentication.

        Three conditions, all required:

          1. a credential-submitting shape — a login-ish path, or a password
             field in the body
          2. a state-changing method; a GET does not authenticate
          3. a 2xx or 3xx response

        Condition 3 matters most. A failed login is not expected to rotate
        anything, so treating a 401 as a boundary would report fixation on
        every application that correctly rejects a bad password.
        """
        # Transaction id -> (request, response), so a status can be attached
        # to the request that earned it. Built per channel because `txn` is
        # only unique within a source/connection.
        events: List[_Auth] = []

        for one in series:
            for txn, group in one.group_by("txn").items():
                request = next(
                    (o for o in group if o.kind == "http_request"), None
                )
                response = next(
                    (o for o in group if o.kind == "http_response"), None
                )
                if request is None or response is None:
                    continue

                method = str(request.attrs.get("method", "")).upper()
                if method not in ("POST", "PUT", "PATCH"):
                    continue

                status = str(response.attrs.get("status", ""))
                if not status[:1] in ("2", "3"):
                    continue

                path = str(request.attrs.get("path", ""))
                body = str(request.attrs.get("body_text", ""))
                signals = []
                if _LOGIN_PATHS.search(path):
                    signals.append(f"path {path}")
                if _PASSWORD_FIELD.search(body):
                    signals.append("password field in request body")
                if not signals:
                    continue

                events.append(_Auth(
                    ts=request.ts,
                    channel=one.channel,
                    host=_host_of(one.channel),
                    path=path,
                    status=status,
                    signal=" + ".join(signals),
                    locus=request.locus,
                ))

        events.sort(key=lambda e: e.ts)
        return events

    # -- fixation ----------------------------------------------------------

    def _judge_fixation(
        self,
        auths: Sequence[_Auth],
        presented: Dict[Tuple[str, str], List[Tuple[float, str, Optional[Locus]]]],
        issued: Dict[Tuple[str, str], List[Tuple[float, str]]],
    ) -> Iterable[CorrelationOutput]:
        if not auths:
            return

        seen: Set[Tuple[str, str, str]] = set()

        for auth in auths:
            auth_domain = _registrable(auth.host)
            for (domain, cookie), timeline in presented.items():
                if domain != auth_domain:
                    continue

                before = [item for item in timeline if item[0] < auth.ts]
                after = [item for item in timeline if item[0] > auth.ts]

                if not before:
                    # Nothing existed to fix. A session issued only after
                    # login is the correct behaviour, not a finding.
                    continue
                if not after:
                    # The capture ends at the login. Declining is the only
                    # honest answer: the identifier may well rotate on the
                    # next request and we did not see it.
                    yield auth.channel, self._insufficient(
                        auth, cookie, "no requests after the authentication "
                        "event, so rotation could not be observed"
                    )
                    continue

                last_before = before[-1][1]
                first_after = after[0][1]
                if last_before != first_after:
                    continue      # rotated — correct behaviour

                marker = (domain, cookie, last_before)
                if marker in seen:
                    continue
                seen.add(marker)

                reissued_same = any(
                    ts > auth.ts and value == last_before
                    for ts, value in issued.get((domain, cookie), ())
                )
                loci = [
                    item[2] for item in (before[-1:] + after[:3]) if item[2]
                ]

                score = 0.90
                notes = [
                    f"authentication detected at {auth.host}{auth.path} "
                    f"-> {auth.status} ({auth.signal})",
                    "the identifier presented before authentication is still "
                    "presented after it",
                    "boundary detection is heuristic — confirm the request "
                    "above really authenticated",
                ]
                if reissued_same:
                    notes.append(
                        "the server re-set the cookie to the SAME value after "
                        "authentication, so this is not a missing Set-Cookie "
                        "but a generator that does not rotate"
                    )
                    score = 0.95

                yield auth.channel, InspectionResult(
                    name=self.name,
                    score=score,
                    facts={
                        "cookie.name": cookie,
                        "domain": domain,
                        "auth_endpoint": f"{auth.host}{auth.path}",
                        "auth_status": auth.status,
                        "auth_signal": auth.signal,
                        "rotated": "no",
                        "reissued_same_value": "yes" if reissued_same else "no",
                        "requests_before": str(len(before)),
                        "requests_after": str(len(after)),
                        "identifier": last_before,       # masked on output
                    },
                    secret_facts=("identifier",),
                    features={
                        "rotated": 0.0,
                        "assessable": 1.0,
                        "requests_before": float(len(before)),
                        "requests_after": float(len(after)),
                    },
                    occurrences=len(before) + len(after),
                    loci=tuple(loci[:8]),
                    notes=tuple(notes),
                )

    def _insufficient(
        self, auth: _Auth, cookie: str, reason: str
    ) -> InspectionResult:
        """Scored at zero so no rule can fire, surfaced as an advisory.

        "We could not observe rotation" is not "rotation did not happen".
        """
        return InspectionResult(
            name=self.name,
            score=0.0,
            facts={
                "cookie.name": cookie,
                "auth_endpoint": f"{auth.host}{auth.path}",
                "insufficient": (
                    f"{reason}. Re-capture with at least one authenticated "
                    "request after logging in."
                ),
            },
            features={"assessable": 0.0},
            loci=(auth.locus,) if auth.locus else (),
            notes=("not assessed — the capture ends at the login",),
        )

    # -- the fixation vector -----------------------------------------------

    def _judge_url_session_ids(
        self, series: Sequence[Series]
    ) -> Iterable[CorrelationOutput]:
        """A session identifier accepted from the URL.

        Reported separately because it is a VECTOR rather than proof of
        fixation: if an identifier can be planted by a link, the bar for
        exploiting a non-rotating session drops from "run script in the
        victim's origin" to "get them to click something".
        """
        found: Dict[str, Tuple[Channel, str, List[Locus], Set[str]]] = {}

        for one, obs in observations_of(series):
            if obs.kind != "http_request":
                continue
            host = _host_of(one.channel)

            hits: List[Tuple[str, str]] = []
            for name, value in parse_qsl(
                str(obs.attrs.get("query", "")), keep_blank_values=True
            ):
                if _URL_SESSION_PARAM.match(name) and len(value) >= 8:
                    hits.append((name, value))
            # Path-embedded form, e.g. `/app;jsessionid=ABC123`.
            path = str(obs.attrs.get("path", ""))
            for match in re.finditer(
                r";(jsessionid|sid|sessionid)=([^;/?]{8,})", path, re.I
            ):
                hits.append((match.group(1), match.group(2)))

            for name, value in hits:
                entry = found.get(host)
                if entry is None:
                    found[host] = (one.channel, value, [obs.locus] if obs.locus else [], {name})
                else:
                    if obs.locus and obs.locus not in entry[2]:
                        entry[2].append(obs.locus)
                    entry[3].add(name)

        for host, (channel, value, loci, names) in found.items():
            yield channel, InspectionResult(
                name="auth.session_id_in_url",
                score=0.70,
                facts={
                    "host": host,
                    "parameters": ", ".join(sorted(names)),
                    "identifier": value,            # masked on output
                },
                secret_facts=("identifier",),
                features={"parameters": float(len(names))},
                occurrences=len(loci) or 1,
                loci=tuple(loci[:8]),
                notes=(
                    "a session identifier in a URL can be planted by a link, "
                    "and is logged by every proxy, CDN and Referer header it "
                    "passes through",
                    "pairs with non-rotating sessions: together they are "
                    "account takeover from a single click",
                ),
            )
