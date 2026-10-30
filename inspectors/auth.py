"""Authentication and session inspectors.

Reference implementations for the `Inspector` interface, chosen as the three
that pay most often in bug bounty and that together exercise every part of
the design: structural analysis of a secret (JWT), header semantics
(cookies), and location-of-credential (token in URL).

Each keeps secrets in redactor-recognised fact keys and structural
conclusions in separate keys, so `--out json` carries the whole analysis with
none of the credentials. See `core/redact.py`.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from core.inspect import Inspector
from core.model import Context, InspectionResult, Observation

__all__ = ["CookieSecurity", "JwtWeakness", "TokenInUrl"]


# --------------------------------------------------------------------------


class CookieSecurity(Inspector):
    """Missing cookie flags and over-broad cookie scope.

    `Domain` is the one to care about most, and it is usually the one
    overlooked. A session cookie scoped to `.example.com` is sent to every
    subdomain, which converts any XSS or subdomain takeover anywhere in the
    estate into full session theft. That turns a dangling CNAME from an
    informational finding into account takeover — a chain worth far more than
    the sum of its parts, and invisible unless something reads the Domain
    attribute.

    Flags are weighted by what the cookie appears to be: a missing `HttpOnly`
    on a session cookie is serious, on an A/B-test cookie it is noise. The
    heuristic is the cookie's name, which is imperfect and deliberately
    conservative — it under-reports rather than crying wolf on every cookie
    a site sets.
    """

    name = "auth.cookie"
    kinds = ("http_response",)
    requires_attrs = ("set_cookie",)

    _SESSION_HINTS = (
        "sess", "sid", "auth", "token", "jwt", "login", "remember",
        "identity", "account", "user", "csrf", "xsrf",
    )

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        cookies = obs.attrs.get("set_cookie") or ()
        if not cookies:
            return None

        worst_score = 0.0
        worst: Optional[Dict[str, str]] = None
        issues_seen: List[str] = []

        for raw in cookies:
            name, value, attributes = _parse_set_cookie(raw)
            if not name:
                continue

            lowered = name.lower()
            sensitive = any(hint in lowered for hint in self._SESSION_HINTS)

            issues: List[str] = []
            score = 0.0

            if "secure" not in attributes:
                issues.append("missing Secure")
                score += 0.35 if sensitive else 0.10
            if "httponly" not in attributes:
                issues.append("missing HttpOnly")
                score += 0.30 if sensitive else 0.05
            if "samesite" not in attributes:
                issues.append("missing SameSite")
                score += 0.20 if sensitive else 0.05

            domain = attributes.get("domain", "")
            if domain.startswith("."):
                issues.append(f"Domain={domain} covers every subdomain")
                # The chain multiplier: broad scope plus a sensitive cookie
                # is the account-takeover precondition.
                score += 0.35 if sensitive else 0.15

            if attributes.get("path", "/") == "/" and sensitive:
                issues.append("Path=/ (no path restriction)")
                score += 0.05

            if name.startswith("__Host-"):
                if domain or attributes.get("path") != "/" or "secure" not in attributes:
                    issues.append("__Host- prefix requirements violated")
                    score += 0.30
            if name.startswith("__Secure-") and "secure" not in attributes:
                issues.append("__Secure- prefix without Secure")
                score += 0.30

            if not issues:
                continue

            issues_seen.extend(issues)
            if score > worst_score:
                worst_score = score
                worst = {
                    "cookie.name": name,
                    "cookie.flags": ", ".join(issues),
                    "cookie.domain": domain or "(host-only)",
                    "cookie.path": attributes.get("path", "/"),
                    "cookie.sensitive_name": "yes" if sensitive else "no",
                    "cookie.value": value,   # masked on output
                    "set_on": f"{obs.attrs.get('host', '')}{obs.attrs.get('path', '')}",
                }

        if worst is None:
            return None

        return self._finding(
            score=min(1.0, worst_score),
            facts=worst,
            obs=obs,
            # Only the cookie's value is a credential. Everything else —
            # name, Domain, Path, flags — IS the finding and must survive.
            secret_facts=("cookie.value",),
            features={"cookies_in_response": float(len(cookies))},
            notes=(f"{len(set(issues_seen))} distinct issue(s) across {len(cookies)} cookie(s)",),
        )


# --------------------------------------------------------------------------


class JwtWeakness(Inspector):
    """JWT header and claim defects.

    Looks in the Authorization header, in cookie values, and in query
    parameters — a JWT in any of those is worth decoding, and the location is
    itself part of the finding.

    Signatures are NOT verified. Verification needs the key, which a passive
    observer does not have, and claiming a token is forged without it would
    be a guess. What is checkable without the key is everything that usually
    matters: the algorithm, whether a signature segment exists at all,
    expiry, and what the claims disclose.
    """

    name = "auth.jwt"
    kinds = ("http_request",)

    _JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.?[A-Za-z0-9_-]*")

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        for location, token in self._candidates(obs):
            decoded = _decode_jwt(token)
            if decoded is None:
                continue
            header, claims, has_signature = decoded

            issues: List[str] = []
            score = 0.15  # a decodable JWT is always worth reporting once

            alg = str(header.get("alg", "")).lower()
            if alg in ("none", ""):
                issues.append("alg=none — unsigned token accepted")
                score += 0.75
            elif alg.startswith("hs"):
                # Not a defect by itself, but the precondition for algorithm
                # confusion if the server also accepts RS*.
                issues.append(f"alg={header.get('alg')} (symmetric; test RS/HS confusion)")
                score += 0.10
            if not has_signature:
                issues.append("empty signature segment")
                score += 0.60

            if "exp" not in claims:
                issues.append("no exp claim — token does not expire")
                score += 0.45
            else:
                lifetime = _lifetime(claims)
                if lifetime is not None and lifetime > 86400 * 30:
                    issues.append(f"exp is {lifetime / 86400:.0f} days out")
                    score += 0.20

            disclosed = sorted(
                k for k in claims
                if k.lower() in ("email", "role", "roles", "scope", "scopes",
                                 "permissions", "is_admin", "admin", "groups",
                                 "phone", "ssn", "name", "username")
            )
            if disclosed:
                issues.append(f"claims disclose {', '.join(disclosed)}")
                score += 0.10

            if location != "authorization":
                issues.append(f"token carried in {location}")
                score += 0.25 if location == "query" else 0.05

            facts = {
                "jwt.alg": str(header.get("alg", "(absent)")),
                "jwt.typ": str(header.get("typ", "(absent)")),
                "kid": str(header.get("kid", "(absent)")),
                "jwt.claims": ", ".join(sorted(claims)),
                "jwt.issues": "; ".join(issues),
                "token_location": location,
                "jwt.raw": token,          # masked on output
            }
            features = {
                "has_exp": 1.0 if "exp" in claims else 0.0,
                "signed": 1.0 if has_signature else 0.0,
                "claim_count": float(len(claims)),
            }
            return self._finding(
                score=min(1.0, score),
                facts=facts,
                obs=obs,
                secret_facts=("jwt.raw",),
                features=features,
                notes=("signature not verified — the key is not observable",),
            )
        return None

    def _candidates(self, obs: Observation) -> List[Tuple[str, str]]:
        found: List[Tuple[str, str]] = []
        auth = str(obs.attrs.get("authorization", ""))
        for match in self._JWT.finditer(auth):
            found.append(("authorization", match.group()))
        for match in self._JWT.finditer(str(obs.attrs.get("cookie", ""))):
            found.append(("cookie", match.group()))
        query = str(obs.attrs.get("query", ""))
        for match in self._JWT.finditer(query):
            found.append(("query", match.group()))
        return found


# --------------------------------------------------------------------------


class TokenInUrl(Inspector):
    """Credentials in the query string.

    Query strings are logged everywhere the URL goes: server access logs,
    reverse proxies, CDN logs, browser history, and the `Referer` header sent
    to every third party the page loads. A credential there is disclosed to
    parties that never needed it, and it stays disclosed in logs that outlive
    the session.

    Detection is by parameter NAME plus value shape. Name alone over-reports
    (`?key=sort_order`), shape alone over-reports (any long opaque string),
    and requiring both keeps it quiet enough to be read.
    """

    name = "auth.token_in_url"
    kinds = ("http_request",)
    requires_attrs = ("query",)

    _CREDENTIAL_NAMES = (
        "api_key", "apikey", "api-key", "access_token", "accesstoken",
        "auth", "auth_token", "authorization", "bearer", "token",
        "session", "sessionid", "session_id", "sid", "key", "secret",
        "password", "passwd", "pwd", "client_secret", "refresh_token",
        "id_token", "code", "signature", "sig", "jwt", "credential",
    )
    _OPAQUE = re.compile(r"^[A-Za-z0-9_\-+/=.]{16,}$")

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        query = str(obs.attrs.get("query", ""))
        if not query:
            return None

        hits: List[Tuple[str, str]] = []
        for key, value in parse_qsl(query, keep_blank_values=True):
            lowered = key.lower()
            name_matches = any(
                lowered == c or lowered.endswith("_" + c) or c in lowered
                for c in self._CREDENTIAL_NAMES
            )
            if name_matches and value and self._OPAQUE.match(value):
                hits.append((key, value))

        if not hits:
            return None

        worst = max(hits, key=lambda kv: len(kv[1]))
        score = min(1.0, 0.45 + 0.15 * len(hits))

        # A credential in the URL of a page that also sends a Referer is
        # strictly worse: it leaves the origin entirely.
        notes: Tuple[str, ...] = ()
        if obs.attrs.get("referer"):
            score = min(1.0, score + 0.10)
            notes = ("request also carried a Referer; URLs with credentials leak cross-origin",)

        return self._finding(
            score=score,
            facts={
                "parameters": ", ".join(k for k, _ in hits),
                "worst_parameter": worst[0],
                "token": worst[1],              # masked on output
                "request": f"{obs.attrs.get('method', '')} "
                           f"{obs.attrs.get('host', '')}{obs.attrs.get('path', '')}",
            },
            obs=obs,
            secret_facts=("token",),
            features={"credential_params": float(len(hits))},
            notes=notes,
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _parse_set_cookie(raw: str) -> Tuple[str, str, Dict[str, str]]:
    """Split a Set-Cookie value into name, value, and lowercased attributes."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return "", "", {}
    name, _, value = parts[0].partition("=")
    attributes: Dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition("=")
        attributes[key.strip().lower()] = val.strip() if sep else ""
    return name.strip(), value.strip(), attributes


def _b64url(segment: str) -> Optional[bytes]:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (ValueError, TypeError):
        return None


def _decode_jwt(token: str) -> Optional[Tuple[dict, dict, bool]]:
    """Decode header and claims. None if it is not actually a JWT."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    raw_header, raw_claims = _b64url(parts[0]), _b64url(parts[1])
    if raw_header is None or raw_claims is None:
        return None
    try:
        header = json.loads(raw_header)
        claims = json.loads(raw_claims)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    has_signature = len(parts) >= 3 and bool(parts[2].strip())
    return header, claims, has_signature


def _lifetime(claims: dict) -> Optional[float]:
    """exp - iat, when both are present and numeric.

    Computed against `iat` rather than wall-clock on purpose: a capture read
    months later would otherwise report every token as long-expired, which
    says something about when the file was opened and nothing about the
    token.
    """
    try:
        exp = float(claims["exp"])
        iat = float(claims.get("iat", exp))
    except (KeyError, TypeError, ValueError):
        return None
    return exp - iat if exp > iat else None
