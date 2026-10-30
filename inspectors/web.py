"""Web-surface inspectors: CORS, secrets in responses, OAuth flow defects.

Together with `inspectors/auth.py` these cover the content findings that pay
most often. What they deliberately do NOT do is probe: every conclusion here
comes from traffic the operator already generated. Confirming an exploitable
CORS policy or a working `redirect_uri` bypass needs a request this tool does
not send, so findings say what was observed and name the test, rather than
claiming the bug.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from core.inspect import Inspector
from core.model import Context, InspectionResult, Observation

__all__ = ["CorsPolicy", "SecretsInResponse", "OAuthFlow", "DisclosureHeaders"]


# --------------------------------------------------------------------------


class CorsPolicy(Inspector):
    """Access-Control headers that undermine the same-origin policy.

    The dangerous combination is a reflected or wildcarded origin TOGETHER
    with `Allow-Credentials: true` — that is what lets an attacker page read
    authenticated responses. Either alone is usually benign: `ACAO: *`
    without credentials is how public APIs are meant to work, and browsers
    reject `*` with credentials outright.

    Reflection is inferred by comparing the response's `ACAO` against the
    request's `Origin`. That needs both messages, and they arrive as separate
    observations — so the request's Origin is carried on the response by the
    capture profile where available, and absent that the inspector reports
    the policy without claiming reflection.
    """

    name = "web.cors"
    kinds = ("http_response",)

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        headers = obs.attrs.get("headers") or {}
        allow_origin = headers.get("access-control-allow-origin", "").strip()
        if not allow_origin:
            return None

        allow_credentials = (
            headers.get("access-control-allow-credentials", "").strip().lower()
            == "true"
        )
        request_origin = str(obs.attrs.get("request_origin", "")).strip()

        issues: List[str] = []
        score = 0.10  # a CORS policy is worth recording once

        reflected = bool(
            request_origin
            and allow_origin.lower() == request_origin.lower()
            and allow_origin not in ("*", "null")
        )

        if reflected:
            issues.append(f"reflects the request Origin ({request_origin})")
            score += 0.45
        if allow_origin == "*":
            issues.append("Allow-Origin: *")
            score += 0.15
        if allow_origin.lower() == "null":
            issues.append("accepts the null origin (sandboxed iframes, local files)")
            score += 0.35

        if allow_credentials:
            if reflected or allow_origin.lower() == "null":
                # The combination is the finding: an attacker origin can read
                # authenticated responses.
                issues.append(
                    "with Allow-Credentials: true — an attacker origin can "
                    "read authenticated responses"
                )
                score += 0.40
            elif allow_origin == "*":
                issues.append(
                    "Allow-Credentials: true with '*' — browsers reject this "
                    "combination, so it is a misconfiguration rather than a bug"
                )
                score += 0.05

        methods = headers.get("access-control-allow-methods", "")
        if any(m in methods.upper() for m in ("PUT", "DELETE", "PATCH")):
            issues.append(f"state-changing methods allowed ({methods})")
            score += 0.10

        if not issues:
            return None

        return self._finding(
            score=min(1.0, score),
            facts={
                "allow_origin": allow_origin,
                "allow_credentials": "true" if allow_credentials else "false",
                "request_origin": request_origin or "(not captured)",
                "issues": "; ".join(issues),
                "endpoint": f"{obs.attrs.get('host', '')}{obs.attrs.get('path', '')}",
            },
            obs=obs,
            features={
                "reflected": 1.0 if reflected else 0.0,
                "credentialed": 1.0 if allow_credentials else 0.0,
            },
            notes=(
                "not probed — confirm by replaying with a different Origin",
            ),
        )


# --------------------------------------------------------------------------


class SecretsInResponse(Inspector):
    """Credential-shaped strings in a response body.

    The patterns are a small high-precision set, not an exhaustive catalog.
    Each has a distinctive prefix or structure, so a hit is a hit rather than
    a guess — which is the only way this is readable on a real capture, where
    a loose regex matches every base64 blob on the page.

    The broad 80-pattern catalog in the `offensive-osint` skill is the right
    source to grow this from, and the right way to grow it is one pattern at
    a time with a prefix anchor.
    """

    name = "web.secrets_in_response"
    kinds = ("http_response",)
    requires_attrs = ("body_text",)

    #: (label, pattern, score). Anchored on distinctive prefixes.
    _PATTERNS: Tuple[Tuple[str, "re.Pattern[str]", float], ...] = (
        ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.90),
        ("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b"), 0.95),
        ("Stripe restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{16,}\b"), 0.85),
        ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), 0.95),
        ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 0.90),
        ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0.85),
        ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), 0.85),
        ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{24,}\b"), 0.90),
        ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.95),
        ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), 0.50),
    )

    #: Internal hosts and RFC1918 addresses — disclosure, not a credential,
    #: so scored much lower and reported separately in the facts.
    _INTERNAL = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|[a-z0-9\-]+\.(?:internal|corp|local|intranet)(?:\.[a-z]{2,})?)\b"
    )

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        body = str(obs.attrs.get("body_text", ""))
        if not body:
            return None

        hits: List[Tuple[str, str, float]] = []
        for label, pattern, weight in self._PATTERNS:
            match = pattern.search(body)
            if match:
                hits.append((label, match.group(), weight))

        internal = sorted(set(self._INTERNAL.findall(body)))[:5]

        if not hits and not internal:
            return None

        score = max((w for _, _, w in hits), default=0.0)
        if internal:
            score = max(score, 0.35)

        facts: Dict[str, str] = {
            "endpoint": f"{obs.attrs.get('host', '')}{obs.attrs.get('path', '')}",
            "status": str(obs.attrs.get("status", "")),
            "kinds_found": ", ".join(label for label, _, _ in hits) or "(none)",
        }
        secrets: List[str] = []
        for index, (label, value, _) in enumerate(hits):
            key = f"secret_{index}"
            facts[key] = value          # masked on output
            secrets.append(key)
            facts[f"{key}_kind"] = label
        if internal:
            facts["internal_hosts"] = ", ".join(internal)

        return self._finding(
            score=min(1.0, score),
            facts=facts,
            obs=obs,
            secret_facts=tuple(secrets),
            features={
                "secret_count": float(len(hits)),
                "internal_host_count": float(len(internal)),
                "body_bytes": float(len(body)),
            },
            notes=(
                "high-precision prefixes only; a negative result is not a "
                "clean bill of health",
            ),
        )


# --------------------------------------------------------------------------


class OAuthFlow(Inspector):
    """Defects visible in an OAuth/OIDC authorization request.

    Everything here is readable from the authorize URL alone, which is what
    makes it a per-message inspection: the response type, whether PKCE is
    present, whether `state` is present, and what scopes are being asked for.

    What is NOT claimed: that `redirect_uri` validation is bypassable, or
    that `state` is unpredictable across requests. Both need probing or
    multiple samples. The finding names the test instead of asserting the
    result.
    """

    name = "web.oauth"
    kinds = ("http_request",)

    _AUTHORIZE_PATHS = (
        "/oauth/authorize", "/oauth2/authorize", "/authorize",
        "/connect/authorize", "/oauth2/v2.0/authorize", "/o/oauth2/v2/auth",
        "/oauth/v2/authorize", "/as/authorization.oauth2",
    )
    _PRIVILEGED_SCOPES = (
        "admin", "write", "delete", "offline_access", "all",
        "user:email", "repo", "root",
    )

    def applies_to(self, obs: Observation, ctx: Context) -> bool:
        if not super().applies_to(obs, ctx):
            return False
        path = str(obs.attrs.get("path", "")).lower()
        if any(path.endswith(p) or path == p for p in self._AUTHORIZE_PATHS):
            return True
        # Fall back to parameter shape: a request carrying response_type and
        # client_id is an authorization request whatever the path is called.
        query = parse_qs(str(obs.attrs.get("query", "")))
        return "response_type" in query and "client_id" in query

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        query = parse_qs(str(obs.attrs.get("query", "")))
        if not query:
            return None

        def first(key: str) -> str:
            values = query.get(key) or []
            return values[0] if values else ""

        response_type = first("response_type")
        issues: List[str] = []
        score = 0.15

        if response_type and response_type != "code":
            # Implicit and hybrid flows return tokens in the URL fragment,
            # where they land in history and Referer. Deprecated for this
            # reason by the OAuth 2.0 Security BCP.
            issues.append(
                f"response_type={response_type} (implicit/hybrid — token "
                "returned in the URL fragment)"
            )
            score += 0.45

        if not first("code_challenge"):
            if response_type == "code":
                issues.append("no PKCE (code_challenge absent) on an auth-code flow")
                score += 0.35
            else:
                issues.append("no PKCE (code_challenge absent)")
                score += 0.15
        elif first("code_challenge_method").lower() == "plain":
            issues.append("code_challenge_method=plain defeats the point of PKCE")
            score += 0.30

        state = first("state")
        if not state:
            issues.append("no state parameter — the callback is CSRF-exposed")
            score += 0.30
        elif len(state) < 8:
            issues.append(f"state is only {len(state)} characters")
            score += 0.15

        redirect_uri = first("redirect_uri")
        if redirect_uri:
            split = urlsplit(redirect_uri)
            if split.scheme == "http":
                issues.append("redirect_uri is plaintext http")
                score += 0.30
            if "*" in redirect_uri:
                issues.append("redirect_uri contains a wildcard")
                score += 0.35

        scopes = (first("scope") or "").replace("+", " ").split()
        privileged = [s for s in scopes if any(p in s.lower() for p in self._PRIVILEGED_SCOPES)]
        if privileged:
            issues.append(f"requests privileged scopes: {', '.join(privileged)}")
            score += 0.10

        if not issues:
            return None

        return self._finding(
            score=min(1.0, score),
            facts={
                "endpoint": f"{obs.attrs.get('host', '')}{obs.attrs.get('path', '')}",
                "response_type": response_type or "(absent)",
                "pkce": "present" if first("code_challenge") else "absent",
                "state": "present" if state else "absent",
                "redirect_uri": redirect_uri or "(absent)",
                "scopes": " ".join(scopes) or "(none)",
                "issues": "; ".join(issues),
            },
            obs=obs,
            features={
                "has_pkce": 1.0 if first("code_challenge") else 0.0,
                "has_state": 1.0 if state else 0.0,
                "scope_count": float(len(scopes)),
            },
            notes=(
                "redirect_uri validation and state unpredictability are not "
                "tested here — both need probing or repeated samples",
            ),
        )


# --------------------------------------------------------------------------


class DisclosureHeaders(Inspector):
    """Version and framework disclosure in response headers.

    Low value on its own and scored to stay out of the way. It earns its
    place as inventory: knowing a host runs a specific nginx and Express
    build is what makes a later CVE lookup possible, and it costs nothing to
    record while the capture is open.
    """

    name = "web.disclosure"
    kinds = ("http_response",)

    _TELLS = (
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-drupal-cache", "x-runtime", "x-version",
    )
    _VERSIONED = re.compile(r"\d+\.\d+")

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        headers = obs.attrs.get("headers") or {}
        found = {name: headers[name] for name in self._TELLS if headers.get(name)}
        if not found:
            return None

        versioned = [v for v in found.values() if self._VERSIONED.search(v)]
        return self._finding(
            # Deliberately below every rule threshold in the ontology: this
            # is recorded as evidence, not reported as a finding, unless a
            # rule explicitly asks for it.
            score=0.25 if versioned else 0.10,
            facts={
                "endpoint": f"{obs.attrs.get('host', '')}{obs.attrs.get('path', '')}",
                **{f"header.{k}": v for k, v in found.items()},
            },
            obs=obs,
            features={
                "headers": float(len(found)),
                "versioned": float(len(versioned)),
            },
        )
