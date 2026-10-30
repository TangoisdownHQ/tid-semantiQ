"""HTTP ruleset — bug-bounty findings.

Refs are CWE and OWASP rather than ATT&CK: the audience is a triager reading
a bug report, not an analyst mapping an intrusion.

These rules are mostly single-inspection, which is correct and worth saying
out loud. A cookie missing `Secure` is a fact, not a statistical inference —
there is nothing to corroborate and no confidence to accumulate. Confidence
here reflects how bad the instance is (how many flags, how sensitive the
cookie) rather than how sure we are that we saw it.

`http.session.token_in_url_cross_origin` is the exception: it combines a
content fact with a behavioural one, which is what having both analyzers in
one `Evidence` buys.
"""

from __future__ import annotations

from core.model import Severity
from core.score import Boost, Condition, Ontology, Rule

__all__ = ["HTTP"]


HTTP = Ontology(
    domain="http",
    rules=(
        Rule(
            id="http.auth.jwt_unsigned_or_unexpiring",
            title="JWT with a structural weakness",
            severity=Severity.HIGH,
            require=(Condition("auth.jwt", ">=", 0.50),),
            weigh={"auth.jwt": 1.0},
            boosts=(
                Boost(
                    when=Condition("auth.jwt", "<", 0.5, feature="signed"),
                    add=0.15,
                    because="signature segment is empty, so the token is unverified",
                ),
            ),
            refs=("cwe:347", "cwe:613", "owasp:API2:2023"),
            min_confidence=0.50,
        ),
        Rule(
            id="http.session.cookie_insecure",
            title="Session cookie missing protections or scoped too broadly",
            severity=Severity.MEDIUM,
            require=(Condition("auth.cookie", ">=", 0.40),),
            weigh={"auth.cookie": 1.0},
            refs=("cwe:614", "cwe:1004", "cwe:1275", "owasp:API8:2023"),
            min_confidence=0.40,
        ),
        Rule(
            id="http.session.cookie_takeover_chain",
            title="Sensitive cookie scoped to all subdomains",
            severity=Severity.HIGH,
            require=(
                Condition("auth.cookie", ">=", 0.70),
            ),
            weigh={"auth.cookie": 1.0},
            # Called out separately from the generic cookie rule because the
            # consequence is different in kind: a wildcard-Domain session
            # cookie turns any subdomain XSS or dangling-CNAME takeover
            # anywhere in the estate into account takeover. Worth its own
            # title so a triager sees the chain and not just a missing flag.
            refs=("cwe:1275", "cwe:565"),
            supersedes=("http.session.cookie_insecure",),
            min_confidence=0.70,
        ),
        Rule(
            id="http.auth.credential_sent_to_third_party",
            title="Authentication credential sent to an unrelated host",
            severity=Severity.CRITICAL,
            require=(
                Condition("auth.credential_reuse", ">=", 0.70),
                # The gate is the DOMAIN split, not the reuse. A token shared
                # between api.example.com and cdn.example.com is first-party
                # plumbing; the same token at an analytics vendor is a
                # credential disclosed to a party that should never hold it.
                Condition("auth.credential_reuse", ">=", 1.0, feature="cross_party"),
            ),
            weigh={"auth.credential_reuse": 1.0},
            refs=("cwe:200", "cwe:522", "owasp:API8:2023"),
            supersedes=("http.auth.credential_shared_across_hosts",),
            min_confidence=0.70,
        ),
        Rule(
            id="http.auth.credential_shared_across_hosts",
            title="Credential reused across several first-party hosts",
            severity=Severity.LOW,
            require=(
                Condition("auth.credential_reuse", ">=", 0.40),
                Condition("auth.credential_reuse", "<", 1.0, feature="cross_party"),
            ),
            weigh={"auth.credential_reuse": 1.0},
            refs=("cwe:522",),
            min_confidence=0.40,
        ),
        Rule(
            id="http.privacy.identifier_to_third_party",
            title="User identifier sent to a third-party host",
            severity=Severity.LOW,
            require=(Condition("privacy.identifier_spray", ">=", 0.50),),
            weigh={"privacy.identifier_spray": 1.0},
            # Low by design. Often disclosed and intended; it is reported as
            # a data flow for the client to confirm, not as a vulnerability.
            refs=("cwe:359",),
            min_confidence=0.50,
        ),
        Rule(
            id="http.cors.credentialed_wildcard_or_reflection",
            title="CORS policy allows a foreign origin to read authenticated responses",
            severity=Severity.HIGH,
            require=(
                Condition("web.cors", ">=", 0.60),
                Condition("web.cors", ">=", 1.0, feature="credentialed"),
            ),
            weigh={"web.cors": 1.0},
            refs=("cwe:942", "cwe:346", "owasp:API8:2023"),
            supersedes=("http.cors.permissive_policy",),
            min_confidence=0.60,
        ),
        Rule(
            id="http.cors.permissive_policy",
            title="Permissive CORS policy",
            severity=Severity.LOW,
            require=(Condition("web.cors", ">=", 0.30),),
            weigh={"web.cors": 1.0},
            refs=("cwe:942",),
            min_confidence=0.30,
        ),
        Rule(
            id="http.disclosure.secret_in_response_body",
            title="Credential-shaped string in a response body",
            severity=Severity.CRITICAL,
            require=(Condition("web.secrets_in_response", ">=", 0.80),),
            weigh={"web.secrets_in_response": 1.0},
            refs=("cwe:200", "cwe:312", "cwe:540"),
            supersedes=("http.disclosure.internal_host_in_response",),
            min_confidence=0.80,
        ),
        Rule(
            id="http.disclosure.internal_host_in_response",
            title="Internal hostname or RFC1918 address disclosed in a response",
            severity=Severity.LOW,
            require=(
                Condition("web.secrets_in_response", ">=", 0.30),
                Condition("web.secrets_in_response", ">=", 1.0,
                          feature="internal_host_count"),
            ),
            weigh={"web.secrets_in_response": 1.0},
            refs=("cwe:200",),
            min_confidence=0.30,
        ),
        Rule(
            id="http.oauth.weak_authorization_request",
            title="OAuth authorization request with a flow weakness",
            severity=Severity.HIGH,
            require=(Condition("web.oauth", ">=", 0.50),),
            weigh={"web.oauth": 1.0},
            boosts=(
                Boost(
                    when=Condition("web.oauth", "<", 1.0, feature="has_state"),
                    add=0.10,
                    because="no state parameter leaves the callback CSRF-exposed",
                ),
            ),
            refs=("cwe:352", "cwe:601", "owasp:API8:2023"),
            min_confidence=0.50,
        ),
        Rule(
            id="http.session.token_predictable",
            title="Session token is predictable or carries readable structure",
            severity=Severity.CRITICAL,
            require=(
                Condition("auth.token_quality", ">=", 0.70),
                # Only fires on an assessed group. An unassessable token
                # scores zero and must never reach a rule — "we could not
                # measure it" is not "it is weak".
                Condition("auth.token_quality", ">=", 1.0, feature="assessable"),
            ),
            weigh={"auth.token_quality": 1.0},
            refs=("cwe:330", "cwe:340", "owasp:API2:2023"),
            supersedes=("http.session.token_weak_structure",),
            min_confidence=0.70,
        ),
        Rule(
            id="http.session.token_weak_structure",
            title="Session token shows fixed framing or a narrow keyspace",
            severity=Severity.MEDIUM,
            require=(
                Condition("auth.token_quality", ">=", 0.30),
                Condition("auth.token_quality", ">=", 1.0, feature="assessable"),
            ),
            weigh={"auth.token_quality": 1.0},
            refs=("cwe:331", "cwe:330"),
            min_confidence=0.30,
        ),
        Rule(
            id="http.timing.hidden_differential",
            title="Response times split into two clusters not visible in the responses",
            severity=Severity.MEDIUM,
            require=(
                Condition("web.timing_differential", ">=", 0.60),
                # The valuable case: two latency clusters whose response
                # statuses OVERLAP, so nothing in the responses themselves
                # reveals the difference. That is the shape of a username
                # enumeration oracle — identical status, identical body, and
                # only the time differs.
                Condition("web.timing_differential", "<", 1.0,
                          feature="status_aligned"),
            ),
            weigh={"web.timing_differential": 1.0},
            # MEDIUM, not HIGH, and deliberately. The statistics can be very
            # tight and still describe caching, connection reuse or backend
            # load. Promoting an unreplayed timing difference to HIGH would
            # be exactly the plausible-looking finding nobody can reproduce
            # that ADR-001 set out to avoid.
            refs=("cwe:208", "cwe:203", "owasp:API2:2023"),
            min_confidence=0.60,
        ),
        Rule(
            id="http.timing.visible_differential",
            title="Response times differ by outcome",
            severity=Severity.LOW,
            require=(
                Condition("web.timing_differential", ">=", 0.40),
                Condition("web.timing_differential", ">=", 1.0,
                          feature="status_aligned"),
            ),
            weigh={"web.timing_differential": 1.0},
            # The clusters line up with status codes, so the distinction is
            # already visible without measuring anything. Recorded, not
            # pressed.
            refs=("cwe:208",),
            min_confidence=0.40,
        ),
        Rule(
            id="http.session.fixation",
            title="Session identifier survives authentication",
            severity=Severity.HIGH,
            require=(
                Condition("auth.session_fixation", ">=", 0.80),
                # Never fire on an unassessable boundary. "We could not
                # observe rotation" is not "rotation did not happen".
                Condition("auth.session_fixation", ">=", 1.0,
                          feature="assessable"),
                # At least one request either side, or there is nothing to
                # compare.
                Condition("auth.session_fixation", ">=", 1.0,
                          feature="requests_before"),
                Condition("auth.session_fixation", ">=", 1.0,
                          feature="requests_after"),
            ),
            weigh={"auth.session_fixation": 1.0},
            refs=("cwe:384", "cwe:613", "owasp:API2:2023"),
            min_confidence=0.80,
        ),
        Rule(
            id="http.session.identifier_in_url",
            title="Session identifier accepted in a URL",
            severity=Severity.MEDIUM,
            require=(Condition("auth.session_id_in_url", ">=", 0.60),),
            weigh={"auth.session_id_in_url": 1.0},
            boosts=(
                Boost(
                    when=Condition("auth.session_fixation", ">=", 0.80),
                    add=0.15,
                    because="the same session also fails to rotate on login, "
                            "so a planted link is account takeover",
                ),
            ),
            refs=("cwe:598", "cwe:384", "cwe:532"),
            min_confidence=0.60,
        ),
        Rule(
            id="http.oauth.refresh_token_replayed",
            title="Refresh token accepted more than once",
            severity=Severity.HIGH,
            require=(
                Condition("oauth.refresh_rotation.replayed", ">=", 0.80),
                Condition("oauth.refresh_rotation.replayed", ">=", 2.0,
                          feature="uses"),
            ),
            weigh={"oauth.refresh_rotation.replayed": 1.0},
            # The strong form. Not an inference from a response body — the
            # server demonstrably accepted the same token twice, so a stolen
            # copy keeps working and its use is indistinguishable from the
            # real client's.
            refs=("cwe:613", "cwe:384", "owasp:API2:2023"),
            supersedes=("http.oauth.refresh_token_not_rotated",),
            min_confidence=0.80,
        ),
        Rule(
            id="http.oauth.refresh_token_not_rotated",
            title="Refresh token not rotated on use",
            severity=Severity.MEDIUM,
            require=(
                Condition("oauth.refresh_rotation.not_rotated", ">=", 0.60),
            ),
            weigh={"oauth.refresh_rotation.not_rotated": 1.0},
            boosts=(
                Boost(
                    when=Condition("oauth.refresh_rotation.long_lived_access",
                                   ">=", 0.30),
                    add=0.10,
                    because="the access token is long-lived too, so rotation "
                            "would have little left to protect either way",
                ),
            ),
            # MEDIUM: the response not carrying a new token is good evidence
            # of no rotation, but it is still an inference. The replay rule
            # above is the observed version and supersedes this.
            refs=("cwe:613", "owasp:API2:2023"),
            min_confidence=0.60,
        ),
        Rule(
            id="http.auth.credential_in_url",
            title="Credential carried in a query string",
            severity=Severity.MEDIUM,
            require=(Condition("auth.token_in_url", ">=", 0.45),),
            weigh={"auth.token_in_url": 1.0},
            refs=("cwe:598", "cwe:532", "owasp:API8:2023"),
            min_confidence=0.45,
        ),
    ),
)
