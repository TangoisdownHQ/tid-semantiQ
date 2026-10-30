"""The codes a finding cites, in plain language.

A finding ends with a line like `refs  attack:T1071.001, attack:T1573` or
`refs  cwe:384`. Those codes are precise and standard — an ATT&CK technique,
an ICS ATT&CK technique, a CWE weakness — and they are exactly the part of a
finding a non-specialist cannot read. The whole point of this tool is that
its output can be followed without taking it on trust, so a code the reader
cannot expand is a small hole in that promise.

This module is the counterpart to `out/glossary.py`: where the glossary
defines the *words* the narration used, this defines the *codes* the findings
cited. It is built the same way and for the same reasons — ordinary code, no
model, so a description cannot drift from the standard it names — and it is
contextual in the same way: `reference_section` is handed the refs that the
findings which actually fired carried, and defines only those.

A code with no local description is still listed, with a note that says so,
rather than dropped — the same honesty rule the rest of the tool follows: a
reader must be able to tell "nothing to add" from "silently omitted".

The vocabulary is bounded. Every rule in `ontology/` cites from a fixed set,
and `test_every_cited_ref_has_a_description` walks the ontologies to assert
this file covers all of it — so a new rule that introduces a code the reader
cannot expand fails a test rather than shipping.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

__all__ = ["REFERENCES", "describe_ref", "label_ref", "reference_section"]


#: ref id -> (short title, category label, extensive plain-language body).
#: Keys carry the namespace exactly as the ontologies write them.
REFERENCES: Dict[str, Tuple[str, str, str]] = {
    # ---- ATT&CK Enterprise -----------------------------------------------
    "attack:T1071.001": (
        "Application Layer Protocol: Web Protocols",
        "ATT&CK · Command and Control",
        "An attacker runs command-and-control over HTTP or HTTPS so the "
        "traffic blends in with the ordinary web browsing every network "
        "produces all day. The protocol is legitimate; what gives it away is "
        "behaviour — a regular check-in cadence to an unremarkable-looking "
        "destination — which is why this tool cites it for a periodic "
        "callback rather than for anything in the payload.",
    ),
    "attack:T1071.004": (
        "Application Layer Protocol: DNS",
        "ATT&CK · Command and Control",
        "An attacker carries command-and-control, or smuggles data, inside "
        "DNS queries and answers. DNS is attractive because almost every "
        "network lets it out unfiltered, so a channel that cannot reach the "
        "internet any other way can often still reach a resolver. The "
        "signature is a flood of distinct, often long or random-looking names "
        "under one zone — high cardinality where a normal client would reuse "
        "a handful of names.",
    ),
    "attack:T1573": (
        "Encrypted Channel",
        "ATT&CK · Command and Control",
        "An attacker encrypts the command-and-control channel so its contents "
        "cannot be read by anything inspecting the wire. This tool never "
        "needs to read those contents to cite it: encryption hides the "
        "payload but not the shape, so a regular, rare, lopsided channel is "
        "described from timing and volume alone, with the encryption itself "
        "noted as consistent with the technique rather than as proof of it.",
    ),
    "attack:T1029": (
        "Scheduled Transfer",
        "ATT&CK · Exfiltration",
        "Data is moved out on a schedule — at a fixed time of day or a fixed "
        "interval — so each transfer is small and regular enough to pass for "
        "routine background traffic. The cited signal is periodicity on an "
        "outbound channel; the schedule is the tell, and it is also exactly "
        "how a backup or a telemetry agent behaves, which is why rarity has "
        "to accompany it before the finding is raised.",
    ),
    "attack:T1041": (
        "Exfiltration Over C2 Channel",
        "ATT&CK · Exfiltration",
        "Stolen data is sent back out over the same channel the attacker "
        "already uses for command-and-control, rather than opening a second, "
        "noisier path. In metadata this shows as an outbound-heavy "
        "asymmetry on a channel that is otherwise a steady beacon — the "
        "check-in that suddenly also carries bulk.",
    ),
    "attack:T1030": (
        "Data Transfer Size Limits",
        "ATT&CK · Exfiltration",
        "An attacker splits the data being stolen into uniform, modest-sized "
        "pieces so no single transfer is large enough to trip a volume "
        "threshold. The giveaway is the uniformity itself — many transfers of "
        "suspiciously similar size — which is visible in the per-exchange "
        "trace even when the content is encrypted.",
    ),
    "attack:T1046": (
        "Network Service Discovery",
        "ATT&CK · Discovery",
        "An attacker probes a host or a range to learn which services and "
        "ports are listening, as reconnaissance before an attack. The "
        "signature is one source touching many destinations or many ports in "
        "a short span — high fanout — often with a high rate of refused or "
        "unanswered connections, since most probes hit nothing.",
    ),
    "attack:T1048.003": (
        "Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol",
        "ATT&CK · Exfiltration",
        "Data is carried out over a different, cleartext protocol than the "
        "command channel — classically DNS or ICMP — chosen because it is "
        "rarely inspected. This tool cites it alongside the DNS technique "
        "when a zone is used as a high-cardinality carrier, because a DNS "
        "tunnel is simultaneously a covert channel and an exfiltration path.",
    ),
    "attack:T1568.002": (
        "Dynamic Resolution: Domain Generation Algorithms",
        "ATT&CK · Command and Control",
        "Rather than hard-code a destination that defenders could block, "
        "malware computes a stream of pseudo-random domain names and tries "
        "them until one resolves to a live controller. The signature is a run "
        "of lookups for algorithmic-looking names that mostly return "
        "NXDOMAIN — which is also what a search-domain list or a buggy client "
        "produces, so the tool describes the shape and does not leap to the "
        "cause.",
    ),
    # ---- ATT&CK for ICS --------------------------------------------------
    "ics-attack:T0814": (
        "Denial of Service",
        "ATT&CK ICS · Inhibit Response Function",
        "An attacker floods or stalls an industrial device so it can no "
        "longer respond to legitimate control traffic — in an ICS this does "
        "not merely slow a service, it can take a physical process out of "
        "control. Cited when a device stops answering or is overwhelmed by "
        "request volume.",
    ),
    "ics-attack:T0815": (
        "Denial of View",
        "ATT&CK ICS · Inhibit Response Function",
        "The operator's window onto the process is blinded — the HMI or "
        "monitoring path is disrupted so the humans in charge can no longer "
        "see what the plant is doing, even if control itself still functions. "
        "Dangerous precisely because it hides whatever else is happening.",
    ),
    "ics-attack:T0816": (
        "Device Restart/Shutdown",
        "ATT&CK ICS · Inhibit Response Function",
        "A controller is commanded to restart or shut down, interrupting the "
        "process it governs. On a control network a restart command from an "
        "unexpected source, or at an unexpected time, is a serious event, and "
        "the tool cites this when it sees such a command issued.",
    ),
    "ics-attack:T0830": (
        "Adversary-in-the-Middle",
        "ATT&CK ICS · Collection",
        "An attacker positions between two parties to read or alter the "
        "traffic flowing between them. On a control network, where protocols "
        "often carry no authentication, this allows both eavesdropping and "
        "tampering with commands and readings in transit.",
    ),
    "ics-attack:T0831": (
        "Manipulation of Control",
        "ATT&CK ICS · Impair Process Control",
        "An attacker changes the commands reaching a process so it behaves "
        "the way they choose rather than the way the operator intends — "
        "opening a valve, changing a setpoint, driving an actuator. Cited for "
        "control-plane writes that did not originate from an established, "
        "authorised master.",
    ),
    "ics-attack:T0836": (
        "Modify Parameter",
        "ATT&CK ICS · Impair Process Control",
        "A device's configuration or operating parameters are altered — a "
        "threshold, a calibration, a setpoint — so it operates outside safe "
        "bounds while still appearing to function. Cited when a write "
        "targets a parameter register rather than a normal control coil.",
    ),
    "ics-attack:T0842": (
        "Network Sniffing",
        "ATT&CK ICS · Collection",
        "An attacker passively captures control-network traffic to learn the "
        "layout, the devices, and the normal command patterns before acting. "
        "It leaves little trace itself; it is cited as the reconnaissance "
        "that precedes an active manipulation.",
    ),
    "ics-attack:T0846": (
        "Remote System Discovery",
        "ATT&CK ICS · Discovery",
        "An attacker enumerates the devices on a control network — their "
        "addresses, unit identifiers and roles — to map what is present "
        "before choosing a target. The signature is a sweep across many "
        "device or unit ids from one source, which on a one-master network "
        "stands out sharply.",
    ),
    "ics-attack:T0855": (
        "Unauthorized Command Message",
        "ATT&CK ICS · Impair Process Control",
        "A control command is sent by a party that has no business sending "
        "it — a device that is not the established master issuing a write or "
        "an action. Because many ICS protocols authenticate nothing, the "
        "message is obeyed; the tool cites this when a command comes from an "
        "unestablished source.",
    ),
    "ics-attack:T0856": (
        "Spoof Reporting Message",
        "ATT&CK ICS · Impair Process Control",
        "False readings are fed back toward the operator so the process "
        "appears normal while it is being manipulated — the digital form of "
        "pinning a gauge. Cited when reported values or reporting sources are "
        "inconsistent with the devices that should be producing them.",
    ),
    "ics-attack:T0878": (
        "Alarm Suppression",
        "ATT&CK ICS · Inhibit Response Function",
        "Alarms that would warn the operator of an unsafe condition are "
        "suppressed or disabled so a developing problem goes unnoticed. Cited "
        "when expected alarm or unsolicited-reporting traffic stops or is "
        "turned off.",
    ),
    "ics-attack:T0889": (
        "Modify Program",
        "ATT&CK ICS · Impair Process Control",
        "The control logic running on a device — the ladder logic or program "
        "in a PLC — is altered, which is among the most serious ICS attacks "
        "because it changes how the device will behave on its own, with no "
        "further traffic from the attacker. Cited for program-download or "
        "logic-modification activity.",
    ),
    # ---- CWE weaknesses --------------------------------------------------
    "cwe:200": (
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE · Information Disclosure",
        "Data that should be restricted is made available to someone who "
        "should not have it — through a response body, a header, an error, or "
        "a misconfiguration. The umbrella weakness under many of the more "
        "specific disclosure findings below.",
    ),
    "cwe:203": (
        "Observable Discrepancy",
        "CWE · Information Disclosure",
        "A system behaves observably differently for two inputs that it "
        "should treat alike, and that difference leaks information. The "
        "response-time oracle is the classic case: a login that answers "
        "faster for an unknown username than a known one tells an attacker "
        "which accounts exist without any valid password.",
    ),
    "cwe:208": (
        "Observable Timing Discrepancy",
        "CWE · Information Disclosure",
        "The specific timing form of the discrepancy above: the time a system "
        "takes to respond depends on secret or sensitive state, so measuring "
        "it reveals that state. Cited for the user-enumeration timing oracle, "
        "which this tool finds from response-time clustering alone.",
    ),
    "cwe:306": (
        "Missing Authentication for Critical Function",
        "CWE · Access Control",
        "A sensitive action can be performed with no authentication at all. "
        "It is endemic in industrial protocols, where a controller will act "
        "on a command simply because it arrived — which is why it accompanies "
        "the ICS unauthorised-command findings.",
    ),
    "cwe:312": (
        "Cleartext Storage of Sensitive Information",
        "CWE · Credential Exposure",
        "Sensitive data is held or transmitted without encryption where it "
        "can be observed. Cited when a credential, token or personal datum is "
        "seen travelling in cleartext — the thing this tool is built to catch "
        "and then mask so the report itself does not repeat the exposure.",
    ),
    "cwe:330": (
        "Use of Insufficiently Random Values",
        "CWE · Cryptographic Weakness",
        "A value that must be unpredictable — a session id, a token — is "
        "generated with too little randomness, so an attacker can guess or "
        "predict it. Cited by the token-quality analysis, which scores only "
        "what few samples can prove, never an estimate of the generator's "
        "strength.",
    ),
    "cwe:331": (
        "Insufficient Entropy",
        "CWE · Cryptographic Weakness",
        "The narrower case of too little randomness specifically: a token "
        "draws from so small a space that its values cluster in a tiny "
        "fraction of what its length implies. Provable from samples — a "
        "position that never varies, a keyspace barely used — which is what "
        "the tool reports rather than a bit-count it cannot justify.",
    ),
    "cwe:340": (
        "Generation of Predictable Numbers or Identifiers",
        "CWE · Cryptographic Weakness",
        "Identifiers follow a pattern — a counter, a timestamp, a sequence — "
        "so that knowing one lets an attacker derive others. Cited when the "
        "token analysis finds a decodable structure such as an embedded, "
        "advancing timestamp at a fixed offset across samples.",
    ),
    "cwe:345": (
        "Insufficient Verification of Data Authenticity",
        "CWE · Trust and Verification",
        "A system accepts data without properly checking that it is genuine "
        "and unaltered, letting a forged or replayed message be treated as "
        "trustworthy. The general weakness behind the signature-verification "
        "and origin-validation findings.",
    ),
    "cwe:346": (
        "Origin Validation Error",
        "CWE · Trust and Verification",
        "A server fails to correctly check where a request came from, so it "
        "honours requests from origins it should refuse. Cited for CORS "
        "misconfigurations that reflect an arbitrary requesting origin back "
        "as allowed.",
    ),
    "cwe:347": (
        "Improper Verification of Cryptographic Signature",
        "CWE · Cryptographic Weakness",
        "A signature is not verified correctly, so a forged token passes as "
        "authentic. The archetype is JWT algorithm confusion — a server that "
        "accepts a symmetric-signed token where it should require an "
        "asymmetric one, letting an attacker sign their own tokens with a "
        "public key.",
    ),
    "cwe:352": (
        "Cross-Site Request Forgery (CSRF)",
        "CWE · Web Session",
        "A site cannot tell an action the user intended from one a hostile "
        "page made the user's browser perform while logged in. Cited when "
        "cookie SameSite protections — the main defence — are absent.",
    ),
    "cwe:359": (
        "Exposure of Private Personal Information",
        "CWE · Information Disclosure",
        "Personal information about an individual is disclosed to a party "
        "that should not receive it. Cited when a user identifier or personal "
        "datum is seen reaching a third party distinct from the one that "
        "issued it.",
    ),
    "cwe:384": (
        "Session Fixation",
        "CWE · Web Session",
        "A session identifier does not change when a user authenticates, so a "
        "value an attacker planted beforehand still identifies the "
        "now-authenticated session. Cited when the same identifier is seen "
        "before and after a login that appears to have succeeded.",
    ),
    "cwe:522": (
        "Insufficiently Protected Credentials",
        "CWE · Credential Exposure",
        "Credentials are handled in a way that leaves them exposed — in a "
        "URL, an unprotected cookie, a cleartext field. Cited whenever a "
        "credential is seen somewhere it can be captured in transit.",
    ),
    "cwe:532": (
        "Insertion of Sensitive Information into Log File",
        "CWE · Credential Exposure",
        "Secrets end up written into logs, where they live far longer and "
        "reach far more readers than intended. Relevant here because a "
        "findings file is a kind of log, which is why this tool masks "
        "credentials by default before anything is written.",
    ),
    "cwe:540": (
        "Inclusion of Sensitive Information in Source Code",
        "CWE · Credential Exposure",
        "Secrets are embedded in source, script or configuration that is "
        "served to clients — an API key in a JavaScript bundle, a token in a "
        "config response. Cited when the response-body scan finds a secret "
        "shipped to the browser.",
    ),
    "cwe:565": (
        "Reliance on Cookies without Validation and Integrity Checking",
        "CWE · Web Session",
        "An application trusts a cookie's contents without verifying they "
        "have not been tampered with, so a user can edit a cookie to change "
        "how the server treats them. Cited for session mechanisms that rest "
        "on an unprotected cookie.",
    ),
    "cwe:598": (
        "Use of GET Request Method With Sensitive Query Strings",
        "CWE · Credential Exposure",
        "Sensitive data is placed in a URL query string, where it is logged "
        "by servers and proxies, kept in browser history, and sent in the "
        "Referer header to other sites. Cited when a credential or token is "
        "seen in a URL rather than a body or header.",
    ),
    "cwe:601": (
        "URL Redirection to Untrusted Site (Open Redirect)",
        "CWE · Web Session",
        "A site redirects to a destination taken from user-controlled input "
        "without restricting it, so an attacker can craft a trusted-looking "
        "link that bounces the victim to a hostile page — a staple of "
        "phishing and of OAuth token theft.",
    ),
    "cwe:613": (
        "Insufficient Session Expiration",
        "CWE · Web Session",
        "Sessions or tokens remain valid for too long, or survive events that "
        "should end them, widening the window in which a stolen one still "
        "works. Cited by the refresh-token analysis when a token keeps "
        "working past the point it should have been invalidated.",
    ),
    "cwe:614": (
        "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "CWE · Web Session",
        "A session cookie lacks the Secure flag, so the browser will send it "
        "over plain HTTP, where it can be captured — defeating the point of "
        "serving the site over HTTPS. Cited when a session cookie is missing "
        "Secure.",
    ),
    "cwe:942": (
        "Permissive Cross-domain Policy with Untrusted Domains",
        "CWE · Trust and Verification",
        "A cross-domain policy is so permissive that untrusted sites are "
        "allowed to make and read authenticated requests. The CORS-specific "
        "severe case: reflecting any origin as allowed while also permitting "
        "credentials.",
    ),
    "cwe:1004": (
        "Sensitive Cookie Without 'HttpOnly' Flag",
        "CWE · Web Session",
        "A session cookie lacks HttpOnly, so scripts running in the page can "
        "read it — which turns any cross-site-scripting flaw into session "
        "theft. Cited when a session cookie is missing HttpOnly.",
    ),
    "cwe:1275": (
        "Sensitive Cookie with Improper SameSite Attribute",
        "CWE · Web Session",
        "A session cookie's SameSite attribute is missing or too loose, so "
        "the browser attaches it to cross-site requests — the condition "
        "cross-site request forgery depends on. Cited when a session cookie "
        "has no adequate SameSite.",
    ),
}


def label_ref(ref: str) -> str:
    """A human label for a raw ref id, known or not.

    `attack:T1071.001` -> `ATT&CK T1071.001`, `ics-attack:T0855` -> `ATT&CK
    ICS T0855`, `cwe:306` -> `CWE-306`. An unrecognised namespace is shown
    verbatim rather than guessed at.
    """
    if ref.startswith("ics-attack:"):
        return "ATT&CK ICS " + ref.split(":", 1)[1]
    if ref.startswith("attack:"):
        return "ATT&CK " + ref.split(":", 1)[1]
    if ref.startswith("cwe:"):
        return "CWE-" + ref.split(":", 1)[1]
    return ref


def describe_ref(ref: str):
    """(title, category, body) for a ref, or None if this file does not cover it."""
    return REFERENCES.get(ref)


def _ordered_unique(refs: Iterable[str]) -> List[str]:
    """Refs in first-seen order, de-duplicated — the order the findings cited
    them, which keeps the explanations next to where the reader met the code."""
    seen = set()
    out: List[str] = []
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            out.append(ref)
    return out


def _wrap(text: str, width: int = 70, indent: str = "      ") -> List[str]:
    words = text.split()
    lines: List[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent + word
        else:
            current = f"{current} {word}" if current.strip() else indent + word
    if current.strip():
        lines.append(current.rstrip())
    return lines


def reference_section(refs: Iterable[str], width: int = 70) -> List[str]:
    """The section defining the ATT&CK / CWE codes the findings cited.

    Returns [] when no refs were given, so a capture that raised no findings —
    or whose findings carried no refs — prints no header.
    """
    ordered = _ordered_unique(refs)
    if not ordered:
        return []

    out: List[str] = ["", "── TECHNIQUES & WEAKNESSES REFERENCED " + "─" * 31]
    out += _wrap(
        "Plain-language descriptions of the ATT&CK techniques and CWE "
        "weaknesses the findings above cited. These describe the general "
        "technique or weakness — not a verdict about this capture; the "
        "evidence for each finding is printed with the finding. No model "
        "writes any of this.",
        width=width, indent="  ",
    )
    for ref in ordered:
        info = describe_ref(ref)
        out.append("")
        if info is None:
            out.append(f"  {label_ref(ref)}")
            out += _wrap("No local description for this reference. Look it up "
                         f"by its identifier ({ref}).", width=width)
            continue
        title, category, body = info
        out.append(f"  {label_ref(ref)} — {title}")
        out += _wrap(category, width=width)
        out += _wrap(body, width=width)
    return out
