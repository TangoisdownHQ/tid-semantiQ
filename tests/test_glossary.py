"""The glossary — the report explaining its own vocabulary.

The feature's whole value is that it is *contextual and honest*: it defines a
term only when the report actually used it, it never implies a definition is a
finding, and — like everything else in the narration — it is written by code
and cannot drift. The tests below pin exactly those properties, plus the two
failure modes a self-scanning glossary invites: defining everything because
its own definitions triggered each other, and pointing a reader at a "see
also" entry that was never printed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.model import Channel, Direction, Entity, Locus, Observation, Series
from out.glossary import GLOSSARY, glossary_section, terms_in
from out.narrate import narrate


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def _dns_series(zone: str, qnames, rcodes,
                client: str = "10.0.0.5", server: str = "10.0.0.1") -> Series:
    """A DNS channel with one query and one response per name.

    Enough to drive a real narration whose text contains DNS vocabulary
    (`DNS`, `lookups`, `NXDOMAIN`, a resolver), so the wiring tests run
    against the narrator's genuine output rather than a hand-written string.
    """
    channel = Channel(
        domain="dns",
        dims={"proto": "udp", "qtype": "A", "zone": zone},
        initiator=Entity("ip", client),
        responder=Entity("ip", server),
    )
    observations = []
    ts = 1_700_000_000.0
    for index, (qname, rcode) in enumerate(zip(qnames, rcodes)):
        observations.append(Observation(
            ts=ts + index, channel=channel, direction=Direction.EGRESS,
            size=40, kind="dns_query",
            attrs={"qname": qname, "qtype": "A", "encrypted": False},
            locus=Locus(source="t.pcap", frames=(index * 2 + 1,)),
        ))
        if rcode is not None:
            observations.append(Observation(
                ts=ts + index + 0.01, channel=channel,
                direction=Direction.INGRESS, size=90, kind="dns_response",
                attrs={"qname": qname, "qtype": "A", "encrypted": False,
                       "rcode": "3" if rcode == "NXDOMAIN" else "0",
                       "rcode_name": rcode},
                locus=Locus(source="t.pcap", frames=(index * 2 + 2,)),
            ))
    return Series(channel, observations)


def _term(name: str):
    for t in GLOSSARY:
        if t.term == name:
            return t
    raise AssertionError(f"no glossary entry named {name!r}")


def _flat(text: str) -> str:
    """Collapse whitespace before asserting on a phrase.

    The definitions wrap at 70 columns, so a phrase assertion is otherwise an
    assertion about where the wrap happened to fall — assert on the words,
    not the layout.
    """
    return " ".join(text.split())


# --------------------------------------------------------------------------
# detection: a term is defined iff it appeared
# --------------------------------------------------------------------------


def test_a_term_that_appeared_is_detected():
    found = {t.term for _, t in terms_in("90% of answered DNS lookups returned NXDOMAIN.")}
    assert "NXDOMAIN" in found, found
    assert "DNS" in found, found


def test_a_term_that_did_not_appear_is_not_defined():
    """The contextual property: a DNS-only text must not drag in TLS entries."""
    text = "A host looked up names; most returned NXDOMAIN from the resolver."
    found = {t.term for _, t in terms_in(text)}
    assert "NXDOMAIN" in found
    assert "TLS" not in found, found
    assert "certificate" not in found, found
    assert "self-signed" not in found, found


def test_empty_narration_produces_no_section():
    assert glossary_section("") == []
    assert glossary_section("   \n  \n") == []


def test_section_has_a_header_a_disclaimer_and_the_definition():
    section = _flat("\n".join(glossary_section("DNS lookups returned NXDOMAIN")))
    assert "TERMS IN THIS REPORT" in section
    # The disclaimer that keeps a definition from reading as a finding.
    assert "not findings" in section
    assert "NXDOMAIN" in section
    # The body, not merely the heading: a distinctive phrase from the long text.
    assert "does not exist" in section


# --------------------------------------------------------------------------
# ordering: the glossary follows the reader down the page
# --------------------------------------------------------------------------


def test_terms_print_in_order_of_first_appearance():
    # "beacon" is written before "DNS" here, so it must be defined first even
    # though DNS comes earlier in the GLOSSARY list.
    text = "A beacon was seen. Later, DNS lookups failed."
    order = [t.term for _, t in terms_in(text)]
    assert order.index("beacon") < order.index("DNS"), order


# --------------------------------------------------------------------------
# the two failure modes a self-scanning glossary invites
# --------------------------------------------------------------------------


def test_definitions_do_not_trigger_each_other():
    """A one-term capture must define one term, not the whole dictionary.

    If the section scanned its own definitions, the entry for `beacon` (whose
    text mentions timing, control servers and confidence) would pull in half
    the vocabulary. The scan must see the report body only.
    """
    found = terms_in("A self-signed certificate was presented.")
    names = {t.term for _, t in found}
    # certificate and self-signed appeared in the text; the many terms their
    # *definitions* mention (TLS 1.3, SNI, periodicity, ...) did not.
    assert "self-signed" in names and "certificate" in names
    assert "periodicity" not in names, names
    assert "beacon" not in names, names


def test_see_also_never_points_at_an_undefined_term():
    """self-signed's see-list names `certificate`; with no certificate term
    triggered, its see-also line must be dropped entirely rather than point a
    reader at an entry that was never printed. (The word `certificate` still
    appears inside self-signed's own definition — that is fine; what must not
    appear is a `see also:` cross-reference to the absent entry.)"""
    lines = glossary_section("The endpoint used a self-signed key.")
    section = _flat("\n".join(lines))
    assert "self-signed" in section
    assert "see also:" not in section, section


def test_see_also_is_kept_when_the_referent_is_present():
    text = "A beacon with high periodicity and little jitter was measured."
    section = "\n".join(glossary_section(text))
    assert "see also:" in section
    # beacon references periodicity and jitter, both present here.
    assert "periodicity" in section and "jitter" in section


# --------------------------------------------------------------------------
# data integrity of the vocabulary itself
# --------------------------------------------------------------------------


def test_every_entry_is_well_formed_and_extensive():
    seen = set()
    for t in GLOSSARY:
        assert t.term and t.term not in seen, f"duplicate/blank term {t.term!r}"
        seen.add(t.term)
        assert t.triggers, f"{t.term} has no triggers"
        assert t.short.strip(), f"{t.term} has no short gloss"
        # "extensive" is the brief; a one-liner would not meet it.
        assert len(t.long) >= 200, f"{t.term} definition is too thin ({len(t.long)})"
        assert len(t.long) > len(t.short), f"{t.term} long is not longer than short"


def test_every_trigger_matches_something_it_should():
    """A trigger that fires nowhere in its own entry's prose is almost always a
    typo'd pattern — a trailing-space, a wrong anchor, a mis-escaped class. So
    every entry must be reachable by at least one of its triggers matching the
    entry's own name, gloss, or definition. (The display name alone is not
    enough: a term like "secret masking" is detected in narration by the word
    "masked", which its title does not contain.)"""
    for t in GLOSSARY:
        probe = f"{t.term} {t.short} {t.long}"
        assert t.first_match(probe) is not None, \
            f"{t.term}: no trigger fires anywhere in its own entry"


# --------------------------------------------------------------------------
# wiring into the narrator
# --------------------------------------------------------------------------


def _dns_narration(**kw) -> str:
    series = [_dns_series(
        "x.test",
        ["a.x.test", "b.x.test", "c.x.test", "d.x.test"],
        ["NXDOMAIN", "NXDOMAIN", None, "NXDOMAIN"],
    )]
    return narrate(series, [], source_name="t.pcap", **kw)


def test_narrator_omits_glossary_unless_asked():
    assert "TERMS IN THIS REPORT" not in _dns_narration()
    assert "TERMS IN THIS REPORT" not in _dns_narration(glossary=False)


def test_narrator_appends_glossary_as_a_pure_suffix():
    """Enabling the glossary must only *add* to the report, never rewrite it —
    so the operator sees the identical narration with definitions beneath."""
    off = _dns_narration(glossary=False)
    on = _dns_narration(glossary=True)
    assert on.startswith(off), "glossary changed the body above it"
    assert len(on) > len(off)
    assert "TERMS IN THIS REPORT" in on


def test_glossary_defines_the_terms_a_dns_capture_actually_used():
    on = _dns_narration(glossary=True)
    tail = _flat(on.split("TERMS IN THIS REPORT", 1)[1])
    assert "NXDOMAIN" in tail
    assert "does not exist" in tail           # NXDOMAIN's definition body
    # and it must not have invented a TLS section for a capture with no TLS.
    assert "self-signed" not in tail, tail


# --------------------------------------------------------------------------
# streaming: the glossary extended to the windowed report
# --------------------------------------------------------------------------

# A fragment of the text the streaming path actually prints — the warm-up,
# an advisory, and the cross-window summary. The streaming vocabulary lives
# here and nowhere in a batch narration.
_STREAM_OUTPUT = (
    "streaming: 171 window(s) of 60s, emitted every 20s. The baseline is "
    "not written in this mode — warm it with a batch pass.\n"
    "ADVICE  the windower shed load — 8 late observations arrived older than "
    "the window and were not analysed.\n"
    "across 171 windows:\n"
    "  dns.tunnel.high_cardinality_zone   4/171 windows  persistent\n"
)


def test_streaming_vocabulary_is_defined_on_streaming_output():
    found = {t.term for _, t in terms_in(_STREAM_OUTPUT)}
    assert "sliding window" in found, found
    assert "persistent / TRANSIENT finding" in found, found
    assert "load shedding" in found, found
    # and the shared term the warm-up mentions
    assert "baseline" in found, found


def test_streaming_vocabulary_stays_out_of_a_batch_report():
    """The streaming terms key off words a file analysis never prints, so a
    batch narration must not drag them in."""
    batch_like = (
        "A single host originated every exchange, reaching 117 addresses. "
        "12% of exchanges were encrypted. 90% of answered DNS lookups failed "
        "(NXDOMAIN). 7 of 638 TCP connections did not establish."
    )
    found = {t.term for _, t in terms_in(batch_like)}
    assert "sliding window" not in found, found
    assert "persistent / TRANSIENT finding" not in found, found
    assert "load shedding" not in found, found


def test_streaming_run_appends_the_glossary():
    """End to end: a windowed run with --glossary prints the TERMS section and
    defines the windowing vocabulary the run itself emitted."""
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    with tempfile.TemporaryDirectory() as d:
        pcap = Path(d) / "suspect.pcap"
        made = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "make_test_pcap.py"),
             str(pcap), "--profile", "suspect"],
            env=env, capture_output=True, text=True,
        )
        assert pcap.exists(), made.stderr
        run = subprocess.run(
            [sys.executable, str(ROOT / "semantiq.py"), "read", str(pcap),
             "--stream", "--window", "60", "--emit-every", "20",
             "--glossary", "--no-inventory"],
            env=env, capture_output=True, text=True,
        )
    assert run.returncode == 0, run.stderr
    tail = _flat(run.stdout.split("TERMS IN THIS REPORT", 1)[-1])
    assert "TERMS IN THIS REPORT" in run.stdout, run.stdout[-500:]
    assert "sliding window" in tail
    # the extensive body, not merely the heading
    assert "a live link never ends" in tail


def test_streaming_run_omits_glossary_without_the_flag():
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    with tempfile.TemporaryDirectory() as d:
        pcap = Path(d) / "suspect.pcap"
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "make_test_pcap.py"),
             str(pcap), "--profile", "suspect"],
            env=env, capture_output=True, text=True,
        )
        run = subprocess.run(
            [sys.executable, str(ROOT / "semantiq.py"), "read", str(pcap),
             "--stream", "--window", "60", "--emit-every", "20",
             "--no-inventory"],
            env=env, capture_output=True, text=True,
        )
    assert run.returncode == 0, run.stderr
    assert "TERMS IN THIS REPORT" not in run.stdout


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
