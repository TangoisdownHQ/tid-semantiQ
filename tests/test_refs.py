"""The reference explainer — the codes a finding cites, in plain language.

The important test here is `test_every_cited_ref_has_a_description`: it walks
the ontologies for every ref any rule can emit and asserts this file covers
it. That is what keeps the promise honest over time — a new rule that cites a
code the reader cannot expand fails the suite rather than shipping a finding
that ends in an unexplained identifier.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from out.refs import (
    REFERENCES,
    describe_ref,
    label_ref,
    reference_section,
)


_REF_RE = re.compile(r"(?:ics-attack|attack|cwe):[A-Za-z0-9.]+")


def _refs_cited_by_the_ontologies() -> set:
    """Every ref literal that appears in ontology/*.py — the full set a run
    can print. Read from source so the test cannot drift from the rules."""
    cited = set()
    for path in (ROOT / "ontology").glob("*.py"):
        for match in _REF_RE.findall(path.read_text()):
            cited.add(match)
    return cited


# --------------------------------------------------------------------------
# completeness: nothing a finding cites is left unexplained
# --------------------------------------------------------------------------


def test_every_cited_ref_has_a_description():
    cited = _refs_cited_by_the_ontologies()
    assert cited, "found no refs in ontology/ — did the grep pattern break?"
    missing = sorted(r for r in cited if r not in REFERENCES)
    assert not missing, f"refs cited by rules but not described: {missing}"


def test_no_orphan_descriptions():
    """A description for a code no rule cites is dead weight and usually a
    typo'd key. Every entry must correspond to something the rules emit."""
    cited = _refs_cited_by_the_ontologies()
    orphans = sorted(r for r in REFERENCES if r not in cited)
    assert not orphans, f"described but never cited: {orphans}"


def test_every_entry_is_well_formed_and_extensive():
    for ref, value in REFERENCES.items():
        assert ref.split(":", 1)[0] in ("attack", "ics-attack", "cwe"), ref
        title, category, body = value
        assert title.strip(), f"{ref}: blank title"
        assert category.strip(), f"{ref}: blank category"
        assert len(body) >= 150, f"{ref}: description too thin ({len(body)})"


# --------------------------------------------------------------------------
# labels
# --------------------------------------------------------------------------


def test_labels_render_each_namespace():
    assert label_ref("attack:T1071.001") == "ATT&CK T1071.001"
    assert label_ref("ics-attack:T0855") == "ATT&CK ICS T0855"
    assert label_ref("cwe:306") == "CWE-306"
    # ics- must win over the attack- prefix it contains.
    assert "ICS" in label_ref("ics-attack:T0814")


def test_unknown_namespace_is_shown_verbatim():
    assert label_ref("capec:98") == "capec:98"
    assert describe_ref("capec:98") is None


# --------------------------------------------------------------------------
# the section
# --------------------------------------------------------------------------


def test_no_refs_yields_no_section():
    assert reference_section([]) == []
    assert reference_section(iter(())) == []


def test_section_defines_only_the_refs_given_and_dedups():
    section = "\n".join(reference_section(
        ["attack:T1071.004", "attack:T1071.004", "cwe:384"]))
    assert "TECHNIQUES & WEAKNESSES REFERENCED" in section
    assert "ATT&CK T1071.004" in section
    assert "CWE-384 — Session Fixation" in section
    # a ref that was not passed must not be defined
    assert "T1573" not in section
    # deduplicated: the DNS technique heading appears once, not twice
    assert section.count("ATT&CK T1071.004 —") == 1


def test_section_preserves_first_seen_order():
    section = reference_section(["cwe:384", "attack:T1573"])
    headings = [ln for ln in section if ln.startswith("  CWE-")
                or ln.startswith("  ATT&CK")]
    assert headings[0].startswith("  CWE-384")
    assert headings[1].startswith("  ATT&CK T1573")


def test_unknown_ref_is_listed_not_dropped():
    """Honesty: a code with no local description is still shown, flagged as
    such, rather than silently omitted."""
    section = "\n".join(reference_section(["capec:98"]))
    assert "capec:98" in section
    assert "No local description" in section


# --------------------------------------------------------------------------
# a couple of content spot-checks, so a wrong mapping is caught
# --------------------------------------------------------------------------


def test_known_codes_map_to_the_right_concept():
    assert describe_ref("cwe:384")[0] == "Session Fixation"
    assert describe_ref("cwe:347")[0] == \
        "Improper Verification of Cryptographic Signature"
    assert describe_ref("attack:T1071.004")[0] == \
        "Application Layer Protocol: DNS"
    assert describe_ref("ics-attack:T0855")[0] == "Unauthorized Command Message"


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
