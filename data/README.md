# Vendored data

## `public_suffix_list.dat`

The Mozilla Public Suffix List, from <https://publicsuffix.org/list/>.

**Licensed MPL-2.0**, separately from the rest of this repository. The file is
vendored **unmodified**, with its licence header intact, which is what MPL-2.0
requires: it is file-level copyleft, so this file stays MPL and the code around
it is unaffected. Do not edit it — edits would make this a modified MPL work
and oblige you to publish the result.

Snapshot taken 2026-10-23 from the 2025-03-12 release: 15744 lines,
9565 normal rules, 166 wildcard rules, 10 exception rules.

### It goes stale

New suffixes are added continually, and a missing rule silently degrades
`core/suffixes.py` to the parent-domain answer for that suffix. Refresh with:

    curl -o data/public_suffix_list.dat \
         https://publicsuffix.org/list/public_suffix_list.dat

Pull it only from that URL — the list's own header says other mirrors are not
supported.

`core/suffixes.py` reports the loaded rule counts via `describe()` so a stale
or truncated file is visible rather than silent.
