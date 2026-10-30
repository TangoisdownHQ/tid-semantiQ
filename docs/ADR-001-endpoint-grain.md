# ADR-001 — Per-endpoint analysis grain

**Status:** accepted; all items implemented · **Date:** 2026-10-23

## The question

Two planned analyses — response-time differentials as a user-enumeration
oracle, and per-endpoint behavioural statistics — need to look at one
endpoint at a time. The http channel is currently keyed on
`{scheme, host}`, so every endpoint on a host lands in one `Series` and
per-endpoint statistics are meaningless.

The README called this "the one architectural change still owed" and assumed
the fix was endpoint-level `dims`. **That assumption was wrong**, and this
document is mostly about why.

## What endpoint-level dims would actually cost

Measured, not estimated. A synthetic HAR of one host, twelve endpoints, where
every response repeats exactly two systemic defects — a session cookie with
no flags and a reflected credentialed CORS header:

| channel grain | channels | findings |
|---|---|---|
| `{scheme, host}` (current) | 1 | **2** |
| `{scheme, host, endpoint}` | 12 | **24** |

```
host dims (current):            endpoint dims (Option A):
   1 x cors.credentialed...        12 x cors.credentialed...
   1 x cookie_takeover_chain       12 x cookie_takeover_chain
```

Same two defects, twelve times each. The multiplication factor is the
endpoint count, so a 200-endpoint application reports one misconfigured
cookie 200 times.

Folding does not help: `fold()` collapses repeats *within* a channel, and
under endpoint dims each endpoint is a different channel. Suppressing it
afterwards would mean teaching the scorer that some findings are
host-scoped and some are endpoint-scoped — which is the distinction `dims`
was supposed to encode in the first place.

Two further costs:

- **`rarity` changes meaning.** Prevalence would become "what fraction of
  hosts call this exact endpoint", which is near-zero for almost every
  endpoint and would make the rarity gate fire everywhere. Host-level
  prevalence is the question with a useful answer.
- **Host-level cardinality questions break.** `Fanout(attr="path")` needs
  many paths in one series; with one path per channel it answers 1 forever.

That last one turns out not to matter, which is its own finding: **no rule
references `fanout.path`.** It is in the http primitive stack, computed on
every run, and discarded. It should be removed regardless of this decision.

## What actually needs the finer grain

Exactly one analyzer: the response-time differential. Re-deriving the list
honestly:

| Planned analysis | Needs endpoint grain? |
|---|---|
| Response-time differential (enumeration oracle) | **yes** |
| Per-endpoint size/cadence statistics | yes, same mechanism |
| Session fixation across a login boundary | **no** — needs ordering, not grain |
| Endpoint & parameter inventory | **no** — already reads `attrs`, not dims |
| Third-party flow map | no — correlators group by host themselves |
| Cross-host credential correlation | no — already derives host from dims |

So the driver is one primitive, not the pipeline. Changing the channel
contract for every analyzer to serve one of them is the wrong trade.

## Options

**A — endpoint-level `dims`.** Rejected on the measurement above. Also
changes `rarity` semantics and breaks host-level cardinality.

**B — `Series.group_by()`.** Keep `{scheme, host}`; give `Series` the
ability to yield sub-series keyed by an attribute or a key function. A
primitive that wants per-endpoint statistics asks for them; everything else
is untouched.

This is not a workaround. `Series.filter(direction=, kind=)` already exists
for exactly this shape of question — looking at a subset of a channel.
`group_by` generalises it. `dims` continues to set the *coarsest* grain at
which findings are attributed; `group_by` lets a specific analyzer ask finer
questions inside that grain. Invariant I1 holds: primitives still consume a
`Series` and nothing else.

Cost: a per-endpoint finding attributes to the host channel and must name the
endpoint in its `features`/`facts` rather than in the channel. Inspections
already do this (`endpoint` fact), so it matches existing practice.

**C — parent/child channels.** A second channel axis with scope
inheritance. Solves the attribution question properly and costs a rewrite of
the scorer, the baseline keys, and every output. Not justified by one
analyzer.

## Decision

**Option B.** Additive, no contract change, existing tests unaffected, and
reversible if the oracle turns out not to work.

### Work items

1. **`Series.group_by(key)`** — DONE. `key` as an attr name or a callable;
   returns `Dict[str, Series]` sharing the channel. Missing keys excluded,
   not bucketed.

2. **Pairing and timing into `attrs`.** This is far cheaper than expected:
   Wireshark already does both.

   ```
   http.request_in   frame number of the matching request
   http.time         seconds since that request
   ```

   Verified present on the TLS fixture — `frame=13 stream=0
   time=0.000063000 req_in=11`. So no pairing logic is needed, and
   crucially it is correct across HTTP keep-alive, where several
   transactions share one `tcp.stream` and naive stream-based pairing would
   mis-associate them. For HTTP/2, `http2.streamid` exists.

   DONE. Both paths now expose `txn` and `elapsed_s`, with `stream` kept and
   documented as a CONNECTION id.
   `test_keepalive_proves_stream_is_not_a_transaction_id` builds three
   transactions over one TLS connection and shows `group_by("stream")`
   returning 1 group against `group_by("txn")` returning 3 — the keep-alive
   case that would have broken stream-based pairing.

3. **`ResponseTimeDifferential` primitive** — DONE, and it did not end up
   partitioning by outcome at all. See "What the oracle became" below.

4. **Remove `Fanout(attr="path")`** from the http primitive stack — DONE.

5. **Session fixation** — DONE, as `correlators/sessions.py`. Needed none of
   the above, as predicted: it wants request ORDERING, not finer grain. It
   did use `group_by("txn")` to attach a response status to the request that
   earned it, which is how a failed login is excluded as a boundary.

## The oracle is the risky part

Timing is noisy in a way cookie flags are not, so this needs the same
negative-tests-first discipline that caught two false positives in the
token-quality work.

**Resolved — the partition question was the wrong question.**

Every candidate partition fails on the case that matters most. Username
enumeration returns the SAME status and the SAME body for valid and invalid
users; that is what a well-written error message is for. Status carries no
signal, body carries no signal, and the distinguishing input is in the
REQUEST, which the tool cannot evaluate.

So the implementation does not partition. It asks whether the latencies for
one endpoint form two SEPARATED CLUSTERS — which needs no partition key — and
then reports whether those clusters happen to align with response status:

    aligned      fast 401s, slow 200s — visible without timing, LOW
    not aligned  two clusters, identical statuses — a HIDDEN oracle, MEDIUM

The second is the finding worth having, and it is exactly what a
partition-by-outcome design cannot see.

**What the oracle became**, and the two false positives found on the way.

*`separation / within_spread` is not a bimodality test.* Splitting any
unimodal sample in half roughly halves the within-half MAD, so the ratio is
inflated by the act of splitting. Measured over 3000 trials per shape,
unimodal noise produced sep/spread between 2.9 and 8.8 — overlapping anything
that would catch real signal. The fix is to measure the VOID between the
clusters: the gap at the split against the typical gap between consecutive
samples. That reads 1-8 on noise against 87-102 on a genuine 80ms split.

*Gap alone is not enough either.* On heavy-tailed lognormal latency — the
realistic shape — the long right tail manufactures large gaps. `gap >= 8`
alone false-fired on 25.7% of samples at n=25, and got WORSE with more data.
Both gates are therefore required, measured at:

    shape              n=10    n=14    n=25
    uniform           1.17%   0.23%   0.00%
    normal            0.40%   0.20%   0.00%
    lognormal         0.50%   0.23%   0.07%
    lognormal heavy   1.60%   1.10%   1.13%
    true positive    98.40%  99.40% 100.00%

Also implemented: a multiplicity correction, because reporting the worst of k
endpoints multiplies the per-endpoint false-positive rate by roughly k; a
5ms absolute floor on effect size, because an oracle smaller than ordinary
internet jitter cannot be measured remotely and so is not exploitable; and
warm-up exclusion.

*Warm-up mattered more than expected.* A capture with no oracle but three
connection warm-ups produced a **0.88-confidence finding with a 387ms
separation** — an "oracle" composed entirely of TLS handshakes. One spike
cannot do it (`MIN_PER_CLUSTER` is 3); three can, and three is what a browser
opening several connections to a host looks like. Pinned by
`test_warm_up_exclusion_prevents_a_false_positive`, which also asserts the
fixture still reproduces the artefact so the test cannot quietly stop
testing anything.

**The honesty constraint.** A timing difference in a capture is not proof of
an oracle. Caching, connection reuse, backend load and routing all produce
one. The finding must say so and name the confirmation step (replay with
controlled inputs), exactly as `web.cors` says "not probed — confirm by
replaying with a different Origin".

Risk if this goes wrong: a plausible-looking CRITICAL that cannot be
reproduced. That is worse than no analyzer, so the negative tests were
written first — and caught both false positives above. The finding is capped
at MEDIUM for the same reason: the statistics can be very tight and still
describe caching, connection reuse or backend load, and the output says
"NOT PROVEN" with the replay step named.

## What would change this decision

Endpoint-level dims become right if the tool ever needs **per-endpoint
rarity against a fleet baseline** — "no other host has ever called this
endpoint". That is a SOC question rather than a bug-bounty one, and it would
need the baseline keyed at endpoint grain. If that arrives, revisit with
Option C rather than A, since by then the attribution problem will need
solving properly rather than flattening.

## Correction to the README

The roadmap line claiming an owed "endpoint-level channel `dims`" change is
wrong and should be replaced with this document's conclusion: a `Series`
capability plus two field plumbings, not a contract change.
