# tid-semantiQ — Observation model & primitive interfaces

Status: **draft contract**, v0.1. Implemented in `core/model.py`,
`core/primitives/`, `core/inspect.py`, `core/correlate.py`, `core/redact.py`,
`capture/base.py`. Verified by seven suites in `tests/` — 89 tests.

This is the contract every other layer hangs off. Changing `Observation`,
`Channel.dims` semantics, or a primitive or inspector `name` is a breaking
change.

---

## 1. The five types

```
Entity       a thing that emits or receives        IP, MAC, CAN node, sysid
Channel      a conversation, at some granularity   dims + endpoints
Observation  one discrete exchange, at a time      -> capture plugins produce these
Series       all observations on one channel       -> primitives consume these
Evidence     what the primitives computed          -> the scorer consumes this
```

Plus `InspectionResult` (per-message content facts — §5a), then `Finding`
(computed, frozen) and `Narrative` (the only thing an LLM writes).

## 2. Two invariants

**I1 — Primitives consume `Series` and nothing else.** No frames, no parsers,
no config files, no globals. Anything else a primitive needs arrives through
`Context`, explicitly. This is what makes primitives unit-testable against
synthetic data with no fixtures, and it is what lets domain #4 reuse all
eight of them unchanged.

**I2 — The language model cannot write a verdict.** `Finding.confidence` and
`Finding.severity` are computed by the scorer from `Evidence`. `Finding` is
frozen and there is no code path from the narrator back into it. The narrator
produces a `Narrative`, and `Narrative.verify_against()` rejects any
narrative citing a feature that was never computed — so the honesty guarantee
is a mechanical check, not a prompt instruction.

## 3. Observation granularity

> An Observation is the domain's smallest **meaningful exchange** — not a
> packet, not a connection.

For frame and datagram domains the frame *is* the exchange. For stream
domains it is an **application-data burst** (§4).

| Domain | `kind` | `Channel.dims` | one Observation = |
|---|---|---|---|
| net (TCP/TLS) | `tcp_burst` | `proto, dport, sni` | an app-data burst |
| dns | `dns_query` | `proto, qtype, zone` | one query |
| http (assisted) | `http_txn` | `proto, host` | one request/response |
| modbus | `modbus_read` | `unit, fn` | one transaction |
| dnp3 | `dnp3_frame` | `addr, fn` | one frame |
| mavlink | `mavlink_msg` | `sysid, compid, msgid` | one message |
| can | `can_frame` | `bus, frame_id` | one frame |
| ble | `ble_adv` | `adv_type` | one advertisement |
| wifi | `dot11_mgmt` | `bssid, subtype` | one management frame |
| rpc | `jsonrpc_call` | `endpoint, method` | one call |

Choosing `dims` is the single most consequential decision when onboarding a
domain. Too coarse and distinct behaviours average into noise; too fine and
no channel accumulates enough observations to score. It also determines which
questions are *askable* — see `Fanout` in §5.

## 4. The burst rule

A burst is a maximal run of same-direction application payload on one
channel, with no direction change and no internal gap > `gap_s` (default
50ms). Payload-free packets (bare ACKs, window updates) neither open nor
extend a burst. A burst is timestamped at its **first** packet, so transfer
duration does not fold into the interval series.

Why not the obvious alternatives:

- **Per-packet** is too fine. Segmentation, MTU, Nagle and retransmits are
  transport properties, not behaviour, and they inject timing noise that
  swamps the cadence.
- **Per-connection** is too coarse, and blind in exactly the modern case. A
  reconnect beacon opens a connection per callback, so connection records
  carry the cadence. A websocket or HTTP/2 implant heartbeats *inside one
  long-lived connection* — connection records show a single multi-hour flow
  and the cadence is gone.

Bursts collapse both onto the same `Series`. `test_in_connection_heartbeat_matches_reconnect_beacon`
asserts the primitive cannot tell them apart.

This is also precisely why `tid-soc-agent`'s existing detector is inverted.
It samples `psutil.net_connections()` once per 30s cycle
(`endpoint/collector.py:718`, `dashboard/storage.py:2460`): a persistent
connection is present at every poll and reads as perfectly regular, while a
short 60-second callback is almost never sampled. False positive on the
shape modern C2 prefers, false negative on the thing it is named after.

**`gap_s` is the most dangerous knob in the tool.** Set it below one round of
segmentation and a single message fragments into several Observations,
manufacturing a fast false cadence. Raise it on high-latency links.

## 5. The eight primitives

Parsers share no code across domains — a TLS ClientHello parser and a CAN
decoder have nothing in common. **The statistics share almost all of it.**
Detecting cadence in a 60s TLS callback is the same computation as in a
MAVLink heartbeat, a Modbus poll cycle, a CAN frame id, or a BLE advertising
interval. Industrial and avionics buses are the *easiest* case — periodic by
design, so deviation is correspondingly meaningful.

| Primitive | Question | Needs |
|---|---|---|
| `periodicity` | is there a repeating cadence, and what is it? | — |
| `jitter` | how much randomisation sits on that cadence? | — |
| `burstiness` | clustered, memoryless, or regular? | — |
| `asymmetry` | which way does volume flow, how hard? | — |
| `rarity` | how new and how uncommon is this channel? | `BaselineStore` |
| `entropy` | how compressible is the payload? | cleartext payload |
| `fanout` | how many distinct values of one attribute? | named attr |
| `sequence` | does the order violate the grammar? | grammar |

Rules:

- **A primitive that cannot answer returns `None`**, never a misleading
  number. A missing result is absent evidence; a zero score is a claim.
  `applies_to` makes that a declaration rather than a comment.
- **`score` answers only that primitive's own question** ("how periodic is
  this?"), never overall suspicion. Combining is the scorer's job.
- `Entropy` is the canonical applicability trap: Shannon entropy over TLS
  ciphertext is ~8 bits/byte by construction, so reporting it is reporting
  that encryption works. It runs only on parser-marked cleartext, or in
  assisted mode where operator-supplied keys yielded real plaintext.
- `Fanout` is naturally cross-channel ("how many destinations?"). Rather
  than widen I1, it counts distinct values of a named **attribute** within
  one series — so the question is asked by choosing `dims` coarsely enough
  to contain it. DNS tunnelling: `dims {"zone": ...}` + `Fanout("qname")`.

## 5a. Inspectors — the second analyzer

Bug-bounty findings are overwhelmingly a different shape from behavioural
ones. "This cookie is missing `Secure`" is not a statistic over a series; it
is a fact about one message. Forcing it through `Primitive` would have meant
pretending otherwise, so there is a second analyzer type:

```
Primitive   Series      -> statistics   "how does this channel behave?"
Inspector   Observation -> facts        "what is wrong with this message?"
```

Both land in one `Evidence`, which has two fields (`results`,
`inspections`). `Evidence.by_name()` searches both, so a rule `Condition`
addresses either kind interchangeably and the rule format needed no second
syntax — "periodic AND carrying an unsigned token" is one condition list.

Three things the inspector path needs that the primitive path does not:

**`facts` are strings.** Primitives produce numbers; inspections produce a
cookie name, a JWT algorithm, the parameter a token appeared in. That is
also where secrets end up, which is why redaction exists at all.

**Folding is mandatory.** An inspector runs per message, so a cookie flag
that is wrong on every response yields one result per response — hundreds of
duplicates on a real capture. `fold()` collapses per name: worst score wins
(not the mean — one bad response out of a thousand is the finding), repeats
are counted, and a bounded sample of loci is kept.

**`Finding.cited`.** Evidence is per-channel; a finding is per-rule. Without
recording which evidence a rule referenced, every finding on a host reprints
every inspection on that host — four findings x three inspections, twelve
blocks, none readable. Measured on the fixture before the fix.

### Redaction

Secrets are masked at SERIALISATION, never at capture: an inspector cannot
tell whether a JWT is unsigned from a masked string. Real values live in
memory, masked values go to disk and to the terminal.

Which keys are secret is **declared by the inspector**
(`InspectionResult.secret_facts`), because that is the only layer that knows.
The first implementation guessed from key names against a deny-list of
substrings ("token", "key", "cookie", "secret") and masked `cookie.domain`
(`.example.com` — the finding), `cookie.path` (`/`), and `jwt.issues` (the
human-readable defect list), since each key contains one of those
substrings. A redactor that destroys the report while still missing any key
nobody enumerated is the worst of both.

`looks_secret()` remains as a deliberately narrow backstop — 28+ characters,
opaque alphabet, no spaces, not a URL or path — for an inspector that forgets
to declare one.

## 5b. Correlators — the third and last scope

Some findings only exist between channels. "This bearer token was minted by
`api.example.com` and later sent to an analytics host" is invisible to
anything looking at one channel, because the finding IS the pair.

```
Primitive    one Series       behaviour over time on one channel
Inspector    one Observation  content of one message
Correlator   all Series       relationships BETWEEN channels
```

Three analyzer types, three scopes a question can have. There is no fourth,
which is why this set is expected to be final.

A correlator does NOT emit `Finding`s — that would put a verdict outside the
scorer and break I2. It emits `(Channel, InspectionResult)` pairs, and those
merge into that channel's `Evidence` before the rules run. Correlation
findings are therefore scored, titled, superseded and redacted by exactly the
same path as everything else.

**Pipeline order is forced.** Correlation cannot run first (it needs
observations grouped by channel) and cannot run last (a rule may require its
output), so the pipeline is `analyse-all -> correlate -> score-all`. That is a
real barrier and the reason the whole capture is held in memory. The
single-channel helper `score_series()` skips correlation by construction, and
a test pins that so the limitation stays explicit rather than becoming a
surprise.

**Attribution is a design decision, not a detail.** A leaked credential is
attributed to the channel that RECEIVED it — the host that should not have
it, and the request a triager opens first. Getting this backwards produced a
finding that read as "the legitimate API leaked to the analytics host",
reversed. The first implementation picked the "primary" side by counting
hosts that shared the credential, which ties at one-each in the commonest
case and broke arbitrarily; the fix keys on which registrable domain the
client talks to most across the whole capture.

## 5c. Grain: `dims` vs `group_by`

`Channel.dims` sets the **coarsest** grain — the unit at which findings are
attributed. `Series.group_by(key)` sets a **finer** grain for one specific
question inside that unit, returning sub-series that still carry the parent
channel.

Both narrow a channel without redefining it, and both return `Series`, so
invariant I1 holds: a primitive still consumes a `Series` and nothing else.
`filter(direction=, kind=)` was already this move; `group_by` generalises it
to an attribute or a key function.

**Why not finer dims.** Measured on a twelve-endpoint fixture where every
response repeated two systemic defects:

| grain | channels | findings |
|---|---|---|
| `{scheme, host}` | 1 | 2 |
| `{scheme, host, endpoint}` | 12 | **24** |

The multiplication factor is the endpoint count, so one misconfigured cookie
is reported 200 times on a 200-endpoint application. `fold()` cannot help —
it collapses repeats *within* a channel, and each endpoint would be a
different channel. Endpoint dims would also make `rarity` ask "what fraction
of hosts call this exact endpoint", which is near-zero for everything and
fires the rarity gate everywhere. Full reasoning in
[ADR-001](ADR-001-endpoint-grain.md).

**Observations with a missing key are excluded**, not bucketed under a null
group. A missing key means the question does not apply to that observation;
grouping them would invent a cohort out of unrelated messages and then report
statistics about it.

### Transactions are not connections

Three `attrs` keys, uniform across the pcap and HAR paths:

```
txn         transaction id — one request/response pair
elapsed_s   seconds from request to response, on the response only
stream      CONNECTION id — NOT unique per transaction
```

HTTP keep-alive puts many transactions on one `tcp.stream`, so any pairing by
stream identity is silently wrong on almost all real traffic. The pcap path
therefore pairs using Wireshark's own `http.request_in`, which is correct
across keep-alive and pipelining, and takes timing from `http.time`.
Demonstrated by `test_keepalive_proves_stream_is_not_a_transaction_id`: three
transactions on one stream, `group_by("stream")` returns 1 group,
`group_by("txn")` returns 3.

`elapsed_s` is **unset** when a response could not be paired, never zero —
zero would read as "instantaneous" and poison any timing comparison.

## 6. Measured separation

`tests/test_timing_separation.py` — synthetic series, seed 1337, 40
observations each, Cobalt-Strike-style jitter (interval uniform in
`[p(1-j), p]`).

```
series                      period  MAD/med  implied   PERIODICITY
beacon  60s, jitter  0%       60.0  0.000     0.0%      1.000
beacon  60s, jitter 20%       54.8  0.040    15.8%      0.858
beacon  60s, jitter 50%       46.6  0.131    52.5%      0.713
beacon  60s, jitter 90%       34.7  0.401   100.0%      0.541
exact poller (cron 300s)     300.0  0.000     0.0%      1.000
interactive / bursty           3.0  0.553   100.0%      0.373
unstructured, same rate       43.2  0.671   100.0%      0.315
```

Three things to read out of this table:

1. **Beacons 0.54–1.00, non-beacons 0.32–0.37.** Clean separation, degrading
   smoothly rather than cliff-failing. The naive `max - min` range test used
   by connection-polling detectors does not fire at all past ~20% jitter —
   asserted in `test_naive_range_test_fails_where_mad_holds`.
2. **90% jitter scores lowest of the beacons (0.54), and that is correct.**
   An interval uniform in [6s, 60s] is close to unstructured by
   construction. A detector claiming high confidence there would be lying.
3. **The exact cron poller scores 1.000 — identical to a zero-jitter
   beacon.** This is the whole false-positive problem in one row.
   Periodicity alone is not a detector; it is one input. What separates them
   is `rarity`, destination reputation, and process attribution. A deployment
   that alerts on periodicity alone will drown in update checkers and
   telemetry agents.

Two implementation notes earned the hard way, both recorded in the code:

- Dispersion maps as `exp(-k·ratio)`, not `1 - ratio`. The linear mapping
  scored memoryless traffic at 0.33 — the same band as a jittered beacon —
  and the separation collapsed.
- Size regularity enters as a bounded **multiplier** in `[0.75, 1.0]`, not an
  additive term. Additive weighting gave every series a floor equal to the
  size weight, compressing the scale. As a multiplier, good size regularity
  can only confirm a cadence timing already found; it can never manufacture
  one.

**These weights are reasoned, not fitted.** `dispersion_decay`,
`size_floor`, `count_saturation` and the jitter band must be refit against
lab ground truth — Sliver or Havoc at 0/20/50/90% jitter, with a week of
clean traffic as the false-positive denominator — before any number here is
quoted to anyone. Nothing in §6 is a detection rate.

## 7. Adding a domain

1. Get the messages out. Either a `TsharkProfile` (if Wireshark dissects the
   protocol) or a `CaptureSource` with a native parser (if it does not). Use
   `BurstAssembler` for a byte stream.
2. Choose `Channel.dims`. Spend real time here, and read the checklist below
   before deciding.
3. Pick a primitive stack in `core/primitives/__init__.py::STACKS`.
4. Write inspectors for per-message facts, if the domain has content worth
   reading.
5. Write ontology rules mapping evidence combinations to named findings.

No new statistics. Five domains in — net, dns, http, modbus, dnp3, mavlink —
none has needed a new primitive.

### The onboarding checklist

Every item below is a mistake that was actually made, in some cases more
than once. They share a shape: each produces plausible output rather than an
error, so none of them announces itself.

**Does any value in `dims` need to be COUNTED?** If so it belongs in
`attrs`. Made and corrected five times: DNS query names under a zone, HTTP
paths under a host, Modbus unit ids, DNP3 link addresses, MAVLink message
ids. `dims` sets the coarsest grain at which findings attribute; anything
whose cardinality is the signal cannot live there, because `Fanout` can only
count attributes. §3 and §5.

**Is `dims` too fine?** Endpoint-level http `dims` multiplied findings by the
endpoint count — two defects became twenty-four on a twelve-endpoint app.
Use `Series.group_by()` for a finer question inside one channel instead.
§5c and ADR-001.

**Does the domain interleave several cadences on one channel?** Then
`Periodicity` needs `group_attr`. A Modbus master polling two function codes
50 ms apart on a 1 s cycle scored **0.001** measured whole, while a flat-rate
scanner scored **1.000** — backwards. Same for MAVLink heartbeats against
position reports.

**Is the transaction key actually unique?** `tcp.stream` is a CONNECTION, not
a transaction, and HTTP keep-alive puts many on one. The DNP3 application
sequence is four bits and wraps at 16, folding 40 exchanges into 16 groups of
ten. Prefer the protocol's own id, and check it does not wrap inside a
capture.

**Does one inspector classify into several categories?** Then it must emit a
per-category NAME. `fold()` keeps the worst result per name, so a single name
silently discards every lower-scoring category — on DNP3 a restart hid a
reporting-suppression command and the rule meant to catch it could never
fire. The same bug was latent in Modbus.

**Is a score saturating where `fold` needs to pick a winner?** A saturating
score means several instances tie at the ceiling and the retained facts come
from whichever tied first. The MAVLink position jump reported an arbitrary
discontinuity rather than the largest until the score was made monotonic.

**Does `rarity`'s blended score answer the question being asked?** Often not.
`prevalence` drops the initiator by design, so on a one-master control
network it is 100% by construction and cannot see a second master; `recency`
spans days, so inside one capture everything is recent. For "is this source
new", gate on `rarity.novel`. Rarity measured 0.40 for both the established
Modbus master and the rogue.

**Are the saturations and thresholds domain-sized?** 50 distinct DNS names
under a zone is unremarkable; 50 Modbus unit ids is an exhaustive sweep of a
network that normally has three. `Fanout` takes `saturation` and `kind` for
this reason.

**Does a placeholder behave as "no opinion" or as "everything is wrong"?**
`SequenceOrder(allowed=frozenset())` permits nothing, so it scored every
transition on valid traffic as a violation. It shipped that way in the modbus
stack and was inert only because no rule referenced it.

## 7a. What implementing it changed

Three defects the spec did not survive contact with. All three are the kind
that produce plausible output rather than an error, which is why they are
recorded rather than quietly fixed.

**`prevalence` could not work off `Channel.key`.** The key includes the
initiator, so "how much of the estate uses this channel?" always answers "one
host" — every channel scores maximally rare and `rarity` becomes useless,
i.e. the exact failure the primitive exists to prevent. Fixed by adding
`Channel.profile_key` (identity with the initiator removed) and changing
`BaselineStore` to take a `Channel` rather than a key string, so the store
decides which identity each question is asked of. A bare string made the
distinction invisible at the call site.

**A store with no history is indistinguishable from one reporting universal
rarity.** `NullBaseline` answering "never seen, prevalence zero" to every
query scores every channel at 1.0 — gating nothing and surfacing everything.
Fixed with an explicit `available` flag that `Rarity.applies_to` checks: with
no baseline the primitive declines to answer and rarity-gated rules stay
silent, which is the correct response to absent evidence.

**`Context.now` must be the capture's end time, not wall-clock.** A pcap
recorded last year scored against `time.time()` makes every known channel
ancient, drives `rarity.recency` to zero, and collapses rarity onto
prevalence. That *suppresses* findings — so the bug looks like the tool
working. Live capture is the only case where wall-clock is right.

## 7b. End-to-end result

Measured on synthetic fixtures (`tools/make_test_pcap.py`), same capture and
same thresholds, varying only the baseline:

| baseline | findings | prevalent 300s poller | jittered beacon | DNS tunnel |
|---|---|---|---|---|
| cold (no history) | **47** | fired (false positive) | fired | fired |
| warm (30 hosts) | **2** | suppressed | fired | fired |

The beacon reports period 54.2s (generated band [48, 60]), MAD 4.1s, ~30%
implied jitter, over 40 callbacks, confidence 0.82, filter `tcp.stream eq 16`.

`test_warm_baseline_suppresses_the_prevalent_poller` asserts the suppression
comes from prevalence (poller: periodicity > 0.95, prevalence > 0.9, rarity
< 0.5, recency > 0.5) and not from a thin-baseline or clock artefact that
happens to push the score down. Suppression for the wrong reason would pass a
naive assertion and fail silently on real traffic.

## 8. Deliberately not here yet

- A Postgres `BaselineStore` against the SOC's own history — the one that
  gives prevalence a fleet-wide denominator instead of one machine's.
- The narrator. `Narrative` and its verification exist; nothing calls an LLM.
- A spectral periodicity estimator (FFT or autocorrelation) for multi-modal
  and interleaved cadences that MAD misses. Lands behind the existing
  `Primitive` interface with `method="spectral"` — no interface change.
- Modbus and MAVLink transition grammars (`STACKS` has the slots, empty).
- Live-capture windowing. `group_into_series` is the batch form; the sliding
  variant emits and evicts on a timer and produces the same `Series`.
- Refresh-token rotation. The session-fixation correlator has the request
  ordering it needs; this is a second question over the same timeline.
- `tshark` profiles for Modbus, DNP3 and MAVLink. The backend now exists, so
  these are a field list and a dims choice — no parser to write.

### Same-party decisions use the Public Suffix List

`core/suffixes.py` parses the vendored Mozilla list (`data/`, MPL-2.0,
unmodified). It replaced four separate label-count approximations, each of
which documented itself as a placeholder. The approximation was wrong in both
directions, and both mattered:

```
foo.co.uk / bar.co.uk            label count -> both "co.uk"      -> SAME
                                 PSL         -> foo/bar.co.uk     -> different

a.s3.amazonaws.com               label count -> "amazonaws.com"   -> SAME
b.s3.amazonaws.com               PSL         -> a/b.s3.amazon...  -> different
```

The first suppressed a real CRITICAL: a credential crossing two unrelated UK
organisations read as first-party plumbing, so the cross-party gate was
silently disabled for every target under a multi-part ccTLD. The second is
arguably worse for this tool — a credential reaching an attacker-controlled
S3 bucket or GitHub Pages site looked like first-party traffic, which is the
exact finding the tool exists to produce. The PSL's **private section** is
what distinguishes those, so it is included by default;
`include_private=False` restricts to ICANN for the different question of
which registry delegated a name.

Three traps in the algorithm, all tested: wildcard rules (`*.ck`), exception
rules (`!www.ck`, which win outright and drop their leftmost label), and
longest-match (both `com` and `s3.amazonaws.com` match a bucket — taking the
first match found is the classic bug). ~500 rules carry unicode labels while
capture hostnames arrive as punycode, so both forms are stored.

`registrable_zone` feeds DNS `Channel.dims`, so this changes baseline keys
for names under a multi-part suffix and prevalence history for those zones
starts again. Simple suffixes are unaffected.
