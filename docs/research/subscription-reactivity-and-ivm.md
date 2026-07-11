# Query subscriptions, reactivity, and IVM

**Status:** research / design notes (not a commitment to implement)  
**Captured:** 2026-07-11  
**Primary sources:**

- Session `16f42b03` (2026-02-23) — WHERE-clause analysis + IVM literature survey;
  conclusions written into Claude project `MEMORY.md` under *Researched, not
  pursuing* (later compacted out of that file).
- Session `05fd70e5` (2026-03-29) — predicate-aware invalidation shipped as
  v0.15.0 (liteparser → relational algebra → bytecode VM).
- Product truth today: `README.md` (feature description), `STABILITY.md`
  (IVM still out of scope for 1.0), `dist/sqlpipe.cpp` (`QueryWatch`).

This document consolidates that history so the thinking is durable, then
states the *current* map of the design space so a fresh analysis can start
from reality rather than the February snapshot.

---

## 1. Terminology (deliberately sharp)

Three phrases get conflated. Keep them separate:

| Term | Meaning in this doc |
|---|---|
| **Query subscription** | sqlpipe feature: register SQL; get notified with a **full result snapshot** when the answer *may* have changed and the result hash differs. |
| **Reactive query** (product/UI sense) | “My UI updates when the DB changes.” Subscriptions already are this. |
| **IVM** (incremental view maintenance) | Systems sense: maintain the answer as a function of **Δbase → Δresult**, ideally without re-executing Q; often emit **row-level diffs**. |

Calling subscriptions “reactive queries” in agents-guide / casual speech is fine
for product language. It is **not** the same as claiming IVM.

---

## 2. What sqlpipe does today (2026-07)

### 2.1 Pipeline

1. **Subscribe** with a SQL string (`Replica` / `Peer` / `Database` / `QueryWatch`).
2. **Discover table dependencies** (authorizer / parse).
3. **Parse** via liteparser into relational algebra; **extract predicates**;
   propagate through equijoins; compile per-table **bytecode** programs.
4. On write / apply:
   - Table miss → ignore.
   - Optional: evaluate predicates against changeset row images (old and new).
     If neither can match → **skip re-evaluation entirely**.
   - Column-relevance: UPDATEs to columns not referenced by the query can be
     skipped (where tracked).
5. Otherwise **re-execute the full SQL** (cached prepared statement where
   present), materialize the full `QueryResult`.
6. **FNV-1a hash** the result; deliver only if the hash changed.
7. Consumer always receives a **complete snapshot** (`columns` + `rows`), never
   a structured delta.

### 2.2 What is already optimised

| Mechanism | Cost avoided |
|---|---|
| Table-level dependency set | Re-running queries on unrelated tables |
| Predicate-aware skip (bytecode VM) | Re-running when changed rows cannot match WHERE (incl. join-propagated preds) |
| Column relevance | Re-running on UPDATE of irrelevant columns |
| Result hash | Notifying / re-rendering when re-exec was a no-op for the consumer |
| Per-sub prepared statement | Parse/prepare thrash on every notify |
| Batched `handle_messages` | Deferred eval until a burst of messages is applied |

Supported predicate surface (README): equality, inequality, range, `IS NULL`,
`IN` / `NOT IN`, `BETWEEN`, OR-of-equalities; join propagation via equijoins.

### 2.3 What is deliberately not done (1.0)

From `STABILITY.md` *Out of scope for 1.0*:

- Cross-subscription **prepared statement sharing** (keyed by SQL text).
- **IVM** for subscriptions.
- (Related product limits: multi-master, non–INTEGER PRIMARY KEY tables.)

---

## 3. Historical research (2026-02-23)

Context: subscriptions had just landed (v0.3.0) with table-level invalidation
+ result-hash suppression. Liteparser did not yet exist in-tree for this path.

### 3.1 WHERE-clause optimisation analysis

**Problem.** Hash suppression avoids *delivery* of unchanged results; it does
not avoid *execution*. Can we prove a change cannot affect Q and skip the run?

**Feasibility sketch (then):**

| Query shape | Skip cheaply? |
|---|---|
| `WHERE pk = ?` / `pk IN (...)` | Yes |
| Simple column comparisons / ranges | Mostly |
| `LIKE`, functions, EXISTS, subqueries | No / not worth it |
| JOIN / GROUP BY / ORDER BY LIMIT | No |

**Fundamental tension (still true as a *cost* argument):**  
The shapes easiest to filter statically tend to be the ones already cheap to
re-run (indexed point lookups). The expensive shapes (large joins, aggregates,
top-K) are hardest to analyse without a real query engine.

**Approaches considered:** hand SQL parse; `EXPLAIN` bytecode; probe
statements; track contributing rowids. All either fragile, partial, or almost
no better than re-run + hash for the cases they cover.

**Recommendation then:** do **not** pursue WHERE optimisation; if execution
cost hurts, prefer **batching**.

### 3.2 IVM literature survey (summary)

**Core problem:** given `V = Q(R₁…Rₙ)` and ΔR, compute ΔV without re-running Q.

**Foundations:** Gupta & Mumick delta rules (filter, project, join, aggregate);
self-maintainability (filters/projections yes; joins need the other side).

**Commercial DBs:** restrict “fast refresh” / indexed views to SQL subsets;
PostgreSQL stock concurrent refresh is re-exec + diff, not true IVM (pg_ivm
adds real IVM via triggers).

**Reactive systems spectrum:**

| System | Technique | Joins / aggs |
|---|---|---|
| Materialize | Differential dataflow | Yes |
| Noria → ReadySet | Stateful dataflow operators | Yes (subset) |
| RethinkDB / Firestore | Predicate eval on changed docs | Limited / no |
| Meteor | Oplog + re-query | No |
| Supabase Realtime | WAL + simple filter | No |

Pattern: either build a **dataflow engine**, or **restrict** the language and
do predicate-level filtering. Nobody successfully “bolts full IVM onto an
arbitrary SQL string API” without one of those two moves.

**SQLite landscape:** session extension = row changesets, not query semantics;
little published SQLite-specific IVM; Electric-style “shapes” are replication
filters more than IVM.

**Complexity ladder proposed for sqlpipe:**

| Level | Idea | Feb 2023 verdict |
|---|---|---|
| **0** | Table invalidation + result hash | Shipped |
| **1** | Predicate filter on single-table queries | “Overlaps cheap re-exec; skip” |
| **2** | Join relevance probing | Hard without structure |
| **3** | Full SPJ delta computation | Hand-built Noria join |
| **4** | Aggregate maintenance | MIN/MAX hard |
| **5** | Full dataflow engine | Out of scope for a 2-file lib |

**Bottom line then:** Level 1 not worth it; Levels 3–5 too heavy; batching if
needed. Classify in memory as *Researched, not pursuing* for both WHERE and IVM.

### 3.3 What that research got right / wrong

| Claim | Verdict after v0.15.0 |
|---|---|
| Full IVM (L3–L5) is too large for core scope | **Still holds** — remains out of 1.0 |
| Batching is a high-ROI scheduling win | **Shipped** (`handle_messages`) |
| Level 1 not worth it because no parser | **Overturned** — liteparser made structure available; Level 1–2-*ish* shipped |
| Easy filters ≈ cheap queries so skip is pointless | **Partially wrong in product terms** — many live UIs have *many* subscriptions and high write rates; skipping re-exec avoids aggregate CPU even when each query is “cheap” |
| Result hash is the main app-facing win | **Still holds** — IVM without diffs still forces client re-diff of snapshots |

---

## 4. What was built after the research (2026-03 →)

v0.15.0 did **not** implement IVM. It implemented a much stronger **Level 1–2
invalidation filter**:

1. Vendor **liteparser** — real SQL AST.
2. Lower to **relational algebra**; predicate pushdown / split / join
   normalisation.
3. **Transitive predicate propagation** through equijoins.
4. Compile predicates to a **bytecode VM**; evaluate against old and new
   changeset images (subscription fires if either matches).
5. **Column relevance** tracking.
6. Multi-column predicates via row preload / DB rowid lookup as needed.
7. Three-valued SQL NULL semantics, richer operators (`IN`, `NOT IN`, OR→InList,
   etc.).

That is: *prove irrelevance → skip re-exec*. When relevance is possible, still
**full re-exec + full snapshot + hash**.

This is exactly the RethinkDB/Firestore tier of the survey table — not
Materialize/Noria.

---

## 5. Design space map (for the next discussion)

### 5.1 Axes

1. **Invalidation precision** — how often we re-exec (table → predicate →
   column → true delta necessity).
2. **Maintenance model** — re-exec vs maintain materialised state.
3. **Delivery shape** — full snapshot vs row-level diff vs both.
4. **Query language contract** — arbitrary SQL string vs restricted “shape”
   vs builder API.
5. **Where computation runs** — only local DB (today) vs server-side
   evaluation for thin clients.
6. **API stability** — Fluid `Subscription` / `QueryResult` vs 1.0 freeze.

### 5.2 Options still open (not decisions)

**A. Stay the course (recommended default through 1.0 settle)**  
Ship hash + predicate skip; document as live queries; no IVM. Measure real apps
before climbing the ladder.

**B. Diff delivery without IVM**  
Still re-exec, but diff previous snapshot vs new and emit
`{added, removed, updated}` (optionally keyed by PK). Cheaper for UI
integration; execution cost unchanged. Fits Fluid API window if done carefully.

**C. Restricted IVM for SPJ shapes**  
Only for queries that lower cleanly to RA the parser already builds. Maintain
result (or PK set) and apply Gupta-style deltas for filter/project/join.
Fallback to re-exec for unsupported SQL. Matches Noria’s “subset” honesty.

**D. Probe / semi-join relevance only**  
Never materialise ΔV; only improve skip rates for joins (Level 2). Smaller than
C; still no diff API.

**E. Server-side shape sync**  
Electric-like: replication filter is the “subscription”; local DB only holds
matching rows. Different product surface; interacts with table_filter /
ownership, not only QueryWatch.

**F. Explicit non-goals (reaffirm)**  
Full differential dataflow engine; arbitrary-SQL IVM with no fallback; CRDT
multi-master views.

### 5.3 Product tension (same family as DDL ontology)

Arbitrary SQL + “always correct + always fast + always incremental” is a
triple that industry solves by **restricting the language** or **building a
new engine**. sqlpipe’s brand is a small, transport-agnostic library over
SQLite. Climbing to L5 fights that brand; L1 was a good climb once a parser
existed; L3 is the next honest fork in the road.

---

## 6. Suggested evaluation criteria (when unparking)

Use these rather than vibes:

1. **Correctness:** skipped re-eval ⇒ result identical to forced re-eval
   (already have a synthetic test shape; needs breadth).
2. **CPU under load:** N subscriptions × M writes/s; measure re-exec rate and
   wall time with/without candidate feature.
3. **Client work:** does the app still re-diff full snapshots? If yes, diff
   delivery may beat clever invalidation for UX cost.
4. **Complexity budget:** lines + failure modes in `QueryWatch` / RA / VM
   relative to whole library.
5. **API freeze:** anything that changes `QueryResult` shape is a Fluid-item
   break and may reset settling if promoted as stable too early — keep
   experimental until after 1.0 or version carefully.
6. **Fallback honesty:** every incremental path must degrade to re-exec + hash
   without silent wrongness.

---

## 7. Open questions for the next analysis round

1. Is the remaining pain **re-exec cost**, **snapshot delivery size**, or
   **client integration ergonomics**? (Different cures: C/D vs B vs API sugar.)
2. Which query shapes do real / intended apps actually subscribe?
   (Point lookups? Filtered lists? Joins? Aggregates? Top-K?)
3. Should `QueryResult` gain an optional diff channel while keeping full
   snapshot as the compatibility default?
4. Is liteparser RA already a sufficient IR to attempt L3 for a closed SPJ
   subset, or is that a separate project?
5. Interaction with **prediction** (optimistic local rows) and **BestEffort**
   delivery — do incremental views create new inconsistency windows?
6. Should this stay a library feature or become an **app-level recipe**
   (consumer diffs `QueryResult` rows by PK themselves)?
7. Does the 1.0 settle clock argue for **docs-only** until Oct 2026, or is a
   Fluid-only experimental API acceptable?

---

## 8. Pointers

| Artifact | Location |
|---|---|
| Transcript (WHERE + survey) | `~/.claude/projects/-Users-marcelo-work-github-com-marcelocantos-sqlpipe/16f42b03-dee2-4af9-9c32-8d938db432e1.jsonl` |
| Predicate implementation session | `05fd70e5-e52d-4693-a702-10130197406f` |
| Implementation | `dist/sqlpipe.cpp` — predicate extract / bytecode VM / `QueryWatch` |
| Public API | `dist/sqlpipe.h` — `QueryWatch`, `QueryResult`, `Subscription` |
| 1.0 boundary | `STABILITY.md` § Out of scope |
| Feature blurb | `README.md` — Predicate-aware query subscriptions |

---

## 9. One-line doctrine (provisional)

> sqlpipe subscriptions are **correct live re-queries with smart invalidation**,
> not a materialized-view engine. Climb the IVM ladder only when measured load
> or a restricted query contract justifies the complexity — and never silently.

*End of capture. Discussion continues from §5–§7.*
