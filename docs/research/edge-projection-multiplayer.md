# Edge projection for casual multiplayer (and “SQLite edge, hub” data plane)

**Status:** research / design notes (not a commitment to implement)  
**Captured:** 2026-07-11  
**Related:** `docs/research/subscription-reactivity-and-ivm.md` (UI live queries ≠
sync projection), 🎯T26 (structural schema, not DDL history), sqldeep Postgres
backend (shared *query* surface only).

---

## 1. Primary use case

**Casual multiplayer games**, most likely **turn-based** rather than twitch
real-time.

- A large **hub** database holds the universe of game state for many customers.
- Hard isolation along **customer / tenant** boundaries is assumed (outer shell).
- Each **player edge** (device / client) holds a **SQLite** materialization of
  only the slice of the universe that player needs.
- Hub engine may eventually be **Postgres** (or server SQLite); that choice is
  secondary to the **projection specification** problem below.

sqlpipe today moves rows efficiently once both sides hold (or are syncing) a
defined set. It does **not** answer: *which rows, for whom, and why?*

---

## 2. The core problem

Define a **projection specification**:

> Given a global multiplayer database *U*, and a subject *P* (player / device /
> session), define the subset *Uₚ ⊆ U* that *P* is allowed and required to hold
> locally — including rows that are **shared with other players**, not only rows
> that “belong” to *P*.

Hard tenancy is the easy outer shell.  
The interesting shell is **co-interest**: a match, party, trade, or table that
couples two (or *n*) players so both edges need the same shared facts.

A naive instinct is “each player only gets rows with their `player_id`.” That
fails as soon as shared instance data (`matches`, `boards`, `moves`) has no
single owner. Another instinct is “stall once and figure out both players are
involved” — that is right as a **lifecycle moment**, but the durable model is
**membership in a shared scope**, not ad hoc join analysis at read time.

---

## 3. Two layers (do not smash together)

| Layer | Question | Failure if ignored |
|---|---|---|
| **Isolation (tenancy)** | Which customer’s universe? | Cross-tenant leak / wrong shard |
| **Interest (gameplay)** | Which objects is this player “in the room” for? | Missing opponent state, or shipping the world |

Tenant partition is usually static and hierarchical.  
Gameplay interest is dynamic, relational, and often **symmetric** (if A sees
match M, B must too).

---

## 4. Candidate specification models (evaluated)

### 4.1 Column stamp: `player_id` on every table

```text
edge(P) = { row | row.player_id = P }
```

- **Good for:** inventory, profile, settings, private mail.
- **Breaks for:** shared match/board/move/chat objects.

### 4.2 Raw FK closure from `players`

```text
edge(P) = reachable(P) via schema foreign keys
```

- **Good for:** tree-shaped private data (player → characters → items).
- **Breaks for:** many-to-many and shared parents (`match_players` then content
  hanging off `match`). Schema FKs are a **hint**, not the sync graph; full
  join-graph reachability often becomes “almost everything” (catalog, other
  players, …).

### 4.3 Membership / room scopes (preferred core for games)

```text
edge(P) = private(P) ∪ global ∪ ⋃ { contents(S) | member(S, P) }
```

- Scope entities: match, party, lobby, trade, …
- Membership relation: e.g. `match_players(match_id, player_id)`
- Contents: rows tagged by `scope_id` / `match_id` (or an explicit content rule)

**Co-interest falls out:** when matchmaking commits, both A and B become members
of match M; both edges’ interest sets expand to `contents(M)` without cloning
the universe per player.

“Stall once and figure out both players are involved” ≡  
**install membership (and create the scope) in one hub transaction**, then both
edges sync that scope.

### 4.4 Query shapes (Electric-style surface)

```text
edge(P) = materialization of parameterized queries Qᵢ(P)
```

Expressive and familiar. Best treated as **surface syntax** for (4.3), not a
different ontology. Replication still needs: base rows in the shape, membership
churn, and write authorization aligned with the shape.

### 4.5 Unlabeled join-derived interest

```text
edge(P) = { r | ∃ join path from r to player P }
```

Unsafe without a separate **labeled sync graph** (`owns`, `member`,
`visible_if_member`, `public_readonly`) and cut-points for global catalog.

### 4.6 Capability tickets

Hub mints signed `{ player, scopes, tables, exp }`. Edge may only sync under the
ticket. Spec = what the hub is willing to mint; composes with membership.

---

## 5. Recommended model for turn-based multiplayer

Three strata:

```text
┌─────────────────────────────────────────────┐
│ GLOBAL (read-mostly)                        │  rules, card defs, maps, catalog
│  → versioned snapshot on every edge         │
├─────────────────────────────────────────────┤
│ PRIVATE (player-scoped)                     │  inventory, prefs, meta
│  → player_id = P                            │
├─────────────────────────────────────────────┤
│ SCOPED (shared instances)                   │  match, board, moves, match chat
│  → scope_id + membership(scope, player)     │
└─────────────────────────────────────────────┘
```

**Projection:**

```text
U_P =
    Global(version ≤ v)
  ∪ Private(player = P)
  ∪ Scoped(scope ∈ ActiveScopes(P))
```

**ActiveScopes(P)** changes on matchmaking, invite, leave, spectate grant, etc.
Turn-based games keep scope churn low: between turns, scopes are stable; Reliable
delivery + diff on reconnect is enough for many casual titles.

**Discipline:** sync spec first, UI queries second. If a screen needs a join
between two players’ *private* rows, mint a **scope** (trade, match, …) instead
of inferring sync from the join.

---

## 6. What the specification must declare

A usable spec is not one SQL string. It needs roughly:

1. **Table classes** — `global | private | scoped | do_not_sync`
2. **Scope kinds** — membership relation + content rule per kind
3. **Private rule** — column or path to player
4. **Write policy** — who may INSERT/UPDATE/DELETE which class (orthogonal to
   read interest; often hub-authoritative for turn resolution)
5. **Explicit join visibility** — edge joins are legal because both sides are in
   *U_P* by construction, not because the sync engine inferred them

### Conceptual sketch (not an API proposal)

```yaml
global:
  tables: [card_defs, maps, rulesets]
  policy: replicate_by_version

private:
  key: player_id
  tables: [players, inventory, loadouts]

scopes:
  match:
    members: match_players(match_id, player_id)
    contents:
      - table: matches
        key: id
      - table: boards
        key: match_id
      - table: moves
        key: match_id
      - table: match_chat
        key: match_id

active_scopes_for_player: |
  membership holds and status IN ('active', 'finished_recent')
```

---

## 7. Mapping onto sqlpipe (and hub engines)

| Existing primitive | Role vs projection |
|---|---|
| `table_filter` | Crude table-class filter only |
| Peer `owned_tables` | **Write** ownership / negotiation — not read interest |
| Query subscriptions | UI over **local** *U_P* — does not define *U_P* |
| Diff / live sync | Moves whatever is already in the local DB |
| Relay / multi-replica | Topology, not interest policy |
| sqldeep `SQLDEEP_POSTGRES` | Shared **query language** on edge SQLite and hub Postgres — not the data plane |

**Missing layer** (product gap):

```text
  [ Spec: Global ∪ Private(P) ∪ Scoped(ActiveScopes(P)) ]
                         ↓
              authorize + enumerate row sets
                         ↓
           sqlpipe (channels / filters) moves rows
                         ↓
              edge SQLite = materialization of U_P
                         ↓
              QueryWatch / UI over local DB
```

Hub holds *U* (Postgres or server SQLite). Edges never see *U \ U_P*.
Authorization and replication should use the **same** spec.

### Hub engine options (secondary)

| Option | Notes |
|---|---|
| **B. SQLite hub + Postgres mirror** | sqlpipe core untouched; Postgres as analytics/read model |
| **D. Protocol hub adapter** | sqlpipe messages ↔ Postgres DML façade (hard: capture, types, identity) |
| Postgres-native Electric-like | Competes with funded specialists unless ownership + scopes + structural schema differentiate |

Identity constraint: sqlpipe’s safety model is **INTEGER PRIMARY KEY** today.
Multi-edge / hub ambition may force PK-keyed identity work earlier.

Schema: prefer **structural want-state** (sqlift doctrine, 🎯T26) over dual DDL
history on edge and hub.

---

## 8. Doctrine (provisional)

> A player’s edge database is the materialization of a declared policy:
> versioned global data, player-private rows, and the contents of every scope
> (match/party/…) of which they are a member — **not** the transitive closure of
> arbitrary joins over the universe.
>
> Co-interest is **scope membership**, installed at lifecycle events (e.g.
> match start), not special-case join analysis.
>
> Edge is SQLite. Hub may be Postgres. The protocol stays message-shaped. Engines
> meet through adapters and structural schema identity — not by pretending
> Postgres is SQLite or by replaying DDL on both.

---

## 9. Non-goals (for this research thread)

- Full multi-master CRDT gameplay state
- Inferring sync sets from arbitrary UI SQL joins without a labeled sync graph
- Shipping the entire tenant DB to every player device
- Real-time twitch networking as the first success criterion
- Replacing QueryWatch with the projection layer (orthogonal: invalidation vs interest)

---

## 10. Minimal spike (when unparked)

1. One **private** table + one **scoped** match graph (`matches`,
   `match_players`, `moves`) with INTEGER PKs.
2. Hub process evaluates `rows_for(P)` from membership + private stamp.
3. Edge opens empty SQLite; sync only *U_P*; second player joins match → both
   edges receive `contents(match)` via diff.
4. Leave match → scoped rows removed or tombstoned on edge per policy.
5. Optional: same sqldeep query on edge and hub for a scoped read.

**Success:** offline-capable turn on edge for in-scope data; no opponent private
inventory on edge; co-interest without full-DB clone.

---

## 11. Open choices (deferred)

- Scope granularity (per match vs coarser “realm”)
- Spectators as membership with reduced contents
- Opponent public profile: global vs private projection vs scoped copy
- Write authority: hub-authoritative turns vs edge-proposed moves
- Hub engine: Postgres vs SQLite first
- Wire packaging: one filtered stream vs per-scope channels

---

## 12. Pointers

| Artifact | Location |
|---|---|
| This note | `docs/research/edge-projection-multiplayer.md` |
| Subscription / IVM (orthogonal) | `docs/research/subscription-reactivity-and-ivm.md` |
| Structural schema doctrine | 🎯T26 (set aside), `STABILITY.md`, sqlift |
| sqldeep Postgres transpile | `SQLDEEP_POSTGRES` / `sqldeep_transpile_backend` |
| Current table filter / ownership | `MasterConfig::table_filter`, `PeerConfig::owned_tables` |

*End of capture.*
