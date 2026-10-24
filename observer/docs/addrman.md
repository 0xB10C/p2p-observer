# The address manager

How the observer decides who to connect to, and what it remembers about them.

Lives in `observer/src/addresses/`. Replaced the previous `addresses.rs` store
plus the retry loops that used to sit inside `connection.rs`.

## The central decision

The old `addresses.rs` did two jobs at once. It was the crawler's working
memory — who to dial, when to retry — and it was also the only place some
observations were ever recorded. That second job made the first one hard: the
file could not be dropped on a format change, could not forget entries under
pressure, and a half-written copy of it stopped the process from starting.

The two are now separate:

- **The address table is a private cache.** It may forget things. It may be
  discarded wholesale. Its format may change freely. Losing it costs a few
  minutes of GETADDR and gossip, nothing more.
- **Observations go out as NATS events the moment they are seen**, and are
  archived by a separate consumer. Nothing of research value lives only in the
  table.

Almost every simplification below follows from that split. It is the thing to
preserve if any of this is revisited.

## Layout

| File | Holds | Depends on a clock? |
|---|---|---|
| `key.rs` | `AddrKey`, the compact address | No — pure |
| `policy.rs` | Retry delays, class weights, forget rules | No — pure, takes `now` |
| `table.rs` | Entries, classification, eviction, the pick | No — takes `now` |
| `banlist.rs` | CIDR and exact-host bans, own file | Only for its own file |
| `persist.rs` | Snapshot load and save | No |
| `mod.rs` | The manager task, `Handle`, `Dialer` | Yes — the only one |

The split is for testability. Everything except `mod.rs` is synchronous and
takes an explicit `now`, so the policy can be checked against a table of
expected values rather than by running a crawler for a day. `Dialer` is a
trait, so the manager itself can be driven in tests without opening sockets.

## Addresses

`AddrKey` is one enum covering all five networks. Onion and I2P addresses are
held as their raw 32-byte keys, not as 62-character strings; the `.onion`
hostname is computed only for display. An enum costs exactly what a flat
tagged byte array would, because both are sized by the largest variant, so
keeping each network's address length in the type is free.

Two details that matter:

- **IPv4-mapped IPv6 collapses to IPv4**, so one peer cannot occupy two
  entries.
- **CJDNS keeps its own tag.** The same bytes reached over CJDNS and over
  plain IPv6 need different networks enabled, so they are genuinely different
  addresses to us.

## What is stored

One `Entry` per address, about 70 bytes of payload:

- `services`, `ntime`, `last_announced` — what gossip says. Refreshed on every
  re-announcement; the old store froze service flags at whatever the first
  announcement happened to say.
- `last_attempt`, `last_success`, `next_attempt`
- `failures`, `short_sessions` — consecutive counters
- `last_attempt_failed` — separates good from lapsed
- `origin` — `Manual` or `Gossip`
- `transport` — see below

### Classes are derived, not stored

| Class | Meaning |
|---|---|
| `unknown` | No result yet |
| `good` | The most recent attempt succeeded |
| `lapsed` | Has connected before, most recent attempt failed |
| `bad` | Tried at least once, never once connected |

Classification keys off `failures`, not `last_attempt`. That distinction is
load-bearing: `pick` records a dial start, so using `last_attempt` as "has been
tried" made an address look `bad` the moment it was first picked — before any
result existed — which also quietly skewed the class weights, because the
unknown pool drained into the bad pool as it was dialled.

`active` (dialing / connected) is tracked separately and **never persisted**.
After a restart no tasks exist, so anything stored as in-flight would be
undialable forever.

## The manager task

The manager owns all of the state outright. Nothing is behind an
`Arc<Mutex<..>>`, so there is no lock for a scan of the table to hold while
gossip and connection outcomes queue behind it — they wait in channels instead.
The old store was shared between the connect loop, the address task and the RPC
handler, and `get_batch` held the mutex for the whole walk.

It selects over five things:

| Source | Shape | Why |
|---|---|---|
| 1s tick | — | Pick and dial |
| Lifecycle | **Unbounded** | `EndGuard::drop` must post to it; `Drop` cannot await, and `try_send` could drop the message that frees a slot |
| Gossip | Bounded, lossy | Addresses are re-announced constantly; dropping a batch under load beats blocking a connection task |
| Commands | Bounded, oneshot replies | RPC, instead of locking the store |
| 5min tick | — | Save the snapshot |

### Connection tasks are single-shot

Dial, handshake, run the session, report, exit. They hold no retry state and
decide nothing about when an address is tried again. `initial_connect`,
`reconnect_loop`, two attempt counters, the backoff sleeps and the store's
separate one-hour bad-address retry are all gone — two schedules for the same
decision meant some cases were handled twice and others not at all.

`EndGuard` is what makes that safe. It is taken first and dropped last, and
`Drop` runs on a normal return, an early `?`, a panic and on
`JoinHandle::abort`. The manager therefore always learns the attempt is over.
Previously a task that died unexpectedly left its address in the active set for
the lifetime of the process.

## The pick

One pass over the table per tick. Candidates are reservoir-sampled per class,
so nothing is collected or sorted — the old `get_batch` walked every table and
sorted all of `good` once a second to use ten of them.

Order of claim on a tick:

1. **Manual** — operator and bootstrap addresses, ahead of everything.
2. **Due reconnects to `good`** — outside the dial budget, because staying
   connected is the point, but capped by `MAX_RECONNECTS_PER_TICK`.
3. **The budget**, split between `unknown` / `lapsed` / `bad` at 70/20/10.

Skipped: anything active, banned, on a disabled network, or not yet due.

### Why reconnects need a cap

The design notes took *all* due reconnects, which is unbounded. After any
downtime every good entry's `next_attempt` is already in the past, so one tick
would dial the entire good table — thousands of sockets at once and a
thundering herd at the peers. Jitter does not help, because those delays have
already elapsed.

### Why the weights are credit-based

Shares accumulate as credit across ticks and each slot goes to whichever class
is owed most, debiting a whole dial from it.

Taking `floor(credit)` per class and sharing out the leftover does not work at
a budget of one dial per tick: every class floors to zero, so the leftover
decides every pick and whichever class the loop visits first wins every time
without being charged for it. Measured over 1000 single-dial ticks, the
current scheme lands within a couple of points of 70/20/10.

A class with no candidates is skipped, so its share flows to the others rather
than being wasted, but it keeps its credit and gets the share back as soon as
it has candidates again — bounded by `CREDIT_CAP` so a long dry spell cannot
bank a flood.

## Retry policy

All in `policy.rs`, all pure. Starting values, each with ±10% jitter:

| Situation | Delay | Cap |
|---|---|---|
| Session ended after ≥31s | 5s | — |
| Session ended under 31s (likely eviction) | 60s · 2^(k−1) | 1h |
| Failed, has connected before | 60s · 2^(n−1) | 6h |
| Failed, never connected | 1h · 4^(n−1) | 7d |
| Our own fault | 30s | — |
| Manual | 60s fixed | — |

`n` is consecutive failures, `k` consecutive short sessions.

### `OurFault` is not a failure

A missing route, or a Tor proxy that is not running, says nothing whatsoever
about the peer. It does not count as a failure and does not change the
address's class. The old code recorded `NetworkUnreachable` as a bad address,
so running without IPv6 connectivity quietly poisoned the store with every
IPv6 address it was ever told about — and then inconsistently did *not* record
it that way on the reconnect path.

`ENETUNREACH` is ours. `EHOSTUNREACH` stays the peer's, since it usually comes
from a router near the destination.

### Forgetting

- Connected before: forget once the last success is over 30 days old.
- Never connected: forget after 3 failures if not re-announced in 30 days, or
  after 5 failures regardless. The second rule stops an attacker keeping dead
  entries resident by re-gossiping them.
- Manual: never.

## Bounding growth

Inventing addresses is free, so none of these bounds may depend on peers
behaving.

1. **Per-connection token bucket**, ~0.1 addr/s with a burst of 1000, as
   Bitcoin Core does it. One peer can teach us about roughly 8.6k addresses a
   day. This is the most effective single bound. The reply to our own GETADDR
   is exempt — we asked for it, and the protocol caps it at 1000 anyway.
2. **Hard capacity**, default 2M entries (a few hundred MB). When full,
   eviction takes an entry already past its forget rule, or failing that a
   random `unknown`.
3. **`good`, `lapsed` and `manual` are never evicted** to make room for an
   unknown. This is what stops a flood of invented addresses from displacing
   peers we have actually reached — tested with 5000 gossiped addresses
   against a cap of 100.
4. **nTime is clamped** to now + 10 minutes, so a peer cannot claim an address
   is permanently fresher than every honest one.

### On dropping Core's buckets

Bitcoin Core's addrman buckets addresses by source group, which buys eviction
resistance and source diversity. That is deliberately not reproduced here. For
a crawler the crawl bias *is* the output, so the loss would normally be
serious — but the `AddressAnnouncement` event carries the source peer and is
emitted *before* the rate limit, so the share of the table owed to any one peer
or network can be measured offline from the archive instead.

That link is the whole justification. Trimming that event would quietly remove
the ability to detect the thing the buckets were protecting against.

## Transport hints

Per address, so a v1-only peer is not probed with v2 forever.

| Hint | Behaviour |
|---|---|
| `Unknown` | Try v2; if TCP connected but the v2 handshake failed, record `V1Only` and retry with v1 in the same attempt |
| `V2` | v2 only. A failure is a failed attempt, never a downgrade |
| `V1Only { since }` | v1 directly. Reset to `Unknown` when gossip advertises `P2P_V2`, or after 7 days — nodes do get upgraded |

This replaces an in-memory `skip_v1_fallback` flag that was lost whenever the
connection task exited, and it fixes a guard whose condition was inverted:
`ServiceFlags::has` is `(self | flags) == self`, so `has(NONE)` was true for
every flag set, and every address with unknown services went straight to v1.
Combined with service flags only ever being recorded on first sight, an address
got a v2 attempt only if the very first gossip that mentioned it already
advertised `P2P_V2`.

## Persistence

`addresses-<network>.bin`, postcard, written to a temp file, fsynced, and
renamed. At two million entries the difference from JSON is hundreds of
megabytes, and nothing outside the process reads the file.

**`load` cannot fail.** Missing, unreadable, truncated or a different format
version all log and return an empty table. This is the point of treating the
table as a cache. The old JSON store made `main` panic on a half-written file,
and only deleting it by hand would get the process started again.

A snapshot from a different format version is discarded rather than migrated,
for the same reason: guessing at the fields of a layout we do not know is worse
than relearning.

## Ban list

`banlist-<network>.json`, separate from the snapshot and hand-editable. CIDR
`nets` for the IP networks, exact `hosts` for Tor and I2P, which have no prefix
to match. Checked on ingest and on pick; banning also purges what is already
stored.

A malformed ban list **is** fatal, unlike the snapshot. It is operator intent,
and dialling addresses we were told never to dial is worse than not starting.

## Research events

Beyond the existing `ping_rtt` and `block_announcement`:

- **`address_announcement`** — addr vs addrv2, solicited or not, how many
  entries arrived, how many the rate limit dropped, and the parsed entries with
  unclamped nTime. Emitted before the rate limit, so a flood is visible rather
  than silently discarded.
- **`connection_attempt`** — the outcome of every attempt whether or not it
  reached a session, with failure reason and duration. Previously only
  successful contacts left any trace, so the data could not distinguish a peer
  that was never reachable from one nobody tried. `OurFault` is a distinct
  result, so an outage on our side does not read as the network becoming
  unreachable.

## Known limitations

Recorded deliberately rather than discovered later.

- **Forgotten entries can return.** There is no tombstone, so a dropped
  address re-announced by any peer comes back as `unknown` with no history. An
  attacker can therefore keep us re-testing garbage indefinitely. What bounds
  this is the rate limit, not the forget rule. A negative cache would cost
  memory, which is the thing the forget rule exists to save.
- **Reconnect selection is random** among due candidates, not
  longest-waiting-first, to avoid sorting. With a large `good` table some peers
  wait longer than others; it evens out across ticks.
- **Class shares are approximate** over short windows. Correct in the steady
  state, not in any single tick.
- **Numbers are starting points.** Capacity, `max_dialing`, dials per tick, the
  weights and every delay need tuning against real load.
- **I2P addresses are stored but not dialled.** `AddrKey` and the pick handle
  them; there is no transport.
- **A node reachable over several networks occupies several entries** and may
  be connected to more than once. Not deduped, and arguably desirable: it makes
  per-network reachability measurable.
