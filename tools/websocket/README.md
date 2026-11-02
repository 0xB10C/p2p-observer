# websocket

Forwards the observer's events to browsers over a websocket, and ships the
pages that render them. Modelled on the websocket tools of peer-observer and
spytrap: the same `websockets.json` picker, so a page can switch between
several instances.

```sh
# IP -> ASN data: Bitcoin Core's asmap, optional but recommended
curl -sSfL -o latest_asmap.dat https://raw.githubusercontent.com/bitcoin-core/asmap-data/main/latest_asmap.dat
cargo run --release --bin websocket -- --asmap latest_asmap.dat   # websocket on 127.0.0.1:47484
# serve tools/websocket/www with any static file server, then open
# http://127.0.0.1:8000/peers.html?ws=ws://127.0.0.1:47484
```

By default every network's events are followed; `--network` narrows that.

## The tool keeps nothing

An event is decoded, tagged with its network and the peer's autonomous
system, and written to the clients that asked for that kind of event. There
are no snapshots, no histories and no timers: the cost per client is one
serialisation per event, whether a page shows fifty connections or fifty
thousand.

What that means for a page: it starts empty and fills as the network talks.
A connection appears with its first event, and since the observer pings every
two minutes, a page has the whole population within about that time. For
anything that happened before the page was opened, replay an archive.

The pages say which of the two they are showing. A spinner means no message
has carried that value yet, so it should still arrive: the first event, the
next block, the first ping of a connection seen at its handshake. Plain text
means the stream has answered: no connection matches the filter, or a
connection that was already open when the page connected, whose handshake is
in the past and will not be seen.

## Pages

`www/` is plain HTML and JavaScript; d3 and Observable Plot are vendored in
`www/js`, nothing is fetched from the network. A `websockets.json` next to the
pages (see `websockets.example.json`) lists the websocket tools to pick from;
`?ws=<url>` in the page URL overrides it. Serve the pages over HTTPS and the
websocket over `wss://` (e.g. behind nginx) when exposing them.

* `index.html` – what the stream carries, one line per observer run.
* `peers.html` – one row per open connection: address, ASN and AS name,
  transport, user agent, what the handshake said, round trips and the
  kernel's view of the socket. Only the rows in view are rendered, so the
  table holds up at tens of thousands of connections. Counting block
  announcements per peer means receiving one event per connection per block,
  so it is a checkbox rather than the default.
* `sessions.html` – a log of the sessions that have ended since the page was
  opened, newest first: how long each ran, how it ended, what the peer
  claimed in its handshake and what it sent while it was up. Separate from
  the connections page because the two are different questions — what is
  connected now, and what has stopped being — and they want opposite sort
  orders. It keeps the most recent few hundred and forgets the rest, and
  marks a session that carried no message at all.
* `blocks.html` – per block, the share of announcements that had arrived so
  many seconds after the first. The time axis ends at the slowest 95th
  percentile among the drawn curves and never goes past twenty seconds, so it
  follows the data instead of a fixed window without one straggling peer
  flattening every curve against the left edge; the table's t99 column is
  where the tail is read. Each curve is drawn from at most 200 samples however
  many peers announced the block.

The snapshot is the one thing here the tool holds on to, and it holds one per
network rather than anything per connection: the earlier version kept a record
of every connection and every closed session, which is what the rework
removed.

Dial outcomes and the population census that earlier versions drew are gone;
counters like those belong in a metrics endpoint rather than in a page that
has to rebuild them from a stream. The ended sessions page is a log and not a
counter: it lists the sessions themselves, and attempts that never reached one
are not in it.

## Protocol

A client starts with no subscriptions. It sends a JSON object naming the
event kinds it wants, and a later object replaces the choice:

```json
{"handshakes": true, "ping_rtt": true, "connection_results": true}
```

The kinds are `ping_rtt`, `block_announcements`, `address_announcements`,
`connection_results`, `handshakes`, `compact_block_probes`, `fee_filters` and
`send_cmpcts`. An unknown key is an error rather than a silent no-op, so a
page cannot quietly subscribe to nothing. Address announcements carry every
gossiped address and are the heaviest kind by far.

`connection_status` is not an event kind but the periodic status update below,
and may be combined with any of them.

On connect the server sends one hello:

```json
{"hello": {"server_time_ms": 1793168356068, "asmap": true}}
```

Event timestamps come from the observer's clock, which `server_time_ms` lets
a page relate to its own. `asmap` says whether to expect `ip` on events.

Then one message per event:

```json
{"event": {"network": "mainnet", "ip": {"asn": 24940, "handle": "HETZNER-AS",
 "description": "Hetzner Online GmbH", "country": "DE"},
 "connection_id": 1271198, "timestamp_ms": 1793168356068,
 "peer_addr": "138.199.234.144:8333", "user_agent": "/Satoshi:32.0.0/",
 "transport_version": 2, "instance_id": 42, "dropped_events": 0,
 "event": {"Handshake": {"protocol_version": 70017, "...": "..."}}}}
```

The inner `event` is the protobuf `PeerEvent` oneof: one key naming the kind.
`ip` is absent without an asmap and for addresses no asmap covers, such as
onion addresses. A client whose queue fills up is disconnected rather than
allowed to slow the others down.

```sh
cargo run -p websocket --example client -- ws://127.0.0.1:47484 '{"handshakes": true}' 1
```

## Status updates

The events say what happens; they cannot say what is connected. A client that
attaches now never sees the handshake of a session that began an hour ago, so
it learns of that connection only when something next happens on it, with
everything the handshake said missing for good.

So a client that subscribes to `connection_status` is sent, every
`--status-interval-secs` (60 by default, 0 to turn it off), what each observer
says it is connected to:

```json
{"status": {"network": "mainnet", "taken_ms": 1793657370723,
 "instance_id": 3553736845035775826, "connected": 6712, "dialing": 24,
 "connections": [{"connection_id": 4352963, "addr": "91.157.99.72:8333",
  "ip": {"asn": 719, "handle": "ELISA-AS", "...": "..."},
  "uptime_ms": 569932, "user_agent": "/Satoshi:29.1.0/",
  "start_height": 973894, "messages": 37, "...": "..."}]}}
```

That is the observer's own `connections.list` reply (see
[`observer/docs/rpc.md`](../../observer/docs/rpc.md)), passed through with the
autonomous system of each peer filled in exactly as on an event, so a field
the observer adds later needs no change here. The tool keeps only the latest
snapshot per network, to answer a client that subscribes between two polls at
once rather than a minute later; subscribing when there is nothing cached asks
for a poll straight away. Nothing is asked of an observer while no client is
subscribed.

Which observers to ask comes from `--network`, or from the networks seen on
the event stream when that is not given, so the first status update then waits
for the first event. A request that fails or times out is logged and skipped,
and a page keeps the snapshot it has until the next one.

## Usage

```
Forward p2p-observer events to browsers over a websocket

Usage: websocket [OPTIONS]

Options:
  -a, --nats-url <NATS_URL>
          The NATS server to subscribe to [default: nats://localhost:4222]
  -n, --network <NETWORK>
          Only events of this network; all networks by default
  -l, --listen <LISTEN>
          The address the websocket server listens on [default: 127.0.0.1:47484]
      --asmap <ASMAP>
          An asmap file for IP to ASN lookups, e.g. latest_asmap.dat from https://github.com/bitcoin-core/asmap-data. Without it events carry no ASN information
  -h, --help
          Print help
  -V, --version
          Print version
```

`RUST_LOG` sets the log level, as elsewhere in the workspace. The integration
test needs a `nats-server`, found through `NATS_SERVER_BINARY` (the nix shell
sets it); without it the test is skipped.
