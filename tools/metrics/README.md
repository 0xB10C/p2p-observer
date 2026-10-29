# metrics

Turns the observer's events into Prometheus metrics. Modelled on the
metrics tool of peer-observer: subscribe to NATS, count and sample, serve
`/metrics` over HTTP.

```sh
cargo run --release --bin metrics        # NATS at localhost:4222, metrics at 127.0.0.1:8282
curl -s 127.0.0.1:8282/metrics
```

By default every network's events are followed and every series carries a
`network` label; `--network` narrows that. The same scrape config as any
other target:

```yaml
scrape_configs:
  - job_name: p2p-observer
    static_configs:
      - targets: ["127.0.0.1:8282"]
```

## Two groups

The **infrastructure** metrics are about the pipeline from the observer to
here, and answer "is the data complete and current?":

- `events_total` and `event_bytes_total` by event kind: what arrives, and
  how much of it.
- `event_delay_seconds`: the event's timestamp against its arrival here.
  Queueing in the observer and NATS, plus any clock difference.
- `observer_dropped_events` and `..._by_kind`: what the observer failed to
  hand to its publisher, as reported on every event. Address announcements
  are shed first and are the expected entry; anything else is a loss the
  drop policy did not intend.
- `observer_restarts_total`: the instance id changing between two events.
- `undecodable_events_total`, `last_event_timestamp_seconds`,
  `start_timestamp_seconds`.
- `connection_attempts_total{result="our_fault"}`: attempts that said
  nothing about the peer, by what was wrong on our side -- the Tor proxy
  down, a network unreachable.

The **network** metrics are what the events say about the peers:

- Attempts and sessions: `connection_attempts_total` by result and reason,
  `connection_setup_seconds`, `session_duration_seconds`,
  `session_messages_total` by command, `unsolicited_pongs_total`.
- Handshakes: `handshakes_total` by transport, and the peer's claims by user
  agent, protocol version, service bit and feature; `handshake_clock_skew_seconds`;
  `handshake_height_delta` against `best_height`, the highest height any
  announcement has carried.
- The path: `ping_rtt_seconds` and the kernel's view of the socket at the
  pong, `ping_tcp_*`.
- Blocks: `block_announcements_total` and `blocks_total` by message type,
  `block_propagation_seconds` (how long after the first sighting each further
  peer announced a block), the shape of compact blocks, probe steps.
- Policy: `fee_filter_sat_per_kvb`, `send_cmpct_total` by mode and version.
- Gossip: announcements by message, entries by network and service bit, the
  age of what is announced, what the rate limit discarded, self-announcements.

Every series has its help text in the output; `curl` it for the full list.

## Every series is bounded

A Prometheus series is kept for every label combination ever seen, and some
labels come from the peer. Those are normalised and then capped:

- The user agent loses its parenthesised comments and slashes:
  `/Satoshi:28.1.0(foo)/` is `Satoshi:28.1.0`, and
  `/Satoshi:28.1.0/Knots:20250305/` keeps both segments. After the first
  128 distinct values on a network, a new one counts as `other`.
- Protocol versions are capped the same way, at 32.
- A message command outside the known P2P commands is `other`.
- A service bit without a name is `bit_<n>`: at most 64 values, and the
  unnamed one is exactly the one worth seeing.

There is no per-peer or per-connection series: nothing is labelled by
address, ASN or connection id.

## What the tool keeps

Nothing per connection. Each event is a counter increment or a histogram
sample on its own, which is what makes the tool indifferent to how many
connections the observer has. What it does remember, per network, is small:
which observer run is sending, the best height announced, and the first
sighting of the last 64 blocks.

That last one is what `block_propagation_seconds` is measured from: the
announcement the observer marked as the first it heard of the block is the
zero, and every later announcement of the same hash is a sample. A block
whose first sighting this tool did not see -- it started later, or that
event was dropped -- yields no samples.

Open connections are not counted. That would need the tool to remember
every connection from its handshake to its result and to guess at the ones
that were open when it started; the websocket tool's connections page is
where that population is shown.

## Usage

```
Serve Prometheus metrics computed from p2p-observer events

Usage: metrics [OPTIONS]

Options:
  -a, --nats-url <NATS_URL>  The NATS server to subscribe to [default: nats://localhost:4222]
  -n, --network <NETWORK>    Only events of this network; all networks by default
  -l, --listen <LISTEN>      The address the HTTP server listens on; the metrics are at /metrics [default: 127.0.0.1:8282]
  -h, --help                 Print help
  -V, --version              Print version
```

`RUST_LOG` sets the log level, `info` by default.
