# RPC

Request/reply over NATS, on `p2p-observer.<network>.rpc.<method>`.

Every address method is answered by the address manager over its command
channel, so an RPC never blocks dialling. If the manager has shut down, the
reply is `{"error":"address manager unavailable"}`.

The examples below use the `nats` CLI. The `rpc` tool in [`tools/rpc`](../../tools/rpc)
wraps the same methods as subcommands, so the subject and the JSON payload
need not be typed:

```bash
$ p2p-observer-rpc --network signet addresses inspect 1.2.3.4:38333
```

## `addresses.info`

Counts per class, plus how many attempts are in flight.

Classes are derived from an address's history rather than stored: `unknown`
has never produced a result, `good`'s last attempt succeeded, `was_good` has
connected before but not most recently, and `bad` has been tried and has never
once connected.

```bash
$ nats request p2p-observer.signet.rpc.addresses.info ''
{"bad":19,"connected":8,"dialing":3,"good":42,"total":2622,"unknown":2556,"was_good":5}
```

## `addresses.add`

Add addresses to dial, as the operator. These are tried ahead of everything
else, keep a short fixed retry however badly they behave, and are never
forgotten or evicted.

Unparseable input is reported rather than dropped.

```bash
$ nats request p2p-observer.signet.rpc.addresses.add '["1.2.3.4:8333", "nonsense"]'
{"added":1,"rejected":["nonsense"]}
```

## `addresses.inspect`

Everything stored about one address. `null` if we have never heard of it.
Timestamps are unix seconds; `0` means never.

```bash
$ nats request p2p-observer.signet.rpc.addresses.inspect '"1.2.3.4:38333"'
{"addr":"1.2.3.4:38333","class":"good","failures":0,"last_announced":1792800000,
 "last_attempt":1792801000,"last_success":1792801001,"next_attempt":1792801006,
 "origin":"Gossip","services":1033,"short_sessions":0,"transport":"V2"}
```

## `addresses.due`

The addresses due to be dialled soonest, for debugging the pick. Takes an
optional limit; defaults to 20.

```bash
$ nats request p2p-observer.signet.rpc.addresses.due '5'
[{"addr":"1.2.3.4:38333","next_attempt":1792801006}, ...]
```

## `connections.list`

The sessions running right now: one entry per connection whose handshake has
completed, with what the peer claimed as it claimed it.

This is the one question the event stream cannot answer. A consumer that
attaches now cannot learn about a session that handshook an hour ago, because
the handshake that described it has already gone past; it sees such a
connection only when something next happens on it, with everything the
handshake said missing for good. Attempts still dialling are not sessions and
are not listed, but `dialing` says how many there are.

A connection id counts from zero per observer run, so `instance_id` is what
makes the pair identify a connection; it is the same value the events carry.
The totals on each entry are refreshed on that session's own ping timer rather
than as they change, so `updated_ms` says how old they are, and is 0 before
the first ping of a session. Everything that moves faster is on the event
stream.

```bash
$ nats request p2p-observer.signet.rpc.connections.list ''
{"taken_ms":1793657370723,"instance_id":3553736845035775826,"connected":2,"dialing":3,"connections":[{"addr":"1.2.3.4:38333","addr_recv":"0.0.0.0:0","connected_ms":1793657310700,"connection_id":41,"messages":37,"min_rtt_ms":35,"peer_timestamp":1793657310,"protocol_version":70016,"relay":true,"rtt_ms":37,"sendaddrv2":true,"services":1033,"start_height":225381,"transport_version":2,"unsolicited_pongs":0,"uptime_ms":60023,"updated_ms":1793657350700,"user_agent":"/Satoshi:30.0.0/","wtxid_relay":true}, ...]}
```

## `headertree.tips`

Chain tips from the header tree — headers not referenced as a parent by
another header.

```bash
$ nats request p2p-observer.signet.rpc.headertree.tips ''
[{"branch_len":0,"hash":"000000c0c4c4c8b73438f8a36966a6fbc7b12198c80c89d8e5fb7d1f7f737427","height":225381,"status":"active"}]
```

## `banlist.add`

Ban addresses, so they are never dialled. Each entry takes CIDR `nets` for the
IP networks and exact `hosts` for Tor and I2P, which have no prefix to match
against. Banning also drops anything already stored that matches, reported as
`purged`.

The list lives in its own `<datadir>/<network>/banlist.json` rather than
inside the address snapshot, because the snapshot is a disposable cache and a
hand-maintained ban list is not. The file is rewritten on each ban; if that
write fails the ban is still in effect in memory and the reply carries a
`save_error`, since it will not survive a restart.

```bash
$ nats request p2p-observer.signet.rpc.banlist.add '[{"comment":"spammy node","nets":["1.2.3.4/32"]},{"comment":"bad ASN","nets":["10.0.0.0/8","2001:db8::/32"]}]'
{"added":3,"purged":11}
```

Bare IPs default to `/32` (IPv4) or `/128` (IPv6):

```bash
$ nats request p2p-observer.signet.rpc.banlist.add '[{"nets":["1.2.3.4"]}]'
{"added":1,"purged":0}
```

Tor and I2P are banned by exact host:

```bash
$ nats request p2p-observer.signet.rpc.banlist.add '[{"hosts":["abc...xyz.onion:8333"]}]'
{"added":1,"purged":1}
```

## `banlist.list`

All ban entries, with their comments.

```bash
$ nats request p2p-observer.signet.rpc.banlist.list ''
[{"comment":"spammy node","nets":["1.2.3.4/32"],"hosts":[]}]
```
