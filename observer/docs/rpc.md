# RPC

## `addresses.info`

Returns counts of addresses in each table (unknown, good, bad, manual, banned).

```bash
$ nats request p2p-observer.signet.rpc.addresses.info ''
{"bad":19,"good":4,"manual":0,"unknown":2556,"banned":3}
```

## `addresses.add`

Add addresses to the manual table. Returns count of addresses added.

```bash
$ nats request p2p-observer.signet.rpc.addresses.add '["1.2.3.4:8333", "5.6.7.8:8333"]'
{"added":2}
```

## `headertree.tips`

Get chain tips from the header tree — the set of header chains not referenced as a parent by another header.

```bash
$ nats request p2p-observer.signet.rpc.headertree.tips ''
[{"branch_len":0,"hash":"000000c0c4c4c8b73438f8a36966a6fbc7b12198c80c89d8e5fb7d1f7f737427","height":225381,"status":"active"}]
```

## `banlist.add`

Add one or more ban entries (with optional comments) to the banlist. Each entry contains a list of CIDR networks to ban. Returns count of networks added.

```bash
$ nats request p2p-observer.signet.rpc.banlist.add '[{"comment":"spammy node","nets":["1.2.3.4/32"]},{"comment":"bad ASN","nets":["10.0.0.0/8","2001:db8::/32"]}]'
{"added":3}
```

Bare IP addresses default to `/32` (IPv4) or `/128` (IPv6):

```bash
$ nats request p2p-observer.signet.rpc.banlist.add '[{"nets":["1.2.3.4"]}]'
{"added":1}
```

## `banlist.list`

List all ban entries with their comments and networks.

```bash
$ nats request p2p-observer.signet.rpc.banlist.list ''
[{"comment":"spammy node","nets":["1.2.3.4/32"]},{"comment":"bad ASN","nets":["10.0.0.0/8","2001:db8::/32"]},{"nets":["1.2.3.4/32"]}]
```
