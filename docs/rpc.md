# RPC

## `addresses.info`

```bash
$ nats request p2p-observer.signet.rpc.addresses.info ''
{"bad":19,"good":4,"manual":0,"unknown":2556}
```

## `addresses.add`

```bash
$ nats request p2p-observer.signet.rpc.addresses.add '["1.2.3.4:8333", "5.6.7.8:8333"]'
{"added":2}
```
