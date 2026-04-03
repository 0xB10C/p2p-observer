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

## `headertree.tips`

```bash
$ nats request p2p-observer.signet.rpc.headertree.tips ''
[{"branch_len":0,"hash":"000000c0c4c4c8b73438f8a36966a6fbc7b12198c80c89d8e5fb7d1f7f737427","height":225381,"status":"active"}]
```
