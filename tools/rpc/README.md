# rpc

A command line client for the observer's NATS request/reply interface, so
the methods in [`observer/docs/rpc.md`](../../observer/docs/rpc.md) can be
called without hand-writing subjects and JSON payloads.

```
$ rpc --network signet addresses inspect 1.2.3.4:38333
{
  "addr": "1.2.3.4:38333",
  "class": "good",
  ...
}
```

The network and NATS server can also come from the environment, which saves
repeating them:

```
$ export P2P_OBSERVER_NETWORK=mainnet P2P_OBSERVER_NATS_URL=nats://localhost:4222
$ rpc addresses info
$ rpc headertree tips
$ rpc banlist add --comment "spammy node" --net 1.2.3.4 --net 10.0.0.0/8
$ rpc addresses due --limit 5
```

Replies are pretty-printed. An `{"error": ...}` reply goes to stderr with
exit status 1, and no reply within `--timeout` seconds (default 5) is reported
the same way, so a script can tell a failed call from an empty answer.
`--raw` prints the reply byte for byte instead.

Methods this tool does not know yet can be called directly:

```
$ rpc call addresses.due 3
```

## Usage

```
Call the p2p-observer RPC over NATS

Usage: rpc [OPTIONS] --network <NETWORK> <COMMAND>

Commands:
  addresses   The address book
  headertree  The header tree
  banlist     The ban list
  call        Call any method with a raw JSON payload
  help        Print this message or the help of the given subcommand(s)

Options:
  -a, --nats-url <NATS_URL>  The NATS server the observer is connected to [env: P2P_OBSERVER_NATS_URL=] [default: nats://localhost:4222]
  -n, --network <NETWORK>    The network of the observer instance to talk to, as spelled in its config [env: P2P_OBSERVER_NETWORK=]
      --timeout <TIMEOUT>    Seconds to wait for a reply [default: 5]
      --raw                  Print the reply exactly as received instead of pretty-printed JSON
  -h, --help                 Print help
  -V, --version              Print version
```
