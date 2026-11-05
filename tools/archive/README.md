# Event archives

Tooling to archive and replay p2p-observer events.

## archiver

Subscribes to a NATS server and writes the events it receives to binary files
on disk. By default every event type is archived; the type flags narrow that,
so several archivers can run side by side for different recording jobs.

### File format

Each file is a protobuf `ArchiveHeader` from `common/proto/archive.proto`
followed by a sequence of `PeerEvent`s from `common/proto/events.proto`, all
length-delimited:

```
[ varint length ][ ArchiveHeader bytes ]
[ varint length ][ PeerEvent bytes ]
[ varint length ][ PeerEvent bytes ]
...
```

An event is written exactly as it arrived on NATS. It is decoded on the way
past, but only to decide whether it matches the filter and to reject anything
that is not an event at all — re-encoding it would silently drop any field this
build does not know about, which is the one thing a long-lived archive must not
do.

### Why there is a header

A `PeerEvent` carries no network. On the wire that lives only in the subject,
`p2p-observer.<network>.<event>`, so an archive of bare payloads would not say
which chain it came from. One archive covers one network — matching how the
observer runs, one instance per network — and the header records which, once,
rather than repeating it on every event.

The header also lists the event kinds the archiver was recording, always in
full. That is what lets a reader tell "no address announcements happened" apart
from "address announcements were not being recorded", which is otherwise
unknowable from a file that simply has none in them.

### What the archive cannot tell you, and what it can

Events reach the archiver over NATS, and the observer hands them to its
publisher with a `try_send` that drops rather than block a connection task. So
the stream is lossy by design, and an archive is a sample rather than a
complete record.

Every `PeerEvent` therefore carries `dropped_events`: how many the observer
failed to queue since it started. A reader diffs it between consecutive events
to see where the gaps are, and a decrease means the observer restarted. It is a
running count rather than a sequence number precisely so that it survives
filtering — an archive written with `--ping-rtt` alone would show sequence gaps
everywhere, with no way to tell a filtered-out event from a lost one.

When the queue runs short the observer sheds address announcements first, so
a loss is most likely gossip, which peers re-announce, and least likely a
handshake or a disconnect, which they do not. Losses cluster at observer
startup, where every connection handshakes at once and each answers a GETADDR.

The same losses are broken down by kind in `dropped_by_kind`, present only
once something has been lost. Gossip is the expected entry; any other kind
there is a loss the drop policy did not intend.

Every event also carries `instance_id`, a random value chosen when the
observer started. `connection_id` counts from zero per process, and the
archiver is built to outlive the observer, so this is what keeps a join on
`connection_id` from mixing two connections across a restart.

### Compression

Files are compressed with streaming zstd and written as `.bin.zst` directly.
The default level is 18. The top levels (20-22) compress barely better while
costing far more CPU and memory; `--compression-level 3` is much faster at a
still-useful ratio, and `--compression-level 0` writes plain `.bin`.

On live signet traffic level 18 gets events down to about 15 bytes each on disk,
against about 104 uncompressed — the events are highly repetitive, which is what
zstd is good at.

`--max-file-size` is checked against the compressed output, so it is a limit on
disk usage rather than on event volume. It overshoots, and by more than a
rounding error: zstd holds a whole block in its own buffers, and nothing reaches
the tracked count until that block is emitted. A 4 KB limit on live signet
traffic produced a 20 KB file. The limit is a floor on file size, not a ceiling,
so set it to the size you want and expect the first block past it.

### Shutting down

On Ctrl+C or SIGTERM the archiver unsubscribes, writes out the events already
in flight,
and closes the file properly, giving up after 10 seconds. Without that wait the
tail of the stream and zstd's final frame would both be lost, which is the
difference between a readable archive and a truncated one.

### Example

Archive everything on signet, rotating at 100 MB:

```
$ cargo run --bin p2p-observer-archiver -- \
    --network signet \
    --output-dir ./archive \
    --base-name signet \
    --max-file-size 104857600
```

Archive only what the address manager cares about, which is the long-running
job the compression is there for:

```
$ cargo run --bin p2p-observer-archiver -- \
    --network signet \
    --output-dir ./archive \
    --address-announcements --connection-results
```

### Usage

```
Archive p2p-observer events to disk

Usage: p2p-observer-archiver [OPTIONS] --network <NETWORK> --output-dir <OUTPUT_DIR>

Options:
  -a, --nats-url <NATS_URL>
          The NATS server to subscribe to [default: nats://localhost:4222]
  -n, --network <NETWORK>
          The network to archive, as the observer spells it in its config
  -o, --output-dir <OUTPUT_DIR>
          Directory to write archive files to. Created if it does not exist
  -b, --base-name <BASE_NAME>
          Base name for archive files [default: archive]
      --max-file-size <MAX_FILE_SIZE>
          Bytes on disk before rotating to a new file [default: 1073741824]
      --compression-level <COMPRESSION_LEVEL>
          Zstd compression level, 1 to 22. 0 writes plain `.bin` files [default: 18]
      --ping-rtt
          Archive ping RTT events
      --block-announcements
          Archive block announcement events
      --address-announcements
          Archive address announcement events
      --connection-results
          Archive connection result events
      --handshakes
          Archive version handshake events
      --compact-block-probes
          Archive compact block probe events
      --fee-filters
          Archive fee filter events
      --send-cmpcts
          Archive sendcmpct events
  -h, --help
          Print help
  -V, --version
          Print version
```

`RUST_LOG` sets the log level, as elsewhere in the workspace.

## stats

Adds up what is in one or more archives and prints it as a few tables: how
much the files cover, how sessions ended, the hosts with the most sessions,
hosts announcing blocks the observer could not place at a height, user agents
by the number of hosts running them, distinct block hashes by leading zero
digits, and service bits for handshakes and gossiped entries.

Everything is keyed by host, so a host that opens six thousand sessions is one
row rather than six thousand. That is what the tables are for: the questions a
reader asks first of an archive -- who dominates it, whether another chain is
riding on this network's magic, which claims not to believe -- are all answered
by a host that stands out from the rest.

Two things the tables keep apart on purpose. Blocks without a height are
counted separately from blocks with one, because a chain that kept this
network's magic and changed the rules announces blocks the header tree
refuses, and mixed in they distort every block number. A services field with
every bit set is one row of its own rather than one count on each of sixty-four
bits, because a few sources gossip such fields by the hundred thousand.

```bash
$ cargo run --bin p2p-observer-stats -- archive/mainnet.*.bin.zst --top 10
```
== coverage (mainnet)
  events                            33
  span                              2026-10-25T12:00:00Z to 2026-10-25T17:03:00Z (0d 05h 03m)
  observer instances                1
  events dropped by the observer    12
  hosts seen                        4
  hosts that completed a handshake  4
  sessions ended                    11
  block announcements               10
  distinct block hashes             4

== how sessions ended
  decode_error         1   9.1%
  peer_closed          10  90.9%
  (peer sent nothing)  6   54.5%

== attempts that never reached a session
  connection_refused  1  100.0%
  (our fault)         0

== hosts by sessions (top 10)
  host           sessions  silent  mean s  longest s  decode err  failed  unplaced  rate limited  user agent
  198.51.100.7   6         6       60      60         0           0       6         0             /Satoshi:25.1.0/
  192.0.2.10     3         0       4,000   7,200      0           0       0         3             /Satoshi:30.0.0/
  203.0.113.42   1         0       900     900        1           1       0         0             /btcwire:0.5.0/btcd:0.24.2/
  [2001:db8::1]  1         0       1,800   1,800      0           0       0         0             /Satoshi:29.0.0/

== hosts announcing blocks without a height (1 hosts, top 10)
  host          unplaced  sessions  user agent
  198.51.100.7  6         6         /Satoshi:25.1.0/

== user agents by hosts (top 10)
  user agent                   hosts  handshakes
  /Satoshi:25.1.0/             1      6
  /Satoshi:29.0.0/             1      1
  /Satoshi:30.0.0/             1      2
  /btcwire:0.5.0/btcd:0.24.2/  1      1

== distinct block hashes by leading zero hex digits
  zeros  with height  without height
  16     0            1
  19     3            0

== handshake service bits (10 fields)
  bit  name             fields  share
  0    network          4       40.0%
  2    bloom            2       20.0%
  3    witness          4       40.0%
  10   network_limited  4       40.0%
  all  every bit set    0       0.0%

== gossiped entry service bits (2 fields)
  bit  name             fields  share
  0    network          1       50.0%
  3    witness          1       50.0%
  10   network_limited  1       50.0%
  all  every bit set    1       50.0%


```

### Usage

```
Summarise p2p-observer archive files

Usage: p2p-observer-stats [OPTIONS] <FILE>...

Arguments:
  <FILE>...  Archive files to read, either `.bin` or `.bin.zst`. Read in the order given, as one stream

Options:
      --top <TOP>  Rows to show in the per-host and per-user-agent tables [default: 20]
  -h, --help       Print help
  -V, --version    Print version
```

## replayer

Reads archive files and prints what is in them, in the same one-line form the
`logger` tool prints live events. Both call the same renderer in
`common::render`, so replayed output cannot drift from live output.

Takes `.bin` and `.bin.zst`. One unreadable file does not stop the others — a
truncated archive is a normal thing to find after a crash — but the exit status
is non-zero if any file failed.

```bash
$ cargo run --bin p2p-observer-replayer -- archive/signet.20261025-120000-000.bin.zst
 ```

### Example output

```text
INFO replayer: header: created=1761393600 network=signet events=[PingRtt, BlockAnnouncement, AddressAnnouncement, ConnectionResult, Handshake, CompactBlockProbe, FeeFilter, SendCmpct]
INFO replayer: [1] conn=42 peer=1.2.3.4:38333 ua="/Satoshi:30.0.0/" transport=v2 version=70016 services=0x409 height=328019 relay=true skew=-1s addrv2=true wtxidrelay=true sees_us=0.0.0.0:0 ts=1761393601000
INFO replayer: [2] conn=42 peer=1.2.3.4:38333 ua="/Satoshi:30.0.0/" transport=v2 rtt=37ms srtt=38000µs rttvar=4000µs retrans=0 cwnd=10 minrtt=37500µs lost=0 reorder=3 rate=120000B/s rx=4096B ts=1761393601123
INFO replayer: [3] conn=42 peer=1.2.3.4:38333 message=Addrv2 addresses=1000 solicited=true tokens=10.0 ts=1761393602456
INFO replayer: total: 3 events
```

### Usage

```
Read and display p2p-observer archive files

Usage: p2p-observer-replayer [OPTIONS] <FILE>...

Arguments:
  <FILE>...  Archive files to read, either `.bin` or `.bin.zst`

Options:
  -h, --help     Print help
  -V, --version  Print version
```
