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
$ cargo run --bin archiver -- \
    --network signet \
    --output-dir ./archive \
    --base-name signet \
    --max-file-size 104857600
```

Archive only what the address manager cares about, which is the long-running
job the compression is there for:

```
$ cargo run --bin archiver -- \
    --network signet \
    --output-dir ./archive \
    --address-announcements --connection-results
```

### Usage

```
Archive p2p-observer events to disk

Usage: archiver [OPTIONS] --network <NETWORK> --output-dir <OUTPUT_DIR>

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

## replayer

Reads archive files and prints what is in them, in the same one-line form the
`logger` tool prints live events. Both call the same renderer in
`common::render`, so replayed output cannot drift from live output.

Takes `.bin` and `.bin.zst`. One unreadable file does not stop the others — a
truncated archive is a normal thing to find after a crash — but the exit status
is non-zero if any file failed.

```bash
$ cargo run --bin replayer -- archive/signet.20261025-120000-000.bin.zst
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

Usage: replayer [OPTIONS] <FILE>...

Arguments:
  <FILE>...  Archive files to read, either `.bin` or `.bin.zst`

Options:
  -h, --help     Print help
  -V, --version  Print version
```
