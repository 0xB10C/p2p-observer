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

On Ctrl+C the archiver unsubscribes, writes out the events already in flight,
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
INFO replayer: header: created=1761393600 network=signet events=[PingRtt, BlockAnnouncement, AddressAnnouncement, ConnectionResult]
INFO replayer: [1] conn=42 peer=1.2.3.4:38333 ua="/Satoshi:30.0.0/" transport=v2 rtt=37ms ts=1761393601123
INFO replayer: [2] conn=42 peer=1.2.3.4:38333 message=Addrv2 addresses=1000 ts=1761393602456
INFO replayer: total: 2 events
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
