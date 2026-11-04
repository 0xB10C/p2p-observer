use common::{
    anyhow::Result,
    async_nats,
    events::{BlockAnnouncement, PeerEvent, PingRtt, TcpStats, peer_event},
    futures_util::StreamExt,
    prost::Message,
    tokio, tracing, tracing_subscriber,
};
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_NATS_URL: &str = "nats://localhost:4222";
const NATS_SUBJECT: &str = "p2p-observer.>";
const TARGET: &str = "csv";

// CSV headers with common fields + event-specific fields + tcp_stats
const COMMON_HEADER: &str = "connection_id,timestamp_ms,peer_addr,user_agent,transport_version";
const TCP_STATS_HEADER: &str = "srtt_us,rttvar_us,total_retrans,snd_cwnd,min_rtt_us,lost,reordering,delivery_rate,bytes_received";
// No rtt_ms: a block announcement used to carry the last ping RTT, which could
// be a whole ping interval old. The TCP columns are now sampled as the
// announcement arrives, and carry a minimum RTT of their own.
const BLOCK_SPECIFIC_HEADER: &str =
    "block_hash,announcement_type,batch_size,height,new_to_us,short_ids,prefilled_txs";
const PING_SPECIFIC_HEADER: &str = "rtt_ms";

struct CsvLogger<W: Write> {
    block_writer: W,
    ping_writer: W,
}

impl CsvLogger<BufWriter<File>> {
    fn new() -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let block_filename = format!("block_announcements_{}.csv", timestamp);
        let ping_filename = format!("ping_rtt_{}.csv", timestamp);

        let block_writer = BufWriter::new(File::create(&block_filename)?);
        let ping_writer = BufWriter::new(File::create(&ping_filename)?);

        let mut logger = Self {
            block_writer,
            ping_writer,
        };
        logger.write_headers()?;

        tracing::info!(target: TARGET, block_file = %block_filename, ping_file = %ping_filename, "created CSV files");

        Ok(logger)
    }
}

impl<W: Write> CsvLogger<W> {
    /// The header row of each file, written once when it is created.
    ///
    /// Here rather than inline in `new` so that the rows and the names they
    /// are under come from the same place: a test that built its own header
    /// could not catch the two drifting apart.
    fn write_headers(&mut self) -> Result<()> {
        writeln!(
            self.block_writer,
            "{},{},{}",
            COMMON_HEADER, BLOCK_SPECIFIC_HEADER, TCP_STATS_HEADER
        )?;
        writeln!(
            self.ping_writer,
            "{},{},{}",
            COMMON_HEADER, PING_SPECIFIC_HEADER, TCP_STATS_HEADER
        )?;
        self.block_writer.flush()?;
        self.ping_writer.flush()?;
        Ok(())
    }

    fn write_block_announcement(
        &mut self,
        event: &PeerEvent,
        blk: &BlockAnnouncement,
    ) -> Result<()> {
        let connection_id = event.connection_id;
        let timestamp_ms = event.timestamp_ms;
        let peer_addr = escape_csv(&event.peer_addr);
        let user_agent = escape_csv(&event.user_agent);
        // Empty rather than 0 when absent, matching how the other optional
        // columns are written. 0 is not a transport version.
        let transport_version = event
            .transport_version
            .map(|v| v.to_string())
            .unwrap_or_default();
        let block_hash = &blk.block_hash;
        let announcement_type = blk.announcement_type;

        writeln!(
            self.block_writer,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            connection_id,
            timestamp_ms,
            peer_addr,
            user_agent,
            transport_version,
            block_hash,
            announcement_type,
            blk.batch_size,
            blk.height.map(|h| h.to_string()).unwrap_or_default(),
            blk.new_to_us,
            blk.compact_block
                .as_ref()
                .map(|c| c.short_ids.to_string())
                .unwrap_or_default(),
            blk.compact_block
                .as_ref()
                .map(|c| c.prefilled_txs.to_string())
                .unwrap_or_default(),
            tcp_columns(blk.tcp_stats.as_ref()),
        )?;

        self.block_writer.flush()?;
        Ok(())
    }

    fn write_ping_rtt(&mut self, event: &PeerEvent, ping: &PingRtt) -> Result<()> {
        let connection_id = event.connection_id;
        let timestamp_ms = event.timestamp_ms;
        let peer_addr = escape_csv(&event.peer_addr);
        let user_agent = escape_csv(&event.user_agent);
        // Empty rather than 0 when absent, matching how the other optional
        // columns are written. 0 is not a transport version.
        let transport_version = event
            .transport_version
            .map(|v| v.to_string())
            .unwrap_or_default();
        let rtt_ms = ping.rtt_ms;

        writeln!(
            self.ping_writer,
            "{},{},{},{},{},{},{}",
            connection_id,
            timestamp_ms,
            peer_addr,
            user_agent,
            transport_version,
            rtt_ms,
            tcp_columns(ping.tcp_stats.as_ref()),
        )?;

        self.ping_writer.flush()?;
        Ok(())
    }
}

/// The TCP sample as its columns, in TCP_STATS_HEADER order.
///
/// Every column is empty when the sample is absent, and the per-field options
/// are empty individually on a platform or kernel that does not report them --
/// an empty cell rather than a zero, which would read as "no loss" or "no
/// distance" rather than "not measured".
fn tcp_columns(stats: Option<&TcpStats>) -> String {
    let Some(t) = stats else {
        return ",".repeat(8);
    };
    fn opt<T: ToString>(v: Option<T>) -> String {
        v.map(|v| v.to_string()).unwrap_or_default()
    }
    format!(
        "{},{},{},{},{},{},{},{},{}",
        t.srtt_us,
        t.rttvar_us,
        t.total_retrans,
        t.snd_cwnd,
        opt(t.min_rtt_us),
        opt(t.lost),
        opt(t.reordering),
        opt(t.delivery_rate),
        opt(t.bytes_received),
    )
}

/// A field as RFC 4180 wants it: quoted if it holds anything that would
/// otherwise end the field or the record, with embedded quotes doubled.
///
/// The carriage return belongs on that list and was missing from it. A peer
/// chooses its user agent and nothing between the wire and here takes the
/// control characters out of it, so a peer whose subver held a bare CR wrote a
/// row that a reader splitting on CRLF reads as two, and every column after
/// that point in the file belongs to the wrong name.
fn escape_csv(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_NATS_URL.to_owned());

    let nats = async_nats::connect(&url).await?;
    let mut sub = nats.subscribe(NATS_SUBJECT).await?;

    tracing::info!(target: TARGET, %url, subject = NATS_SUBJECT, "connected to NATS");

    let mut logger = CsvLogger::new()?;

    while let Some(msg) = sub.next().await {
        match PeerEvent::decode(msg.payload.as_ref()) {
            Ok(event) => match &event.event {
                Some(peer_event::Event::PingRtt(ping)) => {
                    if let Err(e) = logger.write_ping_rtt(&event, ping) {
                        tracing::error!(target: TARGET, error = %e, "failed to write ping RTT");
                    }
                }
                Some(peer_event::Event::BlockAnnouncement(blk)) => {
                    if let Err(e) = logger.write_block_announcement(&event, blk) {
                        tracing::error!(target: TARGET, error = %e, "failed to write block announcement");
                    }
                }
                // This tool logs block announcements and ping RTTs. The
                // address, handshake and attempt events are for a separate
                // archiver; ignoring them here keeps the two CSV schemas
                // stable.
                Some(peer_event::Event::AddressAnnouncement(_))
                | Some(peer_event::Event::ConnectionResult(_))
                | Some(peer_event::Event::Handshake(_))
                | Some(peer_event::Event::CompactBlockProbe(_))
                | Some(peer_event::Event::FeeFilter(_))
                | Some(peer_event::Event::SendCmpct(_)) => {}
                None => {}
            },
            Err(e) => {
                tracing::warn!(target: TARGET, subject = %msg.subject, error = %e, "failed to decode event")
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::events::{AnnouncementType, CompactBlockShape};

    /// A minimal RFC 4180 reader: records end at a newline outside quotes,
    /// fields at a comma outside quotes, and a doubled quote inside them is
    /// one quote.
    ///
    /// Spelled out rather than asserting on the bytes, because the bytes are
    /// not what matters. The failure this catches is one where the line looks
    /// perfectly reasonable and a reader makes two records out of it.
    fn parse(csv: &str) -> Vec<Vec<String>> {
        let mut records = Vec::new();
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut chars = csv.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        quoted = false;
                    }
                }
                '"' => quoted = true,
                ',' if !quoted => fields.push(std::mem::take(&mut field)),
                // A record ends at either, and CRLF ends one record and not
                // two: this is the part a bare carriage return in a field
                // would otherwise exploit.
                '\n' | '\r' if !quoted => {
                    if !field.is_empty() || !fields.is_empty() {
                        fields.push(std::mem::take(&mut field));
                        records.push(std::mem::take(&mut fields));
                    }
                }
                c => field.push(c),
            }
        }
        if !field.is_empty() || !fields.is_empty() {
            fields.push(field);
            records.push(fields);
        }
        records
    }

    fn with_headers() -> CsvLogger<Vec<u8>> {
        let mut logger = CsvLogger {
            block_writer: Vec::new(),
            ping_writer: Vec::new(),
        };
        logger.write_headers().unwrap();
        logger
    }

    fn event(user_agent: &str) -> PeerEvent {
        PeerEvent {
            connection_id: 42,
            timestamp_ms: 1_700_000_000_000,
            peer_addr: "1.2.3.4:8333".to_owned(),
            user_agent: user_agent.to_owned(),
            transport_version: Some(2),
            ..Default::default()
        }
    }

    fn tcp_stats() -> TcpStats {
        TcpStats {
            srtt_us: 12_000,
            rttvar_us: 3_000,
            total_retrans: 2,
            snd_cwnd: 10,
            min_rtt_us: Some(11_000),
            lost: Some(1),
            reordering: Some(3),
            delivery_rate: Some(1_250_000),
            bytes_received: Some(4_096),
        }
    }

    fn ping() -> PingRtt {
        PingRtt {
            rtt_ms: 37,
            tcp_stats: Some(tcp_stats()),
        }
    }

    fn announcement() -> BlockAnnouncement {
        BlockAnnouncement {
            block_hash: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_owned(),
            announcement_type: AnnouncementType::CompactBlock as i32,
            tcp_stats: Some(tcp_stats()),
            batch_size: 3,
            height: Some(870_000),
            new_to_us: true,
            compact_block: Some(CompactBlockShape {
                short_ids: 2_500,
                prefilled_txs: 1,
            }),
            unplaced: None,
        }
    }

    /// A user agent is whatever the peer said it was, and must not be able to
    /// end a field or a record.
    ///
    /// Four of the five characters that can were quoted; the carriage return
    /// was not. A peer whose subver carried one wrote a row that a reader
    /// splitting on CRLF reads as two, and from there every value in the file
    /// sits under the wrong name -- quietly, in a file nobody re-reads for
    /// weeks.
    #[test]
    fn test_a_user_agent_cannot_end_a_field_or_a_record() {
        for hostile in [
            "/Satoshi:29.0.0/\r/more/",
            "/Satoshi:29.0.0/\r\n/more/",
            "/Satoshi,29.0.0/",
            "/Satoshi:\"29\".0.0/",
            "/Satoshi:29.0.0/\n/more/",
            "/\r\n\",\r\n/",
        ] {
            let mut logger = with_headers();
            logger.write_ping_rtt(&event(hostile), &ping()).unwrap();
            let csv = String::from_utf8(logger.ping_writer.clone()).unwrap();
            let records = parse(&csv);

            assert_eq!(
                records.len(),
                2,
                "{hostile:?} turned one row into {}: {csv:?}",
                records.len() - 1
            );
            assert_eq!(records[1].len(), records[0].len(), "{hostile:?}");
            assert_eq!(records[1][3], hostile, "{hostile:?} came back changed");
        }
    }

    /// Every row has exactly the fields its header names, whatever is absent
    /// from the event.
    ///
    /// The optional columns are written as empty cells, and an option that
    /// wrote nothing at all -- no cell, no comma -- would shift every column
    /// after it by one without making the file unreadable.
    #[test]
    fn test_every_row_has_the_fields_its_header_names() {
        let sparse_ping = PingRtt {
            rtt_ms: 0,
            tcp_stats: None,
        };
        let sparse_block = BlockAnnouncement {
            tcp_stats: None,
            height: None,
            compact_block: None,
            batch_size: 1,
            new_to_us: false,
            ..announcement()
        };

        let mut logger = with_headers();
        logger
            .write_ping_rtt(&event("/Satoshi:29.0.0/"), &ping())
            .unwrap();
        logger.write_ping_rtt(&event(""), &sparse_ping).unwrap();
        logger
            .write_block_announcement(&event("/Satoshi:29.0.0/"), &announcement())
            .unwrap();
        logger
            .write_block_announcement(&event(""), &sparse_block)
            .unwrap();

        for (what, written) in [
            ("ping", logger.ping_writer.clone()),
            ("block", logger.block_writer.clone()),
        ] {
            let csv = String::from_utf8(written).unwrap();
            let records = parse(&csv);
            assert_eq!(records.len(), 3, "{what}: {csv:?}");
            let names = records[0].len();
            for (i, row) in records.iter().enumerate().skip(1) {
                assert_eq!(row.len(), names, "{what} row {i}: {:?}", records[i]);
            }
        }
    }

    /// A sample the platform did not take is an empty cell and not a zero: a
    /// zero would read as no loss, or as no distance at all.
    #[test]
    fn test_an_untaken_sample_is_an_empty_cell() {
        let mut logger = with_headers();
        logger
            .write_ping_rtt(
                &event("/Satoshi:29.0.0/"),
                &PingRtt {
                    rtt_ms: 37,
                    tcp_stats: None,
                },
            )
            .unwrap();
        let csv = String::from_utf8(logger.ping_writer.clone()).unwrap();
        let records = parse(&csv);
        let header = &records[0];
        let row = &records[1];
        for (name, cell) in header.iter().zip(row) {
            if TCP_STATS_HEADER.split(',').any(|n| n == name) {
                assert_eq!(cell, "", "{name} should be empty when nothing sampled it");
            }
        }

        // And a sample that was taken, where the kernel reports only some of
        // it, keeps the fields it has.
        let mut logger = with_headers();
        logger
            .write_ping_rtt(
                &event("/Satoshi:29.0.0/"),
                &PingRtt {
                    rtt_ms: 37,
                    tcp_stats: Some(TcpStats {
                        min_rtt_us: None,
                        lost: None,
                        reordering: None,
                        delivery_rate: None,
                        bytes_received: None,
                        ..tcp_stats()
                    }),
                },
            )
            .unwrap();
        let csv = String::from_utf8(logger.ping_writer.clone()).unwrap();
        let records = parse(&csv);
        let cell = |name: &str| {
            let i = records[0].iter().position(|n| n == name).unwrap();
            records[1][i].clone()
        };
        assert_eq!(cell("srtt_us"), "12000");
        assert_eq!(cell("min_rtt_us"), "");
        assert_eq!(cell("lost"), "");
    }
}
