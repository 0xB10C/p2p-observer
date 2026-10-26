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

struct CsvLogger {
    block_writer: BufWriter<File>,
    ping_writer: BufWriter<File>,
}

impl CsvLogger {
    fn new() -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let block_filename = format!("block_announcements_{}.csv", timestamp);
        let ping_filename = format!("ping_rtt_{}.csv", timestamp);

        let mut block_writer = BufWriter::new(File::create(&block_filename)?);
        let mut ping_writer = BufWriter::new(File::create(&ping_filename)?);

        // Write headers
        writeln!(
            block_writer,
            "{},{},{}",
            COMMON_HEADER, BLOCK_SPECIFIC_HEADER, TCP_STATS_HEADER
        )?;
        writeln!(
            ping_writer,
            "{},{},{}",
            COMMON_HEADER, PING_SPECIFIC_HEADER, TCP_STATS_HEADER
        )?;

        block_writer.flush()?;
        ping_writer.flush()?;

        tracing::info!(target: TARGET, block_file = %block_filename, ping_file = %ping_filename, "created CSV files");

        Ok(Self {
            block_writer,
            ping_writer,
        })
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

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
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
