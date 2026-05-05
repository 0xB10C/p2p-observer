use common::{
    anyhow::Result,
    async_nats,
    events::{BlockAnnouncement, InboundSlotCount, PeerEvent, PingRtt, peer_event},
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
const TCP_STATS_HEADER: &str = "srtt_us,rttvar_us,total_retrans,snd_cwnd";
const BLOCK_SPECIFIC_HEADER: &str = "block_hash,announcement_type,rtt_ms";
const PING_SPECIFIC_HEADER: &str = "rtt_ms";

struct CsvLogger {
    block_writer: BufWriter<File>,
    ping_writer: BufWriter<File>,
    slot_writer: BufWriter<File>,
}

impl CsvLogger {
    fn new() -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let block_filename = format!("block_announcements_{}.csv", timestamp);
        let ping_filename = format!("ping_rtt_{}.csv", timestamp);
        let slot_filename = format!("inbound_slots_{}.csv", timestamp);

        let mut block_writer = BufWriter::new(File::create(&block_filename)?);
        let mut ping_writer = BufWriter::new(File::create(&ping_filename)?);
        let mut slot_writer = BufWriter::new(File::create(&slot_filename)?);

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
        writeln!(
            slot_writer,
            "peer_addr,max_concurrent_connections,total_opened,timestamp_ms"
        )?;

        block_writer.flush()?;
        ping_writer.flush()?;
        slot_writer.flush()?;

        tracing::info!(target: TARGET, block_file = %block_filename, ping_file = %ping_filename, slot_file = %slot_filename, "created CSV files");

        Ok(Self {
            block_writer,
            ping_writer,
            slot_writer,
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
        let transport_version = event.transport_version;
        let block_hash = &blk.block_hash;
        let announcement_type = blk.announcement_type;

        // Optional rtt_ms
        let rtt_ms = blk.rtt_ms.map(|r| r.to_string()).unwrap_or_default();

        // Optional tcp_stats (flattened)
        let (srtt_us, rttvar_us, total_retrans, snd_cwnd) = if let Some(tcp) = &blk.tcp_stats {
            (
                tcp.srtt_us.to_string(),
                tcp.rttvar_us.to_string(),
                tcp.total_retrans.to_string(),
                tcp.snd_cwnd.to_string(),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };

        writeln!(
            self.block_writer,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            connection_id,
            timestamp_ms,
            peer_addr,
            user_agent,
            transport_version,
            block_hash,
            announcement_type,
            rtt_ms,
            srtt_us,
            rttvar_us,
            total_retrans,
            snd_cwnd
        )?;

        self.block_writer.flush()?;
        Ok(())
    }

    fn write_ping_rtt(&mut self, event: &PeerEvent, ping: &PingRtt) -> Result<()> {
        let connection_id = event.connection_id;
        let timestamp_ms = event.timestamp_ms;
        let peer_addr = escape_csv(&event.peer_addr);
        let user_agent = escape_csv(&event.user_agent);
        let transport_version = event.transport_version;
        let rtt_ms = ping.rtt_ms;

        // Optional tcp_stats (flattened)
        let (srtt_us, rttvar_us, total_retrans, snd_cwnd) = if let Some(tcp) = &ping.tcp_stats {
            (
                tcp.srtt_us.to_string(),
                tcp.rttvar_us.to_string(),
                tcp.total_retrans.to_string(),
                tcp.snd_cwnd.to_string(),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };

        writeln!(
            self.ping_writer,
            "{},{},{},{},{},{},{},{},{},{}",
            connection_id,
            timestamp_ms,
            peer_addr,
            user_agent,
            transport_version,
            rtt_ms,
            srtt_us,
            rttvar_us,
            total_retrans,
            snd_cwnd
        )?;

        self.ping_writer.flush()?;
        Ok(())
    }

    fn write_inbound_slot_count(
        &mut self,
        event: &PeerEvent,
        slot: &InboundSlotCount,
    ) -> Result<()> {
        let peer_addr = escape_csv(&event.peer_addr);
        writeln!(
            self.slot_writer,
            "{},{},{},{}",
            peer_addr,
            slot.max_concurrent_connections,
            slot.total_opened,
            event.timestamp_ms,
        )?;
        self.slot_writer.flush()?;
        Ok(())
    }
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
                Some(peer_event::Event::InboundSlotCount(slot)) => {
                    if let Err(e) = logger.write_inbound_slot_count(&event, slot) {
                        tracing::error!(target: TARGET, error = %e, "failed to write inbound slot count");
                    }
                }
                None => {}
            },
            Err(e) => {
                tracing::warn!(target: TARGET, subject = %msg.subject, error = %e, "failed to decode event")
            }
        }
    }

    Ok(())
}
