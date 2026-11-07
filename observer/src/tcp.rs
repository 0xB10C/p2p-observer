/// TCP statistics sampled from the OS kernel via `getsockopt`.
///
/// Fields are in canonical units (microseconds for time, segments for window
/// sizes) regardless of what the kernel reports natively. Platform availability
/// is noted per field; an `Option` is `None` where the platform has no
/// equivalent, because zero is a real value for most of these.
pub(crate) struct TcpStats {
    /// Smoothed RTT in microseconds (SRTT).
    /// Available on: Linux, macOS.
    pub srtt_us: u32,

    /// RTT variance in microseconds. Reflects jitter / stability of the path.
    /// Available on: Linux, macOS.
    pub rttvar_us: u32,

    /// Total number of retransmitted segments over the lifetime of the connection.
    /// Increases indicate packet loss on the path.
    /// Available on: Linux (`tcpi_total_retrans`), macOS (`tcpi_rxretransmitpackets`).
    pub total_retrans: u32,

    /// Congestion window size in segments.
    /// A small value means the sender is congestion-limited.
    /// Available on: Linux, macOS.
    pub snd_cwnd: u32,

    /// Lowest RTT seen over the connection's life, in microseconds. Tracks the
    /// propagation delay rather than the current queueing, which is what makes
    /// it the better of the two for judging distance.
    /// Available on: Linux (`tcpi_min_rtt`). macOS reports a current RTT only.
    pub min_rtt_us: Option<u32>,

    /// Segments the stack currently believes lost.
    /// Available on: Linux (`tcpi_lost`).
    pub lost: Option<u32>,

    /// The stack's reordering estimate.
    /// Available on: Linux (`tcpi_reordering`).
    pub reordering: Option<u32>,

    /// Delivery rate estimate in bytes per second.
    /// Available on: Linux (`tcpi_delivery_rate`).
    pub delivery_rate: Option<u64>,

    /// Payload bytes received from the peer over the connection's life,
    /// counted by the TCP stack and so excluding TCP/IP header overhead.
    /// Available on: Linux (`tcpi_bytes_received`), macOS (`tcpi_rxbytes`).
    pub bytes_received: Option<u64>,
}

/// Query the OS TCP stack for statistics on the given socket file descriptor.
/// Returns `None` if the platform is unsupported or the `getsockopt` call fails.
#[cfg(unix)]
pub(crate) fn tcp_info(fd: std::os::unix::io::RawFd) -> Option<TcpStats> {
    #[cfg(target_os = "linux")]
    {
        let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                &mut info as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return None;
        }
        // `tcp_info` has grown over kernel versions and `getsockopt` reports how
        // much of it it filled in. The struct was zeroed, so a field the kernel
        // did not write reads as zero -- which for a minimum RTT or a delivery
        // rate is a claim, not a blank. Taking a field only once the returned
        // length covers it keeps "absent" meaning absent.
        //
        // min_rtt and delivery_rate arrived in Linux 4.9, bytes_received in 4.1.
        let filled = len as usize;
        let have = |field_end: usize| filled >= field_end;
        macro_rules! field_end {
            ($f:ident) => {
                std::mem::offset_of!(libc::tcp_info, $f) + std::mem::size_of_val(&info.$f)
            };
        }
        Some(TcpStats {
            srtt_us: info.tcpi_rtt,
            rttvar_us: info.tcpi_rttvar,
            total_retrans: info.tcpi_total_retrans,
            snd_cwnd: info.tcpi_snd_cwnd,
            min_rtt_us: have(field_end!(tcpi_min_rtt)).then_some(info.tcpi_min_rtt),
            lost: have(field_end!(tcpi_lost)).then_some(info.tcpi_lost),
            reordering: have(field_end!(tcpi_reordering)).then_some(info.tcpi_reordering),
            delivery_rate: have(field_end!(tcpi_delivery_rate)).then_some(info.tcpi_delivery_rate),
            bytes_received: have(field_end!(tcpi_bytes_received))
                .then_some(info.tcpi_bytes_received),
        })
    }
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_connection_info>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_CONNECTION_INFO,
                &mut info as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return None;
        }
        // Time fields are in milliseconds on macOS — convert to microseconds.
        Some(TcpStats {
            srtt_us: info.tcpi_srtt * 1_000,
            rttvar_us: info.tcpi_rttvar * 1_000,
            total_retrans: info.tcpi_rxretransmitpackets as u32,
            snd_cwnd: info.tcpi_snd_cwnd,
            // No minimum RTT, loss, reordering or rate estimate in
            // tcp_connection_info. tcpi_rxoutoforderbytes counts bytes rather
            // than events, so it is not the same measurement as reordering and
            // is deliberately not reported as one.
            min_rtt_us: None,
            lost: None,
            reordering: None,
            delivery_rate: None,
            bytes_received: Some(info.tcpi_rxbytes),
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        None
    }
}

#[cfg(not(unix))]
pub(crate) fn tcp_info(_fd: i32) -> Option<TcpStats> {
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use common::tokio;
    use common::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use common::tokio::net::{TcpListener, TcpStream};
    use std::os::unix::io::AsRawFd;

    /// The kernel actually answers, and the fields come back where this code
    /// says they are.
    ///
    /// Everything in here is offsets into a struct that has grown over kernel
    /// versions, read through a raw `getsockopt`. The `have` check exists
    /// because a field the kernel did not write would otherwise read as a
    /// zero -- and a zero minimum RTT or delivery rate is a claim, not a
    /// blank. None of that had a test: the only thing exercising this path
    /// was a session test that never looked at the numbers, so a wrong offset
    /// would have shown up as a plausible measurement in the archive and
    /// nowhere else.
    #[tokio::test]
    async fn test_the_kernel_answers_and_the_fields_land_where_they_should() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
            stream.flush().await.unwrap();
            // Held open until the client has sampled.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // A round trip first: the smoothed RTT is zero until something has
        // been acknowledged, and a sample of nothing proves nothing.
        client.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();

        let stats = tcp_info(client.as_raw_fd()).expect("the kernel reports TCP_INFO on linux");

        // Loopback is fast but not instantaneous, and the units are
        // microseconds: a value of zero here means the field was never
        // written, which is what a wrong offset looks like.
        assert!(stats.srtt_us > 0, "srtt was {}", stats.srtt_us);
        // Nothing was lost on loopback, and these are counters.
        assert_eq!(stats.total_retrans, 0);
        assert!(stats.snd_cwnd > 0, "cwnd was {}", stats.snd_cwnd);

        // The fields that arrived with later kernels. Any kernel that reports
        // them at all reports them for a connection that has just exchanged
        // data, and the minimum cannot exceed the smoothed value it is the
        // minimum of.
        if let Some(min_rtt) = stats.min_rtt_us {
            assert!(
                min_rtt <= stats.srtt_us,
                "a minimum RTT of {min_rtt} above the smoothed {}",
                stats.srtt_us
            );
        }
        assert_eq!(stats.lost, Some(0), "nothing is lost on loopback");
        // Four bytes each way, so the count is small but not zero.
        if let Some(rx) = stats.bytes_received {
            assert_eq!(rx, 4, "bytes_received was {rx}");
        }

        server.abort();
    }
}
