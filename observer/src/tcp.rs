/// TCP statistics sampled from the OS kernel via `getsockopt`.
///
/// Fields are in canonical units (microseconds for time, segments for window
/// sizes) regardless of what the kernel reports natively. Platform availability
/// is noted per field.
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
        Some(TcpStats {
            srtt_us: info.tcpi_rtt,
            rttvar_us: info.tcpi_rttvar,
            total_retrans: info.tcpi_total_retrans,
            snd_cwnd: info.tcpi_snd_cwnd,
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
