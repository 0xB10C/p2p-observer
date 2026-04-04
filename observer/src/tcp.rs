/// Query the OS TCP stack for the smoothed RTT of a socket in microseconds.
/// Returns `None` if the platform is unsupported or the syscall fails.
#[cfg(unix)]
pub(crate) fn srtt_us(fd: std::os::unix::io::RawFd) -> Option<u32> {
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
        if ret == 0 { Some(info.tcpi_rtt) } else { None }
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
        // tcpi_srtt is in milliseconds on macOS — convert to microseconds.
        if ret == 0 {
            Some(info.tcpi_srtt * 1_000)
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        None
    }
}

#[cfg(not(unix))]
pub(crate) fn srtt_us(_fd: i32) -> Option<u32> {
    None
}
