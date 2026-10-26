//! The signal to stop on, shared by every long-running binary.

/// Resolves when the process is asked to stop: SIGINT (ctrl-c) or, on unix,
/// SIGTERM.
///
/// Both mean the same thing to a binary with state to write out. SIGTERM is
/// what a supervisor, a container runtime or a bare `kill` sends, and a
/// process that listens only for ctrl-c skips its shutdown path entirely when
/// it arrives -- for the observer that was up to a snapshot interval of
/// address book and any unsaved headers, gone.
///
/// Listening for a signal can itself fail; a failure is logged and that signal
/// is then simply never seen, rather than the process refusing to start.
pub async fn signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!("could not listen for ctrl-c: {e}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                tracing::warn!("could not listen for SIGTERM: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
}
