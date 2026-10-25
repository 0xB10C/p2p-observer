//! Archiving and replaying observer events.

pub(crate) const TARGET_ARCHIVER: &str = "archiver";

pub mod archiver;
pub mod read;

/// Sets up logging for the binaries in this crate, honouring `RUST_LOG` the way
/// the rest of the workspace does and defaulting to info.
pub fn init_logging() {
    common::tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(
            common::tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| common::tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
