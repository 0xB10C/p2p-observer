use archive::archiver::{Args, run};
use common::{
    anyhow::{Context, Result},
    clap::Parser,
    tokio::{self, sync::watch},
    tracing,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    archive::init_logging();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut archiver = tokio::spawn(run(args, shutdown_rx));

    tokio::select! {
        _ = common::shutdown::signal() => {
            tracing::info!("asked to stop, stopping");
            shutdown_tx.send(true).context("sending the shutdown signal")?;
        }
        // The archiver can also stop on its own, by a write failing or the
        // subscription ending.
        result = &mut archiver => return finish(result),
    }

    // The signal path. Wait for the archiver to drain, flush and close its
    // file, which is the difference between a readable archive and a truncated
    // one.
    finish(archiver.await)
}

fn finish(result: std::result::Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    result.context("joining the archiver task")?
}
