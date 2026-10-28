use common::{
    anyhow::{Context, Result},
    clap::Parser,
    tokio::{self, sync::watch},
    tracing,
};
use websocket::{Args, TARGET, init_logging, run};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut server = tokio::spawn(run(args, shutdown_rx, None));

    tokio::select! {
        _ = common::shutdown::signal() => {
            tracing::info!(target: TARGET, "asked to stop, stopping");
            shutdown_tx.send(true).context("sending the shutdown signal")?;
        }
        result = &mut server => return result.context("joining the server task")?,
    }
    server.await.context("joining the server task")?
}
