use common::{
    anyhow::{Context, Result},
    clap::Parser,
    tokio::{self, sync::watch},
    tracing,
};
use metrics::{Args, TARGET, init_logging, run};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tool = tokio::spawn(run(args, shutdown_rx, None));

    tokio::select! {
        _ = common::shutdown::signal() => {
            tracing::info!(target: TARGET, "asked to stop, stopping");
            shutdown_tx.send(true).context("sending the shutdown signal")?;
        }
        result = &mut tool => return result.context("joining the tool task")?,
    }
    tool.await.context("joining the tool task")?
}
