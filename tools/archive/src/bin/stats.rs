use archive::stats::{self, Args};
use common::{anyhow::Result, clap::Parser};

fn main() -> Result<()> {
    let args = Args::parse();
    archive::init_logging();
    stats::run(&args)
}
