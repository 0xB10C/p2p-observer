use archive::replayer::{self, Args};
use common::{anyhow::Result, clap::Parser};

fn main() -> Result<()> {
    let args = Args::parse();
    archive::init_logging();

    if replayer::run(&args) {
        std::process::exit(1);
    }

    Ok(())
}
