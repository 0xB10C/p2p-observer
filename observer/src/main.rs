use common::tokio;

#[tokio::main]
async fn main() {
    let cfg = observer::Config::load().expect("failed to load config");
    observer::init_logging(&cfg);
    observer::run(cfg, common::shutdown::signal()).await;
}
