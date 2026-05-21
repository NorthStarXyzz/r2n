use r2n_config::SupernodeConfig;
use r2n_supernode_lib::Supernode;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (config, config_path) = SupernodeConfig::load_or_create()?;
    println!("Loaded configuration from {:?}", config_path);

    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone());
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&log_level)).init();

    let addr = format!("0.0.0.0:{}", config.listen_port);
    let supernode = Supernode::new_with_config(&addr, config).await?;
    supernode.run().await
}
