use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use curb_relay::{build_router, RelayConfig, DEFAULT_MAX_BACKUP_BYTES};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "curb-relay",
    version,
    about = "Zero-knowledge P2P rendezvous relay and optional E2E-encrypted backup server for Curb"
)]
struct Args {
    /// Address and port to bind (e.g. 0.0.0.0:8443)
    #[arg(long, env = "CURB_RELAY_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// Optional directory to persist E2E-encrypted settings backup blobs on disk.
    /// If omitted, encrypted backups are kept in memory only.
    #[arg(long, env = "CURB_RELAY_BACKUP_DIR")]
    backup_dir: Option<PathBuf>,

    /// Disable encrypted settings backup storage (run as a 100% stateless P2P relay).
    #[arg(long, env = "CURB_RELAY_NO_BACKUP", default_value_t = false)]
    no_backup: bool,

    /// Maximum allowed encrypted backup payload size in bytes.
    #[arg(
        long,
        env = "CURB_RELAY_MAX_BACKUP_BYTES",
        default_value_t = DEFAULT_MAX_BACKUP_BYTES
    )]
    max_backup_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cfg = RelayConfig {
        backup_dir: args.backup_dir.clone(),
        backup_enabled: !args.no_backup,
        max_backup_bytes: args.max_backup_bytes,
        ..RelayConfig::default()
    };

    let app = build_router(cfg);
    let listener = TcpListener::bind(args.listen).await?;
    info!(
        listen = %args.listen,
        backup_enabled = !args.no_backup,
        backup_dir = ?args.backup_dir,
        version = env!("CARGO_PKG_VERSION"),
        "curb-relay started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("curb-relay shutting down");
}
