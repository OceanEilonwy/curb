mod dns_proxy;
mod engine;
mod ipc_server;
mod processes;
mod windows;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use curb_core::store::default_data_dir;
use tracing::{error, info, warn};

use crate::engine::ServiceEngine;

#[derive(Debug, Parser)]
#[command(name = "curb-service", about = "Curb LocalSystem enforcement service")]
struct Args {
    /// Run interactively in the foreground console instead of Windows SCM.
    #[arg(long)]
    console: bool,

    /// Override the Curb data directory (defaults to C:\ProgramData\Curb on Windows).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Local DNS proxy bind address.
    #[arg(long, default_value = "127.0.0.1:53")]
    dns_bind: SocketAddr,

    /// Upstream DNS resolver address.
    #[arg(long, default_value = "1.1.1.1:53")]
    dns_upstream: SocketAddr,

    /// Skip starting the local DNS proxy (useful for non-root dev sessions).
    #[arg(long)]
    no_dns: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "curb_service=info,curb_core=info".into()),
        )
        .init();

    let args = Args::parse();

    #[cfg(windows)]
    if !args.console {
        if let Err(e) = run_as_windows_service() {
            error!("Windows service dispatcher failed: {e}");
        }
        return;
    }

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(run_service_runtime(args));
}

async fn run_service_runtime(args: Args) {
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    info!("Starting curb-service with data dir: {}", data_dir.display());

    let engine = match ServiceEngine::new(data_dir.clone()) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to initialize Curb engine: {e}");
            return;
        }
    };

    #[cfg(windows)]
    {
        let wf_engine = engine.clone();
        let wf_dir = data_dir.clone();
        tokio::spawn(async move {
            windows::run_windows_enforcement_loop(wf_engine, wf_dir).await;
        });
    }

    if !args.no_dns {
        let dns_engine = engine.clone();
        let bind = args.dns_bind;
        let upstream = args.dns_upstream;
        tokio::spawn(async move {
            if let Err(e) = dns_proxy::run_dns_proxy(dns_engine, bind, upstream).await {
                warn!("Local DNS proxy stopped ({bind}): {e}");
            }
        });
    }

    if let Err(e) = ipc_server::run_ipc_server(engine).await {
        error!("IPC server failed: {e}");
    }
}

#[cfg(windows)]
fn run_as_windows_service() -> Result<(), windows_service::Error> {
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        let status_handle =
            service_control_handler::register("CurbService", move |control| match control {
                ServiceControl::Stop => ServiceControlHandlerResult::NoError,
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .expect("register service handler");

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(run_service_runtime(Args {
            console: false,
            data_dir: None,
            dns_bind: "127.0.0.1:53".parse().unwrap(),
            dns_upstream: "1.1.1.1:53".parse().unwrap(),
            no_dns: false,
        }));
    }

    service_dispatcher::start("CurbService", ffi_service_main)
}
