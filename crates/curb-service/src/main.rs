mod dns_proxy;
mod engine;
mod ipc_server;
mod linux;
mod windows;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info, warn};

use crate::engine::ServiceEngine;

fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        curb_windows::default_data_dir()
    }
    #[cfg(target_os = "linux")]
    {
        curb_linux::default_data_dir()
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        PathBuf::from("/tmp/curb-data")
    }
}

#[cfg(target_os = "linux")]
const DEFAULT_DNS_BIND: &str = "127.0.0.1:5353";
#[cfg(not(target_os = "linux"))]
const DEFAULT_DNS_BIND: &str = "127.0.0.1:53";

#[derive(Debug, Parser)]
#[command(name = "curb-service", about = "Curb system enforcement service")]
struct Args {
    /// Run interactively in the foreground console instead of Windows SCM.
    #[arg(long)]
    console: bool,

    /// Override the Curb data directory (defaults to C:\ProgramData\Curb on Windows, /var/lib/curb on Linux).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Local DNS proxy bind address.
    #[arg(long, default_value = DEFAULT_DNS_BIND)]
    dns_bind: SocketAddr,

    /// Upstream DNS resolver address.
    #[arg(long, default_value = "1.1.1.1:53")]
    dns_upstream: SocketAddr,

    /// Skip starting the local DNS proxy (useful for non-root dev sessions).
    #[arg(long)]
    no_dns: bool,
}

fn init_logging(to_file: bool, data_dir: &std::path::Path) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "curb_service=info,curb_core=info".into());

    if to_file {
        let log_path = data_dir.join("logs").join("curb-service.log");
        if let Some(writer) = RotatingLogWriter::open(log_path) {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(writer)
                .try_init();
            return;
        }
    }

    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

/// Simple size-capped rotating log writer (`curb-service.log` -> `curb-service.log.1` at 2 MB)
/// so Windows Service (Session 0) diagnostics are preserved on disk without unbounded growth.
#[derive(Clone)]
struct RotatingLogWriter {
    inner: std::sync::Arc<std::sync::Mutex<RotatingLogState>>,
}

struct RotatingLogState {
    path: PathBuf,
    file: std::fs::File,
    written: u64,
}

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

impl RotatingLogWriter {
    fn open(path: PathBuf) -> Option<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok()?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Some(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(RotatingLogState {
                path,
                file,
                written,
            })),
        })
    }
}

impl std::io::Write for RotatingLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if st.written.saturating_add(buf.len() as u64) > MAX_LOG_BYTES {
            let backup = st.path.with_extension("log.1");
            let _ = st.file.flush();
            let _ = std::fs::rename(&st.path, &backup);
            if let Ok(fresh) = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&st.path)
            {
                st.file = fresh;
                st.written = 0;
            }
        }
        let n = st.file.write(buf)?;
        st.written = st.written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        st.file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RotatingLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn main() {
    let args = Args::parse();
    let data_dir = args.data_dir.clone().unwrap_or_else(default_data_dir);

    #[cfg(windows)]
    if !args.console {
        init_logging(true, &data_dir);
        if let Err(e) = run_as_windows_service() {
            error!("Windows service dispatcher failed: {e}");
        }
        return;
    }

    init_logging(false, &data_dir);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        #[cfg(unix)]
        {
            let tx = shutdown_tx.clone();
            tokio::spawn(async move {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).ok();
                let mut sigint = signal(SignalKind::interrupt()).ok();
                tokio::select! {
                    _ = async {
                        if let Some(ref mut s) = sigterm {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("Received SIGTERM — initiating graceful shutdown");
                    }
                    _ = async {
                        if let Some(ref mut s) = sigint {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("Received SIGINT — initiating graceful shutdown");
                    }
                }
                let _ = tx.send(true);
            });
        }
        let _keep_tx = shutdown_tx;
        run_service_runtime(args, shutdown_rx, None).await;
    });
}

fn build_service_adaptors() -> curb_core::adaptors::ServiceAdaptors {
    #[cfg(windows)]
    {
        curb_windows::service_adaptors()
    }

    #[cfg(target_os = "linux")]
    {
        curb_linux::service_adaptors()
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        curb_core::adaptors::ServiceAdaptors::default()
    }
}

async fn run_service_runtime(
    args: Args,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    power_resume_notify: Option<std::sync::Arc<tokio::sync::Notify>>,
) {
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    info!("Starting curb-service with data dir: {}", data_dir.display());

    let adaptors = build_service_adaptors();
    let engine = match ServiceEngine::with_adaptors(data_dir.clone(), adaptors) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to initialize Curb engine: {e}");
            return;
        }
    };

    if let Some(power_notify) = power_resume_notify {
        let eng = engine.clone();
        let mut sd = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = power_notify.notified() => {
                        info!("System power event received — refreshing adapter DNS and NCSI");
                        eng.notify_dns_refresh();
                    }
                    _ = sd.changed() => {
                        if *sd.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    #[cfg(windows)]
    let wf_task = {
        let wf_engine = engine.clone();
        let wf_dir = data_dir.clone();
        let wf_upstream = args.dns_upstream;
        let wf_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            windows::run_windows_enforcement_loop(wf_engine, wf_dir, wf_upstream, wf_shutdown)
                .await;
        })
    };

    #[cfg(target_os = "linux")]
    let linux_task = {
        let lx_engine = engine.clone();
        let lx_dns_port = args.dns_bind.port();
        let lx_upstream = args.dns_upstream;
        let lx_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            linux::run_linux_enforcement_loop(lx_engine, lx_dns_port, lx_upstream, lx_shutdown)
                .await;
        })
    };

    if !args.no_dns {
        let dns_engine = engine.clone();
        let bind = args.dns_bind;
        let upstream = args.dns_upstream;
        tokio::spawn(async move {
            loop {
                if let Err(e) = dns_proxy::run_dns_proxy(dns_engine.clone(), bind, upstream).await {
                    warn!("Local DNS proxy stopped ({bind}): {e}; restarting in 2s");
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }

    if let Err(e) = ipc_server::run_ipc_server(engine, shutdown_rx).await {
        error!("IPC server failed: {e}");
    }

    #[cfg(windows)]
    {
        let _ = wf_task.await;
    }

    #[cfg(target_os = "linux")]
    {
        let _ = linux_task.await;
    }
}

#[cfg(windows)]
fn run_as_windows_service() -> Result<(), windows_service::Error> {
    use std::ffi::OsString;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let power_notify = Arc::new(tokio::sync::Notify::new());
        let power_handler = power_notify.clone();
        let handle_cell: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
        let handler_cell = handle_cell.clone();

        let status_handle =
            service_control_handler::register("CurbService", move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Some(h) = handler_cell.get() {
                        let _ = h.set_service_status(ServiceStatus {
                            service_type: ServiceType::OWN_PROCESS,
                            current_state: ServiceState::StopPending,
                            controls_accepted: ServiceControlAccept::empty(),
                            exit_code: ServiceExitCode::Win32(0),
                            checkpoint: 0,
                            wait_hint: Duration::from_secs(15),
                            process_id: None,
                        });
                    }
                    let _ = shutdown_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::PowerEvent(_) => {
                    power_handler.notify_one();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .expect("register service handler");

        let _ = handle_cell.set(status_handle);

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::POWER_EVENT,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(run_service_runtime(
            Args {
                console: false,
                data_dir: None,
                dns_bind: "127.0.0.1:53".parse().unwrap(),
                dns_upstream: "1.1.1.1:53".parse().unwrap(),
                no_dns: false,
            },
            shutdown_rx,
            Some(power_notify),
        ));

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    }

    service_dispatcher::start("CurbService", ffi_service_main)
}
