use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::info;

use curb_core::ipc::{IpcRequest, IpcResponse};

use crate::engine::ServiceEngine;

/// Starts the IPC server:
/// - Windows: Named Pipe `\\.\pipe\curb-ipc`
/// - Non-Windows (dev): Unix domain socket `/tmp/curb-ipc.sock`
pub async fn run_ipc_server(
    engine: ServiceEngine,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        run_windows_pipe_server(engine, shutdown).await
    }

    #[cfg(not(windows))]
    {
        run_unix_socket_server(engine, shutdown).await
    }
}

async fn handle_stream<S>(stream: S, engine: ServiceEngine)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<IpcRequest>(&line) {
            Ok(req) => engine.handle_request(req),
            Err(e) => IpcResponse::Error {
                message: format!("Malformed IPC request: {e}"),
            },
        };
        if let Ok(mut serialized) = serde_json::to_string(&response) {
            serialized.push('\n');
            if writer.write_all(serialized.as_bytes()).await.is_err() {
                break;
            }
        }
    }
}

#[cfg(windows)]
async fn run_windows_pipe_server(
    engine: ServiceEngine,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    use curb_core::ipc::WINDOWS_PIPE_NAME;
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    /// RAII wrapper for a Win32 security descriptor allocated by
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    ///
    /// Grants Full Control to SYSTEM (`SY`) and Administrators (`BA`), and Read/Write
    /// to local Authenticated Users (`AU`) so the non-elevated `curb-app` tray UI can
    /// communicate with `CurbService` (which enforces Argon2 password + session auth
    /// on every state-changing IPC request). Remote SMB clients are rejected via
    /// `reject_remote_clients(true)`.
    struct PipeSecurityDescriptor {
        raw: PSECURITY_DESCRIPTOR,
    }

    // SAFETY: The immutable self-relative SECURITY_DESCRIPTOR buffer is never mutated
    // after creation and is only freed in Drop.
    unsafe impl Send for PipeSecurityDescriptor {}
    unsafe impl Sync for PipeSecurityDescriptor {}

    impl PipeSecurityDescriptor {
        fn new() -> std::io::Result<Self> {
            let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)\0"
                .encode_utf16()
                .collect();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(sddl.as_ptr()),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )
            }
            .map_err(|e| std::io::Error::other(format!("Failed to build pipe DACL: {e}")))?;
            Ok(Self { raw: sd })
        }

        fn create_pipe(
            &self,
            first_instance: bool,
        ) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
            let mut sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.raw.0,
                bInheritHandle: false.into(),
            };
            let mut opts = ServerOptions::new();
            opts.first_pipe_instance(first_instance)
                .reject_remote_clients(true);
            unsafe {
                opts.create_with_security_attributes_raw(
                    WINDOWS_PIPE_NAME,
                    (&mut sa as *mut SECURITY_ATTRIBUTES).cast(),
                )
            }
        }
    }

    impl Drop for PipeSecurityDescriptor {
        fn drop(&mut self) {
            if !self.raw.0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.raw.0));
                }
            }
        }
    }

    let sec = PipeSecurityDescriptor::new()?;
    info!("Curb IPC server listening on Named Pipe {WINDOWS_PIPE_NAME}");
    let mut server = sec.create_pipe(true)?;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Curb IPC server shutting down");
                    return Ok(());
                }
            }
            res = server.connect() => {
                res?;
                let connected = server;
                server = sec.create_pipe(false)?;

                let eng = engine.clone();
                tokio::spawn(async move {
                    handle_stream(connected, eng).await;
                });
            }
        }
    }
}

#[cfg(not(windows))]
async fn run_unix_socket_server(
    engine: ServiceEngine,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    use curb_core::ipc::DEV_UNIX_SOCKET_PATH;
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(DEV_UNIX_SOCKET_PATH);
    let listener = UnixListener::bind(DEV_UNIX_SOCKET_PATH)?;
    info!("Curb IPC dev server listening on {DEV_UNIX_SOCKET_PATH}");

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Curb IPC dev server shutting down");
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let eng = engine.clone();
                        tokio::spawn(async move {
                            handle_stream(stream, eng).await;
                        });
                    }
                    Err(e) => tracing::warn!("IPC accept error: {e}"),
                }
            }
        }
    }
}
