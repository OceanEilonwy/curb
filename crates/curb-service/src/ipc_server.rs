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

const MAX_IPC_LINE_BYTES: usize = 256 * 1024;

async fn handle_stream<S>(stream: S, engine: ServiceEngine)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(1024);

    loop {
        buf.clear();
        let n = match (&mut reader)
            .take((MAX_IPC_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut buf)
            .await
        {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        if n > MAX_IPC_LINE_BYTES && !buf.ends_with(b"\n") {
            let err_resp = IpcResponse::Error {
                message: "IPC request exceeds maximum allowed size.".into(),
            };
            if let Ok(mut serialized) = serde_json::to_string(&err_resp) {
                serialized.push('\n');
                let _ = writer.write_all(serialized.as_bytes()).await;
            }
            break;
        }

        let Ok(line) = std::str::from_utf8(&buf) else {
            let err_resp = IpcResponse::Error {
                message: "Malformed IPC request: invalid UTF-8".into(),
            };
            if let Ok(mut serialized) = serde_json::to_string(&err_resp) {
                serialized.push('\n');
                let _ = writer.write_all(serialized.as_bytes()).await;
            }
            break;
        };

        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<IpcRequest>(line) {
            Ok(req) => {
                let eng = engine.clone();
                tokio::task::spawn_blocking(move || eng.handle_request(req))
                    .await
                    .unwrap_or_else(|e| IpcResponse::Error {
                        message: format!("Internal service error: {e}"),
                    })
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn rejects_oversized_ipc_line_without_oom() {
        let dir = std::env::temp_dir().join(format!("curb_ipc_limit_{}", uuid::Uuid::new_v4()));
        let engine = ServiceEngine::new(dir.clone()).unwrap();

        let (mut client, server) = tokio::io::duplex(512 * 1024);
        let srv_task = tokio::spawn(async move {
            handle_stream(server, engine).await;
        });

        let huge = vec![b'a'; MAX_IPC_LINE_BYTES + 1024];
        let _ = client.write_all(&huge).await;
        let _ = client.shutdown().await;

        let mut resp = String::new();
        let _ = client.read_to_string(&mut resp).await;
        srv_task.await.unwrap();

        assert!(
            resp.contains("exceeds maximum allowed size"),
            "expected size limit error, got: {resp}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
