use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::info;

use curb_core::ipc::{IpcRequest, IpcResponse};

use crate::engine::ServiceEngine;

/// Starts the IPC server:
/// - Windows: Named Pipe `\\.\pipe\curb-ipc`
/// - Non-Windows (dev): Unix domain socket `/tmp/curb-ipc.sock`
pub async fn run_ipc_server(engine: ServiceEngine) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        run_windows_pipe_server(engine).await
    }

    #[cfg(not(windows))]
    {
        run_unix_socket_server(engine).await
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
async fn run_windows_pipe_server(engine: ServiceEngine) -> std::io::Result<()> {
    use curb_core::ipc::WINDOWS_PIPE_NAME;
    use tokio::net::windows::named_pipe::ServerOptions;

    info!("Curb IPC server listening on Named Pipe {WINDOWS_PIPE_NAME}");
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(WINDOWS_PIPE_NAME)?;

    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new().create(WINDOWS_PIPE_NAME)?;

        let eng = engine.clone();
        tokio::spawn(async move {
            handle_stream(connected, eng).await;
        });
    }
}

#[cfg(not(windows))]
async fn run_unix_socket_server(engine: ServiceEngine) -> std::io::Result<()> {
    use curb_core::ipc::DEV_UNIX_SOCKET_PATH;
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(DEV_UNIX_SOCKET_PATH);
    let listener = UnixListener::bind(DEV_UNIX_SOCKET_PATH)?;
    info!("Curb IPC dev server listening on {DEV_UNIX_SOCKET_PATH}");

    loop {
        match listener.accept().await {
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
