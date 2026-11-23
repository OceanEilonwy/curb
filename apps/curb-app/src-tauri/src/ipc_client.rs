use curb_core::ipc::{IpcRequest, IpcResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Sends a single JSON-RPC request to `curb-service` over the Windows Named Pipe
/// (or local Unix socket during non-Windows development).
pub async fn send_request(req: &IpcRequest) -> Result<IpcResponse, String> {
    let mut payload = serde_json::to_string(req).map_err(|e| e.to_string())?;
    payload.push('\n');

    #[cfg(windows)]
    {
        use curb_core::ipc::WINDOWS_PIPE_NAME;
        use tokio::net::windows::named_pipe::ClientOptions;

        let mut client = ClientOptions::new()
            .open(WINDOWS_PIPE_NAME)
            .map_err(|e| format!("Could not connect to CurbService ({WINDOWS_PIPE_NAME}): {e}"))?;

        client
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;

        serde_json::from_str::<IpcResponse>(&line).map_err(|e| e.to_string())
    }

    #[cfg(not(windows))]
    {
        use curb_core::ipc::DEV_UNIX_SOCKET_PATH;
        use tokio::net::UnixStream;

        let mut stream = UnixStream::connect(DEV_UNIX_SOCKET_PATH)
            .await
            .map_err(|e| format!("Could not connect to curb-service ({DEV_UNIX_SOCKET_PATH}): {e}"))?;

        stream
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;

        serde_json::from_str::<IpcResponse>(&line).map_err(|e| e.to_string())
    }
}
