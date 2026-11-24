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
        use std::time::Duration;
        use tokio::net::windows::named_pipe::ClientOptions;

        const ERROR_PIPE_BUSY: i32 = 231;

        let mut client = {
            let mut attempts = 0u8;
            loop {
                match ClientOptions::new().open(WINDOWS_PIPE_NAME) {
                    Ok(c) => break c,
                    Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 10 => {
                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Could not connect to CurbService ({WINDOWS_PIPE_NAME}): {e}"
                        ));
                    }
                }
            }
        };

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
        use tokio::net::UnixStream;

        let socket_path = curb_core::ipc::default_unix_socket_path();
        let mut stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| format!("Could not connect to curb-service ({socket_path}): {e}"))?;

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
