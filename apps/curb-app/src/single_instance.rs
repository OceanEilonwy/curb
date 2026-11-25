//! Single-instance reactivation helper for Linux desktop sessions (especially
//! tiling Wayland compositors like Sway, Mango, and dwl where users re-launch
//! `curb-app` from a keybind or application launcher rather than a system tray).

#[cfg(target_os = "linux")]
mod imp {
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::thread;

    pub fn instance_socket_path() -> PathBuf {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            if !runtime_dir.is_empty() {
                return PathBuf::from(runtime_dir).join("curb-app.sock");
            }
        }
        let uid = std::env::var("UID").unwrap_or_else(|_| "user".into());
        PathBuf::from(format!("/tmp/curb-app-{uid}.sock"))
    }

    /// Attempts to notify an already-running `curb-app` instance to show/focus its window.
    /// Returns `true` if an existing instance accepted the command and this process should exit.
    pub fn try_activate_existing() -> bool {
        let path = instance_socket_path();
        if let Ok(mut stream) = UnixStream::connect(&path) {
            let _ = stream.write_all(b"show\n");
            let _ = stream.flush();
            return true;
        }
        false
    }

    /// Holds the bound single-instance socket path and removes it on drop.
    pub struct SingleInstanceGuard {
        path: PathBuf,
    }

    impl Drop for SingleInstanceGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// Binds the per-user reactivation socket and invokes `on_show` on the UI event loop
    /// whenever another `curb-app` invocation requests window activation.
    pub fn start_listener<F>(on_show: F) -> Option<SingleInstanceGuard>
    where
        F: Fn() + Send + 'static,
    {
        let path = instance_socket_path();
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).ok()?;

        thread::Builder::new()
            .name("curb-single-instance".into())
            .spawn(move || {
                for stream in listener.incoming().flatten() {
                    let mut stream = stream;
                    let mut buf = [0u8; 32];
                    let _ = stream.read(&mut buf);
                    on_show();
                }
            })
            .ok()?;

        Some(SingleInstanceGuard { path })
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub struct SingleInstanceGuard;

    pub fn try_activate_existing() -> bool {
        false
    }

    pub fn start_listener<F>(_on_show: F) -> Option<SingleInstanceGuard>
    where
        F: Fn() + Send + 'static,
    {
        None
    }
}

pub use imp::{start_listener, try_activate_existing};
