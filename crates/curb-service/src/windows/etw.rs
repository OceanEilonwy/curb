use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
};

/// Holds an open NTFS handle to a verified running executable with `FILE_SHARE_READ`
/// ONLY (no `FILE_SHARE_WRITE` and no `FILE_SHARE_DELETE`).
///
/// While this guard is alive, Windows blocks renaming or replacing the `.exe` or
/// any of its parent folders, preventing standard users from performing a
/// rename-and-swap attack in user-writable folders such as Steam libraries.
pub struct LockedImageHandle {
    handle: HANDLE,
}

unsafe impl Send for LockedImageHandle {}

impl LockedImageHandle {
    pub fn acquire(path: &Path) -> Option<Self> {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ, // Deliberately omits FILE_SHARE_WRITE and FILE_SHARE_DELETE
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .ok()?;

        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        Some(Self { handle })
    }
}

impl Drop for LockedImageHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Tracks active locked binary handles keyed by process ID.
#[derive(Default)]
pub struct ImageLockTable {
    locks: HashMap<u32, LockedImageHandle>,
}

impl ImageLockTable {
    pub fn lock_for_pid(&mut self, pid: u32, path: &Path) -> bool {
        if let Some(guard) = LockedImageHandle::acquire(path) {
            self.locks.insert(pid, guard);
            true
        } else {
            false
        }
    }

    pub fn release_pid(&mut self, pid: u32) {
        self.locks.remove(&pid);
    }
}
