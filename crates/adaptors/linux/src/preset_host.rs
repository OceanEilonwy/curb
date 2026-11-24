use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use curb_core::presets::{PresetHost, TargetOs};
use curb_core::steam::is_windows_exe;
use curb_core::verify::{peek_binary, BinaryIdentity};
use curb_core::Result;

/// Linux implementation of [`PresetHost`] providing OS-agnostic host primitives
/// (executable ELF/Proton detection, home directory enumeration, binary metadata peeks)
/// to any registered [`curb_core::presets::PresetPlugin`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxPresetHost;

/// Returns true if `path` is either a Proton/Wine `.exe` or an executable Linux ELF binary.
pub fn is_linux_executable(path: &Path) -> bool {
    if is_windows_exe(path) {
        return true;
    }
    let Some(name_lower) = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    if name_lower.contains(".so") || name_lower.ends_with(".sh") || name_lower.ends_with(".py") {
        return false;
    }
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if meta.permissions().mode() & 0o111 == 0 {
        return false;
    }
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
}

impl PresetHost for LinuxPresetHost {
    fn target_os(&self) -> TargetOs {
        TargetOs::Linux
    }

    fn is_executable(&self, path: &Path) -> bool {
        is_linux_executable(path)
    }

    fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity> {
        peek_binary(path)
    }

    fn user_home_dirs(&self) -> Vec<PathBuf> {
        let mut homes = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            homes.push(PathBuf::from(home));
        }
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() && !homes.contains(&p) {
                    homes.push(p);
                }
            }
        }
        homes
    }
}
