use std::path::{Path, PathBuf};

use curb_core::adaptors::BinaryVerifier;
use curb_core::presets::{PresetHost, RegistryRoot, TargetOs};
use curb_core::steam::is_windows_exe;
use curb_core::verify::BinaryIdentity;
use curb_core::Result;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, REG_SZ, REG_VALUE_TYPE,
};

use crate::verify::WindowsBinaryVerifier;

/// Windows implementation of [`PresetHost`] providing OS-agnostic host primitives
/// (Registry lookups, `.exe` detection, Authenticode/PE metadata peeks, user home dirs)
/// to any registered [`curb_core::presets::PresetPlugin`].
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsPresetHost;

impl PresetHost for WindowsPresetHost {
    fn target_os(&self) -> TargetOs {
        TargetOs::Windows
    }

    fn is_executable(&self, path: &Path) -> bool {
        is_windows_exe(path)
    }

    fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity> {
        WindowsBinaryVerifier.peek_binary(path)
    }

    fn read_windows_registry_string(
        &self,
        root: RegistryRoot,
        subkey: &str,
        value: &str,
    ) -> Option<String> {
        let hive = match root {
            RegistryRoot::LocalMachine => HKEY_LOCAL_MACHINE,
            RegistryRoot::CurrentUser => HKEY_CURRENT_USER,
        };
        let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let value_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
                return None;
            }

            let mut buf = [0u16; 512];
            let mut buf_bytes = (buf.len() * 2) as u32;
            let mut kind = REG_VALUE_TYPE::default();
            let res = RegQueryValueExW(
                hkey,
                PCWSTR(value_w.as_ptr()),
                None,
                Some(&mut kind),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut buf_bytes),
            );
            let _ = RegCloseKey(hkey);

            if res.is_ok() && kind == REG_SZ {
                let char_len = (buf_bytes as usize / 2).min(buf.len());
                let s = String::from_utf16_lossy(&buf[..char_len])
                    .trim_end_matches('\0')
                    .to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
        None
    }

    fn user_home_dirs(&self) -> Vec<PathBuf> {
        std::env::var("USERPROFILE")
            .ok()
            .map(|h| vec![PathBuf::from(h)])
            .unwrap_or_default()
    }
}
