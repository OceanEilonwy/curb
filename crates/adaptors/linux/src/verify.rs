use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use curb_core::adaptors::BinaryVerifier;
use curb_core::verify::{inspect_binary, peek_binary, BinaryIdentity};
use curb_core::Result;

use crate::proc_net::read_proc_exe;

const MAX_WRAPPER_SCRIPT_BYTES: u64 = 64 * 1024;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// Linux `BinaryVerifier` that handles:
/// 1. Symlinked launcher paths (e.g. `/usr/bin/librewolf -> /usr/lib/librewolf/librewolf`)
/// 2. Small POSIX shell wrapper scripts (e.g. `/usr/bin/librewolf` running
///    `exec /usr/lib/librewolf/librewolf "$@"`) so users adding a launcher by path
///    allow the real ELF binary instead of hashing the wrapper script
/// 3. Flatpak/Snap/container mount-namespace paths (e.g. `/app/lib/librewolf/librewolf`)
///    by falling back to `/proc/<pid>/exe` for a live process with that path
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxBinaryVerifier;

impl BinaryVerifier for LinuxBinaryVerifier {
    fn inspect_binary(&self, path: &Path) -> Result<BinaryIdentity> {
        inspect_linux_path(path, false)
    }

    fn peek_binary(&self, path: &Path) -> Result<BinaryIdentity> {
        inspect_linux_path(path, true)
    }
}

fn inspect_linux_path(path: &Path, peek_only: bool) -> Result<BinaryIdentity> {
    let run = |p: &Path| {
        if peek_only {
            peek_binary(p)
        } else {
            inspect_binary(p)
        }
    };

    if path.exists() {
        let resolved = resolve_launcher_target(path);
        return run(&resolved);
    }

    // Path doesn't exist in the host mount namespace (e.g. Flatpak `/app/lib/librewolf/librewolf`).
    // Find a running process whose `/proc/<pid>/exe` points to this logical path and inspect
    // through the kernel's `/proc/<pid>/exe` magic symlink.
    if let Some(pid) = find_live_pid_for_exe_path(path) {
        let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let mut id = run(&proc_exe)?;
        id.path = path.to_string_lossy().to_string();
        id.filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        return Ok(id);
    }

    run(path)
}

/// Resolves symlinks and small shell-script launchers (`#!/bin/sh ... exec /path/to/elf`)
/// to the real underlying ELF binary when present.
pub fn resolve_launcher_target(path: &Path) -> PathBuf {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(target) = extract_shell_wrapper_elf_target(&canonical) {
        return fs::canonicalize(&target).unwrap_or(target);
    }
    canonical
}

fn is_elf_file(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && &magic == ELF_MAGIC
}

fn extract_shell_wrapper_elf_target(path: &Path) -> Option<PathBuf> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_WRAPPER_SCRIPT_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if !bytes.starts_with(b"#!") {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut candidate_target: Option<PathBuf> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rest = if let Some(r) = line.strip_prefix("exec ") {
            r.trim()
        } else if let Some(r) = line.strip_prefix("exec\t") {
            r.trim()
        } else {
            continue;
        };

        let mut tokens = rest.split_whitespace().peekable();
        while let Some(tok) = tokens.next() {
            if tok == "-a" {
                let _ = tokens.next();
                continue;
            }
            if tok == "env" || tok.starts_with('-') || tok.contains('=') {
                continue;
            }
            let cleaned = tok.trim_matches('"').trim_matches('\'');
            if cleaned.starts_with('/') {
                let p = PathBuf::from(cleaned);
                if is_elf_file(&p) {
                    candidate_target = Some(p);
                }
            }
            break;
        }
    }

    candidate_target
}

fn find_live_pid_for_exe_path(target: &Path) -> Option<u32> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if read_proc_exe(pid).as_deref() == Some(target) {
            return Some(pid);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_shell_wrapper_script_to_real_elf_binary() {
        let dir = std::env::temp_dir().join(format!("curb_wrap_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let real_elf = dir.join("librewolf-bin");
        fs::write(&real_elf, b"\x7fELFfake-binary-payload").unwrap();

        let wrapper = dir.join("librewolf");
        fs::write(
            &wrapper,
            format!("#!/bin/sh\nexec \"{}\" \"$@\"\n", real_elf.display()),
        )
        .unwrap();

        let resolved = resolve_launcher_target(&wrapper);
        assert_eq!(resolved, fs::canonicalize(&real_elf).unwrap());

        let verifier = LinuxBinaryVerifier;
        let id_from_wrapper = verifier.inspect_binary(&wrapper).unwrap();
        let id_from_elf = verifier.inspect_binary(&real_elf).unwrap();
        assert_eq!(id_from_wrapper.sha256, id_from_elf.sha256);
        assert_eq!(id_from_wrapper.filename, "librewolf-bin");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaves_plain_elf_binary_unchanged() {
        let dir = std::env::temp_dir().join(format!("curb_elf_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let elf = dir.join("app");
        fs::write(&elf, b"\x7fELFplain").unwrap();

        assert_eq!(resolve_launcher_target(&elf), fs::canonicalize(&elf).unwrap());

        let _ = fs::remove_dir_all(&dir);
    }
}
