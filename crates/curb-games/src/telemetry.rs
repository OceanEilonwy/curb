use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, UNIX_EPOCH};

use chrono::Utc;

use crate::{FileActivity, GameTelemetrySnapshot, TcpEndpointSample, UdpEndpointSample};

/// Stateful cross-platform telemetry collector for running Steam games.
///
/// Tracks previous per-PID I/O counters so consecutive `sample()` calls yield
/// accurate bytes/sec deltas without ever touching game process memory.
#[derive(Debug, Default)]
pub struct TelemetrySampler {
    prev_io: HashMap<u32, (u64, u64, Instant)>,
}

impl TelemetrySampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Collects a read-only telemetry snapshot for all running processes matching
    /// `install_dir` (if known) or any filename in `exe_hints`.
    pub fn sample(
        &mut self,
        app_id: u32,
        install_dir: Option<&Path>,
        exe_hints: &[&str],
        watched_dirs: &[PathBuf],
    ) -> GameTelemetrySnapshot {
        let now_instant = Instant::now();
        let pids = find_matching_pids(install_dir, exe_hints);

        // Prune exited PIDs from delta cache.
        self.prev_io.retain(|pid, _| pids.contains(pid));

        let (udp_endpoints, tcp_endpoints) = collect_pid_sockets(&pids);

        let mut total_rx_bps = 0u64;
        let mut total_tx_bps = 0u64;
        for &pid in &pids {
            if let Some((rx_total, tx_total)) = read_pid_io_bytes(pid) {
                if let Some((prev_rx, prev_tx, prev_time)) = self.prev_io.get(&pid) {
                    let dt = now_instant.duration_since(*prev_time).as_secs_f64();
                    if dt > 0.05 {
                        let drx = rx_total.saturating_sub(*prev_rx);
                        let dtx = tx_total.saturating_sub(*prev_tx);
                        total_rx_bps = total_rx_bps.saturating_add((drx as f64 / dt) as u64);
                        total_tx_bps = total_tx_bps.saturating_add((dtx as f64 / dt) as u64);
                    }
                }
                self.prev_io.insert(pid, (rx_total, tx_total, now_instant));
            }
        }

        let file_activities = collect_file_activities(watched_dirs);

        GameTelemetrySnapshot {
            timestamp_utc: Utc::now(),
            app_id,
            pids,
            udp_socket_count: udp_endpoints.len(),
            udp_endpoints,
            tcp_endpoints,
            rx_bytes_per_sec: total_rx_bps,
            tx_bytes_per_sec: total_tx_bps,
            udp_packets_per_sec: 0,
            file_activities,
        }
    }
}

fn collect_file_activities(watched_dirs: &[PathBuf]) -> Vec<FileActivity> {
    let mut out = Vec::new();
    for dir in watched_dirs {
        collect_dir_files(dir, 0, 2, &mut out);
        if out.len() >= 50 {
            break;
        }
    }
    out
}

fn collect_dir_files(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<FileActivity>) {
    if depth > max_depth || out.len() >= 50 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= 50 {
            break;
        }
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if ft.is_dir() && depth < max_depth {
            collect_dir_files(&path, depth + 1, max_depth, out);
        } else if ft.is_file() {
            if let Ok(meta) = entry.metadata() {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                out.push(FileActivity {
                    path: path.to_string_lossy().to_string(),
                    modified_epoch_secs: mtime,
                    size_bytes: meta.len(),
                });
            }
        }
    }
}

fn matches_game_path(exe_path: &str, cmdline: &str, install_dir: Option<&Path>, exe_hints: &[&str]) -> bool {
    let exe_norm = exe_path.replace('\\', "/").to_ascii_lowercase();
    let cmd_norm = cmdline.replace('\\', "/").to_ascii_lowercase();

    if let Some(dir) = install_dir {
        let dir_norm = dir
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        if !dir_norm.is_empty()
            && (exe_norm.starts_with(&format!("{dir_norm}/")) || cmd_norm.contains(&dir_norm))
        {
            return true;
        }
    }

    for hint in exe_hints {
        let h = hint.to_ascii_lowercase();
        if !h.is_empty() && (exe_norm.ends_with(&format!("/{h}")) || exe_norm == h || cmd_norm.contains(&h)) {
            return true;
        }
    }
    false
}

// ============================================================================
// Linux Implementation (/proc)
// ============================================================================

#[cfg(target_os = "linux")]
fn find_matching_pids(install_dir: Option<&Path>, exe_hints: &[&str]) -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let proc_dir = entry.path();
        let exe_path = std::fs::read_link(proc_dir.join("exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cmdline = std::fs::read(proc_dir.join("cmdline"))
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .map(|s| String::from_utf8_lossy(s))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        if matches_game_path(&exe_path, &cmdline, install_dir, exe_hints) {
            pids.push(pid);
        }
    }
    pids
}

#[cfg(target_os = "linux")]
fn read_pid_io_bytes(pid: u32) -> Option<(u64, u64)> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    let mut rchar = 0u64;
    let mut wchar = 0u64;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("rchar:") {
            rchar = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("wchar:") {
            wchar = v.trim().parse().unwrap_or(0);
        }
    }
    Some((rchar, wchar))
}

#[cfg(target_os = "linux")]
fn collect_pid_sockets(pids: &[u32]) -> (Vec<UdpEndpointSample>, Vec<TcpEndpointSample>) {
    use std::collections::HashSet;

    let mut inodes = HashSet::new();
    for &pid in pids {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let s = target.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(num) = rest.strip_suffix(']') {
                        if let Ok(inode) = num.parse::<u64>() {
                            inodes.insert(inode);
                        }
                    }
                }
            }
        }
    }

    if inodes.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut udps = Vec::new();
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines().skip(1) {
                if let Some((local_port, remote, inode)) = parse_proc_net_line(line) {
                    if inodes.contains(&inode) {
                        udps.push(UdpEndpointSample {
                            local_port,
                            remote_addr: if remote.ends_with(":0") {
                                None
                            } else {
                                Some(remote)
                            },
                        });
                    }
                }
            }
        }
    }

    let mut tcps = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines().skip(1) {
                if let Some((local_port, remote, inode, state_hex)) = parse_proc_net_tcp_line(line)
                {
                    if inodes.contains(&inode) {
                        tcps.push(TcpEndpointSample {
                            local_port,
                            remote_addr: remote,
                            state: state_hex,
                        });
                    }
                }
            }
        }
    }

    (udps, tcps)
}

#[cfg(target_os = "linux")]
fn parse_proc_net_line(line: &str) -> Option<(u16, String, u64)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 {
        return None;
    }
    let (_, local_port) = parse_hex_ip_port(cols[1])?;
    let (rem_ip, rem_port) = parse_hex_ip_port(cols[2])?;
    let inode: u64 = cols[9].parse().ok()?;
    Some((local_port, format!("{rem_ip}:{rem_port}"), inode))
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp_line(line: &str) -> Option<(u16, String, u64, String)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 {
        return None;
    }
    let (_, local_port) = parse_hex_ip_port(cols[1])?;
    let (rem_ip, rem_port) = parse_hex_ip_port(cols[2])?;
    let state = match cols[3] {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "0A" => "LISTEN",
        other => other,
    }
    .to_string();
    let inode: u64 = cols[9].parse().ok()?;
    Some((local_port, format!("{rem_ip}:{rem_port}"), inode, state))
}

#[cfg(target_os = "linux")]
fn parse_hex_ip_port(s: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if ip_hex.len() == 8 {
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = std::net::Ipv4Addr::from(raw.to_be_bytes());
        // /proc/net/tcp stores IPv4 in host byte order (little-endian on x86_64)
        let octets = ip.octets();
        let host_ip = std::net::Ipv4Addr::new(octets[3], octets[2], octets[1], octets[0]);
        Some((host_ip.to_string(), port))
    } else {
        Some((format!("[{ip_hex}]"), port))
    }
}

// ============================================================================
// Windows Implementation (ToolHelp32 + IP Helper + GetProcessIoCounters)
// ============================================================================

#[cfg(windows)]
fn find_matching_pids(install_dir: Option<&Path>, exe_hints: &[&str]) -> Vec<u32> {
    use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut pids = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return pids;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let exe_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );
                let mut full_path = exe_name.clone();
                if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    let mut buf = vec![0u16; MAX_PATH as usize * 2];
                    let mut len = buf.len() as u32;
                    if QueryFullProcessImageNameW(
                        handle,
                        PROCESS_NAME_WIN32,
                        windows::core::PWSTR(buf.as_mut_ptr()),
                        &mut len,
                    )
                    .is_ok()
                    {
                        full_path = String::from_utf16_lossy(&buf[..len as usize]);
                    }
                    let _ = CloseHandle(handle);
                }

                if matches_game_path(&full_path, &exe_name, install_dir, exe_hints) {
                    pids.push(pid);
                }

                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}

#[cfg(windows)]
fn read_pid_io_bytes(pid: u32) -> Option<(u64, u64)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetProcessIoCounters, OpenProcess, IO_COUNTERS, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut counters = IO_COUNTERS::default();
        let ok = GetProcessIoCounters(handle, &mut counters).is_ok();
        let _ = CloseHandle(handle);
        if ok {
            // OtherTransferCount captures Winsock/network I/O on Windows alongside Read/Write.
            Some((
                counters.ReadTransferCount.saturating_add(counters.OtherTransferCount),
                counters.WriteTransferCount,
            ))
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn collect_pid_sockets(pids: &[u32]) -> (Vec<UdpEndpointSample>, Vec<TcpEndpointSample>) {
    use std::collections::HashSet;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let pid_set: HashSet<u32> = pids.iter().copied().collect();
    if pid_set.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut udps = Vec::new();
    let mut tcps = Vec::new();

    unsafe {
        // IPv4 UDP table
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(None, &mut size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == 0
            {
                let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID,
                    table.dwNumEntries as usize,
                );
                for row in rows {
                    if pid_set.contains(&row.dwOwningPid) {
                        let port = u16::from_be(row.dwLocalPort as u16);
                        udps.push(UdpEndpointSample {
                            local_port: port,
                            remote_addr: None,
                        });
                    }
                }
            }
        }

        // IPv4 TCP table
        let mut tcp_size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut tcp_size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if tcp_size > 0 {
            let mut buf = vec![0u8; tcp_size as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut tcp_size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == 0
            {
                let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID,
                    table.dwNumEntries as usize,
                );
                for row in rows {
                    if pid_set.contains(&row.dwOwningPid) {
                        let local_port = u16::from_be(row.dwLocalPort as u16);
                        let rem_port = u16::from_be(row.dwRemotePort as u16);
                        let rem_ip = std::net::Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
                        let state = match row.dwState {
                            5 => "ESTABLISHED",
                            2 => "LISTEN",
                            _ => "OTHER",
                        }
                        .to_string();
                        tcps.push(TcpEndpointSample {
                            local_port,
                            remote_addr: format!("{rem_ip}:{rem_port}"),
                            state,
                        });
                    }
                }
            }
        }
    }

    (udps, tcps)
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn find_matching_pids(_install_dir: Option<&Path>, _exe_hints: &[&str]) -> Vec<u32> {
    Vec::new()
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn read_pid_io_bytes(_pid: u32) -> Option<(u64, u64)> {
    None
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn collect_pid_sockets(_pids: &[u32]) -> (Vec<UdpEndpointSample>, Vec<TcpEndpointSample>) {
    (Vec::new(), Vec::new())
}
