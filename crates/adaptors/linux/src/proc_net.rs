use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const INODE_CACHE_TTL: Duration = Duration::from_secs(15);
const MAX_INODE_CACHE_ENTRIES: usize = 4096;

fn inode_pid_cache() -> &'static Mutex<HashMap<u64, (u32, Instant)>> {
    static CACHE: OnceLock<Mutex<HashMap<u64, (u32, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolves the owning PID for an outbound TCP/UDP 4-tuple by scanning
/// `/proc/net/{tcp,tcp6,udp,udp6}` for the socket inode and mapping it via
/// `/proc/<pid>/fd/*` (with a short-TTL inode->PID cache to prevent `/proc`
/// scan storms under UDP/QUIC bursts).
///
/// For IPv4 packets, falls back to `/proc/net/{tcp6,udp6}` using IPv4-mapped
/// IPv6 addresses (`::ffff:a.b.c.d`) so dual-stack `AF_INET6` sockets
/// (`IPV6_V6ONLY=0`, used by Chromium/Electron, Go, Java, Steam/CEF, etc.)
/// are attributed accurately.
pub fn resolve_pid_for_socket(
    is_tcp: bool,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<u32> {
    let primary_path = match (is_tcp, src_ip) {
        (true, IpAddr::V4(_)) => "/proc/net/tcp",
        (true, IpAddr::V6(_)) => "/proc/net/tcp6",
        (false, IpAddr::V4(_)) => "/proc/net/udp",
        (false, IpAddr::V6(_)) => "/proc/net/udp6",
    };

    let mut inode = fs::read_to_string(primary_path)
        .ok()
        .and_then(|content| find_socket_inode(&content, src_ip, src_port, dst_ip, dst_port));

    // Dual-stack AF_INET6 sockets connecting to IPv4 destinations appear in
    // `/proc/net/{tcp6,udp6}` with IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`).
    if inode.is_none() {
        if let (IpAddr::V4(v4_src), IpAddr::V4(v4_dst)) = (src_ip, dst_ip) {
            let v6_path = if is_tcp {
                "/proc/net/tcp6"
            } else {
                "/proc/net/udp6"
            };
            let mapped_src = IpAddr::V6(v4_src.to_ipv6_mapped());
            let mapped_dst = IpAddr::V6(v4_dst.to_ipv6_mapped());
            inode = fs::read_to_string(v6_path)
                .ok()
                .and_then(|content| {
                    find_socket_inode(&content, mapped_src, src_port, mapped_dst, dst_port)
                });
        }
    }

    find_pid_by_socket_inode(inode?)
}

/// Searches `/proc/net/{tcp,tcp6,udp,udp6}` text for a matching socket inode.
pub fn find_socket_inode(
    proc_net_table: &str,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<u64> {
    let mut fallback_inode: Option<u64> = None;

    for line in proc_net_table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((local_ip, local_port)) = parse_proc_net_addr(cols[1]) else {
            continue;
        };
        if local_port != src_port {
            continue;
        }
        let Ok(inode) = cols[9].parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }

        if let Some((rem_ip, rem_port)) = parse_proc_net_addr(cols[2]) {
            if (local_ip == src_ip || local_ip.is_unspecified())
                && rem_ip == dst_ip
                && rem_port == dst_port
            {
                return Some(inode);
            }
            // Only fall back to unconnected sockets (`rem_port == 0`, e.g. UDP `sendto()`)
            // so `SO_REUSEADDR`/`SO_REUSEPORT` sockets connected to a different remote peer
            // are never misattributed.
            if rem_port == 0 && (local_ip == src_ip || local_ip.is_unspecified()) {
                fallback_inode.get_or_insert(inode);
            }
        }
    }

    fallback_inode
}

fn parse_proc_net_addr(token: &str) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = token.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    match ip_hex.len() {
        8 => {
            let raw = u32::from_str_radix(ip_hex, 16).ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())), port))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let chunk = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&chunk.to_ne_bytes());
            }
            Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
        }
        _ => None,
    }
}

fn find_pid_by_socket_inode(inode: u64) -> Option<u32> {
    let now = Instant::now();
    if let Ok(cache) = inode_pid_cache().lock() {
        if let Some(&(pid, cached_at)) = cache.get(&inode) {
            if now.duration_since(cached_at) < INODE_CACHE_TTL && pid_exists(pid) {
                return Some(pid);
            }
        }
    }

    let target = format!("socket:[{inode}]");
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                if link.to_string_lossy() == target {
                    if let Ok(mut cache) = inode_pid_cache().lock() {
                        if cache.len() >= MAX_INODE_CACHE_ENTRIES {
                            cache.retain(|_, (_, ts)| now.duration_since(*ts) < INODE_CACHE_TTL);
                            if cache.len() >= MAX_INODE_CACHE_ENTRIES {
                                cache.clear();
                            }
                        }
                        cache.insert(inode, (pid, now));
                    }
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// Returns `true` if `/proc/<pid>` still exists.
pub fn pid_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Resolves `/proc/<pid>/exe`, stripping the trailing `" (deleted)"` suffix added by
/// the kernel when a package is upgraded while the process is still running.
pub fn read_proc_exe(pid: u32) -> Option<PathBuf> {
    let raw = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(clean_deleted_exe_path(raw))
}

pub fn clean_deleted_exe_path(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_suffix(" (deleted)") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

/// Reads `/proc/<pid>/cmdline` split into NUL-delimited arguments.
pub fn read_proc_cmdline(pid: u32) -> Vec<String> {
    let Ok(bytes) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return Vec::new();
    };
    bytes
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

pub fn read_proc_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let mut parts = after_comm.split_whitespace();
    let _state = parts.next()?;
    parts.next()?.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_v6_proc_hex(addr: Ipv6Addr) -> String {
        let octets = addr.octets();
        let mut s = String::with_capacity(32);
        for i in 0..4 {
            let word = u32::from_ne_bytes(octets[i * 4..(i + 1) * 4].try_into().unwrap());
            s.push_str(&format!("{word:08X}"));
        }
        s
    }

    #[test]
    fn matches_proc_net_tcp_inode() {
        let local_ip = Ipv4Addr::new(192, 168, 1, 42);
        let rem_ip = Ipv4Addr::new(1, 1, 1, 1);
        let local_hex = format!("{:08X}", u32::from_ne_bytes(local_ip.octets()));
        let rem_hex = format!("{:08X}", u32::from_ne_bytes(rem_ip.octets()));
        let table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {local_hex}:D431 {rem_hex}:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 987654 1 00000000\n"
        );
        let inode = find_socket_inode(
            &table,
            IpAddr::V4(local_ip),
            0xD431,
            IpAddr::V4(rem_ip),
            0x01BB,
        );
        assert_eq!(inode, Some(987654));
    }

    #[test]
    fn matches_dual_stack_ipv4_mapped_ipv6_inode() {
        let v4_src = Ipv4Addr::new(192, 168, 1, 42);
        let v4_dst = Ipv4Addr::new(104, 16, 1, 2);
        let mapped_src = v4_src.to_ipv6_mapped();
        let mapped_dst = v4_dst.to_ipv6_mapped();
        let local_hex = encode_v6_proc_hex(mapped_src);
        let rem_hex = encode_v6_proc_hex(mapped_dst);
        let table = format!(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {local_hex}:C001 {rem_hex}:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 555123 1 00000000\n"
        );
        let inode = find_socket_inode(
            &table,
            IpAddr::V6(mapped_src),
            0xC001,
            IpAddr::V6(mapped_dst),
            0x01BB,
        );
        assert_eq!(inode, Some(555123));
    }

    #[test]
    fn fallback_only_matches_unconnected_sockets() {
        let local_ip = Ipv4Addr::new(192, 168, 1, 42);
        let other_rem = Ipv4Addr::new(8, 8, 8, 8);
        let target_rem = Ipv4Addr::new(1, 1, 1, 1);
        let local_hex = format!("{:08X}", u32::from_ne_bytes(local_ip.octets()));
        let other_hex = format!("{:08X}", u32::from_ne_bytes(other_rem.octets()));
        let zero_hex = "00000000";

        // Connected socket to 8.8.8.8:443 on same src_port must NOT match fallback for 1.1.1.1:443.
        let connected_only = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {local_hex}:D431 {other_hex}:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 111111 1 00000000\n"
        );
        assert_eq!(
            find_socket_inode(
                &connected_only,
                IpAddr::V4(local_ip),
                0xD431,
                IpAddr::V4(target_rem),
                0x01BB,
            ),
            None
        );

        // Unconnected UDP socket (`0.0.0.0:0` remote) DOES match fallback.
        let with_unconnected = format!(
            "{connected_only}   1: {zero_hex}:D431 {zero_hex}:0000 07 00000000:00000000 00:00000000 00000000  1000        0 222222 1 00000000\n"
        );
        assert_eq!(
            find_socket_inode(
                &with_unconnected,
                IpAddr::V4(local_ip),
                0xD431,
                IpAddr::V4(target_rem),
                0x01BB,
            ),
            Some(222222)
        );
    }

    #[test]
    fn strips_deleted_suffix_from_upgraded_binary_path() {
        assert_eq!(
            clean_deleted_exe_path(PathBuf::from("/usr/bin/firefox (deleted)")),
            PathBuf::from("/usr/bin/firefox")
        );
        assert_eq!(
            clean_deleted_exe_path(PathBuf::from("/usr/bin/firefox")),
            PathBuf::from("/usr/bin/firefox")
        );
    }
}
