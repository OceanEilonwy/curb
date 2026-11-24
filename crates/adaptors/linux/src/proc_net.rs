use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Resolves the owning PID for an outbound TCP/UDP 4-tuple by scanning
/// `/proc/net/{tcp,tcp6,udp,udp6}` for the socket inode and mapping it via
/// `/proc/<pid>/fd/*`.
pub fn resolve_pid_for_socket(
    is_tcp: bool,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<u32> {
    let table_path = match (is_tcp, src_ip) {
        (true, IpAddr::V4(_)) => "/proc/net/tcp",
        (true, IpAddr::V6(_)) => "/proc/net/tcp6",
        (false, IpAddr::V4(_)) => "/proc/net/udp",
        (false, IpAddr::V6(_)) => "/proc/net/udp6",
    };

    let content = fs::read_to_string(table_path).ok()?;
    let inode = find_socket_inode(&content, src_ip, src_port, dst_ip, dst_port)?;
    find_pid_by_socket_inode(inode)
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
            if local_ip == src_ip && rem_ip == dst_ip && rem_port == dst_port {
                return Some(inode);
            }
        }

        if local_ip == src_ip || local_ip.is_unspecified() {
            fallback_inode.get_or_insert(inode);
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
                    return Some(pid);
                }
            }
        }
    }
    None
}

pub fn read_proc_exe(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
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
}
