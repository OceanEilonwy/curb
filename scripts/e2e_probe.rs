//! Minimal zero-dependency Rust network probe for Windows WFP E2E tests.
//!
//! Compiled directly with `rustc -O scripts/e2e_probe.rs -o <path>.exe` so tests
//! can create multiple distinct executables with unique paths and SHA-256 hashes
//! (e.g. `probe-a.exe`, `probe-b.exe`, `probe-blocked.exe`, `probe-tampered.exe`).
//!
//! Subcommands:
//!   tcp  <ip_or_host:port> [timeout_ms]
//!   udp  <ip:port>
//!   dns  <hostname>
//!   http <host> <port> <path> [timeout_ms]
//!   hold <host> <port> <path> <ready_file> <stop_file> [interval_ms]

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn kind_str(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::ConnectionAborted => "connection_aborted",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::WouldBlock => "would_block",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        _ => "other",
    }
}

fn print_err(stage: &str, err: &io::Error) {
    let code = err
        .raw_os_error()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "null".to_string());
    println!(
        "{{\"ok\":false,\"stage\":\"{}\",\"kind\":\"{}\",\"os_error\":{},\"message\":\"{}\"}}",
        escape_json(stage),
        kind_str(err.kind()),
        code,
        escape_json(&err.to_string())
    );
}

fn resolve_first_v4_or_any(target: &str) -> io::Result<SocketAddr> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let addrs: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
    if let Some(v4) = addrs.iter().find(|a| a.is_ipv4()) {
        return Ok(*v4);
    }
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"))
}

fn cmd_tcp(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: tcp <addr:port> [timeout_ms]");
        return ExitCode::from(2);
    }
    let timeout_ms: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let addr = match resolve_first_v4_or_any(&args[0]) {
        Ok(a) => a,
        Err(e) => {
            print_err("dns", &e);
            return ExitCode::from(1);
        }
    };
    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(stream) => {
            let peer = stream
                .peer_addr()
                .map(|p| p.to_string())
                .unwrap_or_else(|_| addr.to_string());
            println!("{{\"ok\":true,\"peer\":\"{}\"}}", escape_json(&peer));
            ExitCode::SUCCESS
        }
        Err(e) => {
            print_err("connect", &e);
            ExitCode::from(1)
        }
    }
}

fn cmd_udp(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: udp <dns_server_ip:port> [timeout_ms]");
        return ExitCode::from(2);
    }
    let timeout_ms: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1500);
    let addr = match resolve_first_v4_or_any(&args[0]) {
        Ok(a) => a,
        Err(e) => {
            print_err("dns", &e);
            return ExitCode::from(1);
        }
    };
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            print_err("bind", &e);
            return ExitCode::from(1);
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
    if let Err(e) = sock.connect(addr) {
        print_err("connect", &e);
        return ExitCode::from(1);
    }
    // Minimal DNS A-record query for example.com (txid 0x1234) so we verify
    // actual kernel UDP packet egress + reply (WFP drops outbound UDP silently
    // after send() queues it, so a round-trip reply proves whether UDP passed).
    let dns_query: [u8; 29] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    if let Err(e) = sock.send(&dns_query) {
        print_err("send", &e);
        return ExitCode::from(1);
    }
    let mut resp = [0u8; 512];
    match sock.recv(&mut resp) {
        Ok(n) if n >= 12 && resp[0] == 0x12 && resp[1] == 0x34 => {
            println!(
                "{{\"ok\":true,\"received\":{},\"peer\":\"{}\"}}",
                n,
                escape_json(&addr.to_string())
            );
            ExitCode::SUCCESS
        }
        Ok(n) => {
            print_err(
                "recv",
                &io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected UDP payload ({n} bytes)"),
                ),
            );
            ExitCode::from(1)
        }
        Err(e) => {
            print_err("recv", &e);
            ExitCode::from(1)
        }
    }
}

fn cmd_dns(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: dns <hostname>");
        return ExitCode::from(2);
    }
    let host = &args[0];
    match (host.as_str(), 80u16).to_socket_addrs() {
        Ok(iter) => {
            let mut ips: Vec<String> = iter.map(|a| a.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            if ips.is_empty() {
                print_err(
                    "dns",
                    &io::Error::new(io::ErrorKind::NotFound, "empty DNS result"),
                );
                return ExitCode::from(1);
            }
            let json_ips: Vec<String> = ips
                .iter()
                .map(|ip| format!("\"{}\"", escape_json(ip)))
                .collect();
            println!("{{\"ok\":true,\"ips\":[{}]}}", json_ips.join(","));
            ExitCode::SUCCESS
        }
        Err(e) => {
            print_err("dns", &e);
            ExitCode::from(1)
        }
    }
}

fn read_http_head_response(stream: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            if buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before HTTP response headers",
                ));
            }
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 16384 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let first_line = text.lines().next().unwrap_or("").trim().to_string();
    if !first_line.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected HTTP status line: {first_line}"),
        ));
    }
    Ok(first_line)
}

fn cmd_http(args: &[String]) -> ExitCode {
    if args.len() < 3 {
        eprintln!("usage: http <host> <port> <path> [timeout_ms]");
        return ExitCode::from(2);
    }
    let host = &args[0];
    let port: u16 = match args[1].parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("invalid port");
            return ExitCode::from(2);
        }
    };
    let path = &args[2];
    let timeout_ms: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let timeout = Duration::from_millis(timeout_ms);

    let addr = match resolve_first_v4_or_any(&format!("{host}:{port}")) {
        Ok(a) => a,
        Err(e) => {
            print_err("dns", &e);
            return ExitCode::from(1);
        }
    };

    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            print_err("connect", &e);
            return ExitCode::from(1);
        }
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curb-e2e-probe/1.0\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = stream.write_all(req.as_bytes()) {
        print_err("write", &e);
        return ExitCode::from(1);
    }

    match read_http_head_response(&mut stream) {
        Ok(status_line) => {
            println!(
                "{{\"ok\":true,\"ip\":\"{}\",\"status_line\":\"{}\"}}",
                escape_json(&addr.ip().to_string()),
                escape_json(&status_line)
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            print_err("read", &e);
            ExitCode::from(1)
        }
    }
}

/// Holds a single persistent HTTP/1.1 keep-alive TCP socket open, issuing periodic
/// HEAD requests over that exact same socket until `stop_file` is created.
/// Any socket drop / ALE reauthorization reset causes an immediate non-zero exit.
fn cmd_hold(args: &[String]) -> ExitCode {
    if args.len() < 5 {
        eprintln!("usage: hold <host> <port> <path> <ready_file> <stop_file> [interval_ms]");
        return ExitCode::from(2);
    }
    let host = &args[0];
    let port: u16 = match args[1].parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("invalid port");
            return ExitCode::from(2);
        }
    };
    let path = &args[2];
    let ready_file = Path::new(&args[3]);
    let stop_file = Path::new(&args[4]);
    let interval_ms: u64 = args
        .get(5)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let timeout = Duration::from_millis(5000);

    let addr = match resolve_first_v4_or_any(&format!("{host}:{port}")) {
        Ok(a) => a,
        Err(e) => {
            print_err("dns", &e);
            return ExitCode::from(1);
        }
    };

    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            print_err("connect", &e);
            return ExitCode::from(1);
        }
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let _ = stream.set_nodelay(true);

    let req = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curb-e2e-probe/1.0\r\nConnection: keep-alive\r\n\r\n"
    );

    if let Err(e) = stream.write_all(req.as_bytes()) {
        print_err("initial_write", &e);
        return ExitCode::from(1);
    }
    if let Err(e) = read_http_head_response(&mut stream) {
        print_err("initial_read", &e);
        return ExitCode::from(1);
    }
    let mut probes: u64 = 1;

    if let Err(e) = fs::write(ready_file, "ready") {
        print_err("ready_file", &e);
        return ExitCode::from(1);
    }

    while !stop_file.exists() {
        thread::sleep(Duration::from_millis(interval_ms));
        if stop_file.exists() {
            break;
        }
        if let Err(e) = stream.write_all(req.as_bytes()) {
            print_err("keepalive_write", &e);
            return ExitCode::from(1);
        }
        if let Err(e) = read_http_head_response(&mut stream) {
            print_err("keepalive_read", &e);
            return ExitCode::from(1);
        }
        probes += 1;
    }

    println!(
        "{{\"ok\":true,\"probes\":{},\"peer\":\"{}\"}}",
        probes,
        escape_json(&addr.to_string())
    );
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: e2e_probe <tcp|udp|dns|http|hold> ...");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "tcp" => cmd_tcp(&args[1..]),
        "udp" => cmd_udp(&args[1..]),
        "dns" => cmd_dns(&args[1..]),
        "http" => cmd_http(&args[1..]),
        "hold" => cmd_hold(&args[1..]),
        other => {
            eprintln!("unknown subcommand: {other}");
            ExitCode::from(2)
        }
    }
}
