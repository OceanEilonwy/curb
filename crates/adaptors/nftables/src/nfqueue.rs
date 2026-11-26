use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use curb_linux::proc_net::{
    is_kernel_owned_socket, read_proc_exe, read_proc_ppid, resolve_pid_for_socket,
};
use tracing::{debug, info, warn};

use std::time::{Duration, Instant};

use crate::ruleset::{merge_policy_mark, CURB_POLICY_MARK_CLEAR, CURB_POLICY_MARK_MASK};

const NETLINK_NETFILTER: libc::c_int = 12;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_NO_ENOBUFS: libc::c_int = 5;

const NLMSG_ERROR: u16 = 2;
const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;

const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_UNBIND: u8 = 2;

const NFQNL_COPY_PACKET: u8 = 2;

// `<linux/netfilter/nfnetlink_queue.h>` `enum nfqnl_attr_type`:
// 1 = NFQA_PACKET_HDR, 2 = NFQA_VERDICT_HDR, 3 = NFQA_MARK, 9 = NFQA_HWADDR, 10 = NFQA_PAYLOAD
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_PAYLOAD: u16 = 10;

const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NF_REPEAT: u32 = 4;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;

const NFQUEUE_RCVBUF_BYTES: libc::c_int = 4 * 1024 * 1024;
const NFQUEUE_MAXLEN: u32 = 4096;
const NFQUEUE_COPY_RANGE: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
}

/// Verdict returned by the NFQUEUE policy callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfqueueVerdict {
    /// Drop the packet (`NF_DROP`).
    Drop,
    /// Accept the packet (`NF_ACCEPT`).
    Accept,
    /// Re-inject with `NF_REPEAT` + `NFQA_MARK` so `chain output` stamps `ct mark`
    /// for the current policy generation and fast-paths subsequent packets.
    AcceptAndMark(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketTuple {
    pub proto: L4Proto,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

/// Decoded packet + resolved Linux process metadata passed to the verdict callback.
#[derive(Debug, Clone)]
pub struct PacketContext {
    pub tuple: PacketTuple,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub exe_path: Option<PathBuf>,
    /// `true` when no process owns the socket because it is a root-owned kernel socket
    /// (WireGuard, NFS, CIFS, ...), as opposed to PID resolution simply failing.
    pub kernel_socket: bool,
}

struct NetlinkSocket {
    fd: RawFd,
}

impl NetlinkSocket {
    fn open() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;

        let rc = unsafe {
            libc::bind(
                fd,
                (&addr as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        // Expand netlink receive buffer (try SO_RCVBUFFORCE first for CAP_NET_ADMIN,
        // falling back to SO_RCVBUF) and enable NETLINK_NO_ENOBUFS so bursts don't
        // stall packet processing.
        let rcvbuf = NFQUEUE_RCVBUF_BYTES;
        unsafe {
            let force_rc = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                (&rcvbuf as *const libc::c_int).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if force_rc < 0 {
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&rcvbuf as *const libc::c_int).cast::<libc::c_void>(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            let one: libc::c_int = 1;
            let _ = libc::setsockopt(
                fd,
                SOL_NETLINK,
                NETLINK_NO_ENOBUFS,
                (&one as *const libc::c_int).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        Ok(Self { fd })
    }

    fn send(&self, buf: &[u8]) -> io::Result<()> {
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
                (&addr as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let rc = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

fn push_nlattr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let nla_len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(buf.len()) - buf.len();
    buf.resize(buf.len() + pad, 0);
}

fn build_nfq_msg(
    msg_type: u16,
    flags: u16,
    seq: u32,
    family: u8,
    queue_num: u16,
    attrs: &[u8],
) -> Vec<u8> {
    let total_len = (16 + 4 + attrs.len()) as u32;
    let mut msg = Vec::with_capacity(total_len as usize);
    msg.extend_from_slice(&total_len.to_ne_bytes());
    msg.extend_from_slice(&((NFNL_SUBSYS_QUEUE << 8) | msg_type).to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.push(family);
    msg.push(0);
    msg.extend_from_slice(&queue_num.to_be_bytes());
    msg.extend_from_slice(attrs);
    msg
}

fn recv_ack(
    sock: &NetlinkSocket,
    seq: &mut u32,
    queue_num: u16,
    expected_seq: u32,
) -> io::Result<()> {
    let mut buf = [0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::Interrupted
                    || e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut offset = 0usize;
        while offset + 16 <= n {
            let nlmsg_len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            let nlmsg_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
            let nlmsg_seq = u32::from_ne_bytes(buf[offset + 8..offset + 12].try_into().unwrap());
            if nlmsg_len < 16 || offset + nlmsg_len > n {
                break;
            }
            if nlmsg_type == NLMSG_ERROR && nlmsg_len >= 20 && nlmsg_seq == expected_seq {
                let err_code =
                    i32::from_ne_bytes(buf[offset + 16..offset + 20].try_into().unwrap());
                if err_code == 0 {
                    return Ok(());
                }
                return Err(io::Error::from_raw_os_error(-err_code));
            }
            // If packets arrive on a pre-existing queue while awaiting config ACK,
            // drop them immediately so they never leak in the kernel ring.
            if nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) && nlmsg_len >= 20 {
                let attrs = &buf[offset + 20..offset + nlmsg_len];
                if let Some((packet_id, _, _)) = parse_nfq_packet_attrs(attrs) {
                    let _ = send_verdict(sock, seq, queue_num, packet_id, 0, NfqueueVerdict::Drop);
                }
            }
            let step = align4(nlmsg_len);
            if step == 0 {
                break;
            }
            offset += step;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out waiting for NFQUEUE netlink ACK",
    ))
}

fn send_cfg_cmd(
    sock: &NetlinkSocket,
    seq: &mut u32,
    queue_num: u16,
    cmd: u8,
    pf: u16,
    wait_ack: bool,
) -> io::Result<()> {
    *seq = seq.wrapping_add(1);
    let expected_seq = *seq;
    let mut payload = [0u8; 4];
    payload[0] = cmd;
    payload[1] = 0;
    payload[2..4].copy_from_slice(&pf.to_be_bytes());
    let mut attrs = Vec::new();
    push_nlattr(&mut attrs, NFQA_CFG_CMD, &payload);
    let flags = if wait_ack {
        NLM_F_REQUEST | NLM_F_ACK
    } else {
        NLM_F_REQUEST
    };
    let msg = build_nfq_msg(
        NFQNL_MSG_CONFIG,
        flags,
        expected_seq,
        libc::AF_UNSPEC as u8,
        queue_num,
        &attrs,
    );
    sock.send(&msg)?;
    if wait_ack {
        recv_ack(sock, seq, queue_num, expected_seq)?;
    }
    Ok(())
}

fn send_cfg_params(sock: &NetlinkSocket, seq: &mut u32, queue_num: u16) -> io::Result<()> {
    *seq = seq.wrapping_add(1);
    let expected_seq = *seq;
    let mut payload = [0u8; 5];
    payload[0..4].copy_from_slice(&NFQUEUE_COPY_RANGE.to_be_bytes());
    payload[4] = NFQNL_COPY_PACKET;
    let mut attrs = Vec::new();
    push_nlattr(&mut attrs, NFQA_CFG_PARAMS, &payload);
    push_nlattr(&mut attrs, NFQA_CFG_QUEUE_MAXLEN, &NFQUEUE_MAXLEN.to_be_bytes());
    let msg = build_nfq_msg(
        NFQNL_MSG_CONFIG,
        NLM_F_REQUEST | NLM_F_ACK,
        expected_seq,
        libc::AF_UNSPEC as u8,
        queue_num,
        &attrs,
    );
    sock.send(&msg)?;
    recv_ack(sock, seq, queue_num, expected_seq)
}

/// Resolves an `NfqueueVerdict` into `(nf_verdict, optional_nfqa_mark)`.
/// If a packet already carries the exact Curb policy mark we are about to stamp via
/// `NF_REPEAT`, downgrade to `NF_ACCEPT` (clearing Curb's top byte while preserving
/// lower 24-bit VPN/routing marks) so a generation-transition race can never cause an
/// infinite `NF_REPEAT` loop.
fn resolve_verdict_and_mark(existing_mark: u32, verdict: NfqueueVerdict) -> (u32, Option<u32>) {
    match verdict {
        NfqueueVerdict::Drop => (NF_DROP, None),
        NfqueueVerdict::Accept => {
            if (existing_mark & CURB_POLICY_MARK_MASK) != 0 {
                (NF_ACCEPT, Some(existing_mark & CURB_POLICY_MARK_CLEAR))
            } else {
                (NF_ACCEPT, None)
            }
        }
        NfqueueVerdict::AcceptAndMark(m) => {
            let masked_new = m & CURB_POLICY_MARK_MASK;
            let masked_existing = existing_mark & CURB_POLICY_MARK_MASK;
            if masked_new != 0 && masked_existing == masked_new {
                (NF_ACCEPT, Some(existing_mark & CURB_POLICY_MARK_CLEAR))
            } else {
                (NF_REPEAT, Some(merge_policy_mark(existing_mark, m)))
            }
        }
    }
}

fn send_verdict(
    sock: &NetlinkSocket,
    seq: &mut u32,
    queue_num: u16,
    packet_id: u32,
    existing_mark: u32,
    verdict: NfqueueVerdict,
) -> io::Result<()> {
    *seq = seq.wrapping_add(1);
    let (nf_verdict, mark) = resolve_verdict_and_mark(existing_mark, verdict);
    let mut payload = [0u8; 8];
    payload[0..4].copy_from_slice(&nf_verdict.to_be_bytes());
    payload[4..8].copy_from_slice(&packet_id.to_be_bytes());
    let mut attrs = Vec::new();
    push_nlattr(&mut attrs, NFQA_VERDICT_HDR, &payload);
    if let Some(m) = mark {
        push_nlattr(&mut attrs, NFQA_MARK, &m.to_be_bytes());
    }
    let msg = build_nfq_msg(
        NFQNL_MSG_VERDICT,
        NLM_F_REQUEST,
        *seq,
        libc::AF_UNSPEC as u8,
        queue_num,
        &attrs,
    );
    sock.send(&msg)
}

/// Runs the blocking NFQUEUE packet loop until `stop` is set to `true`.
/// Invokes `decide(&PacketContext)` for each queued TCP/UDP packet and sends
/// `NF_ACCEPT` or `NF_DROP` back to the kernel.
pub fn run_nfqueue_loop<F>(queue_num: u16, stop: Arc<AtomicBool>, decide: F) -> io::Result<()>
where
    F: Fn(&PacketContext) -> bool,
{
    let ready = Arc::new(AtomicBool::new(false));
    run_nfqueue_loop_with_ready(queue_num, stop, ready, |ctx| {
        if decide(ctx) {
            NfqueueVerdict::Accept
        } else {
            NfqueueVerdict::Drop
        }
    })
}

/// Runs the blocking NFQUEUE packet loop, verifying kernel bind ACKs, setting
/// `ready` to `true` once bound, and supporting `AcceptAndMark` verdicts for
/// conntrack policy-generation stamping.
pub fn run_nfqueue_loop_with_ready<F>(
    queue_num: u16,
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    decide: F,
) -> io::Result<()>
where
    F: Fn(&PacketContext) -> NfqueueVerdict,
{
    let sock = NetlinkSocket::open()?;
    let mut seq = 0u32;

    // Retry briefly on EEXIST/EBUSY/EADDRINUSE so rapid protection off->on toggles
    // never fail while the kernel finishes releasing the previous netlink queue binding.
    let mut bind_err = None;
    for attempt in 0..8 {
        match send_cfg_cmd(&sock, &mut seq, queue_num, NFQNL_CFG_CMD_BIND, 0, true) {
            Ok(()) => {
                bind_err = None;
                break;
            }
            Err(e) => {
                let transient = matches!(
                    e.raw_os_error(),
                    Some(libc::EEXIST | libc::EBUSY | libc::EADDRINUSE)
                );
                if transient && attempt < 7 && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                    bind_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    if let Some(e) = bind_err {
        return Err(e);
    }
    send_cfg_params(&sock, &mut seq, queue_num)?;

    ready.store(true, Ordering::Release);
    info!("Curb NFQUEUE verifier bound to queue {queue_num} (maxlen={NFQUEUE_MAXLEN})");

    let mut buf = vec![0u8; 65536];
    while !stop.load(Ordering::Relaxed) {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(e) => {
                warn!("NFQUEUE recv error: {e}");
                continue;
            }
        };

        let mut offset = 0usize;
        while offset + 16 <= n {
            let nlmsg_len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            let nlmsg_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
            if nlmsg_len < 16 || offset + nlmsg_len > n {
                break;
            }

            if nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) && nlmsg_len >= 20 {
                let attrs = &buf[offset + 20..offset + nlmsg_len];
                if let Some((packet_id, existing_mark, payload_opt)) = parse_nfq_packet_attrs(attrs)
                {
                    let verdict = match payload_opt.and_then(parse_ip_packet) {
                        Some(tuple) => {
                            let pid = resolve_pid_for_socket(
                                tuple.proto == L4Proto::Tcp,
                                tuple.src_ip,
                                tuple.src_port,
                                tuple.dst_ip,
                                tuple.dst_port,
                            );
                            let exe_path = pid.and_then(read_proc_exe);
                            let kernel_socket = pid.is_none()
                                && is_kernel_owned_socket(
                                    tuple.proto == L4Proto::Tcp,
                                    tuple.src_ip,
                                    tuple.src_port,
                                    tuple.dst_ip,
                                    tuple.dst_port,
                                );
                            let ctx = PacketContext {
                                tuple,
                                pid,
                                ppid: pid.and_then(read_proc_ppid),
                                exe_path,
                                kernel_socket,
                            };
                            decide(&ctx)
                        }
                        None => NfqueueVerdict::Drop,
                    };
                    if let Err(e) = send_verdict(
                        &sock,
                        &mut seq,
                        queue_num,
                        packet_id,
                        existing_mark,
                        verdict,
                    ) {
                        debug!("Failed to send NFQUEUE verdict for packet {packet_id}: {e}");
                    }
                }
            }

            let step = align4(nlmsg_len);
            if step == 0 {
                break;
            }
            offset += step;
        }
    }

    ready.store(false, Ordering::Release);
    let _ = send_cfg_cmd(&sock, &mut seq, queue_num, NFQNL_CFG_CMD_UNBIND, 0, false);
    info!("Curb NFQUEUE verifier unbound from queue {queue_num}");
    Ok(())
}

/// Parses `NFQNL_MSG_PACKET` attributes, returning `(packet_id, existing_mark, payload)`.
/// Always returns `Some` whenever `NFQA_PACKET_HDR` is present so the caller never leaks
/// a queued packet in the kernel ring even if `NFQA_PAYLOAD` is missing.
fn parse_nfq_packet_attrs(mut data: &[u8]) -> Option<(u32, u32, Option<&[u8]>)> {
    let mut packet_id: Option<u32> = None;
    let mut existing_mark: u32 = 0;
    let mut payload: Option<&[u8]> = None;

    while data.len() >= 4 {
        let nla_len = u16::from_ne_bytes([data[0], data[1]]) as usize;
        let nla_type = u16::from_ne_bytes([data[2], data[3]]) & 0x3fff;
        if nla_len < 4 || nla_len > data.len() {
            break;
        }
        let val = &data[4..nla_len];
        match nla_type {
            NFQA_PACKET_HDR if val.len() >= 4 => {
                packet_id = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
            }
            NFQA_MARK if val.len() >= 4 => {
                existing_mark = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
            }
            NFQA_PAYLOAD => {
                payload = Some(val);
            }
            _ => {}
        }
        let step = align4(nla_len);
        if step >= data.len() {
            break;
        }
        data = &data[step..];
    }

    Some((packet_id?, existing_mark, payload))
}

/// Parses an IPv4 or IPv6 packet header (including IPv6 extension headers) and
/// extracts its TCP/UDP 5-tuple.
pub fn parse_ip_packet(pkt: &[u8]) -> Option<PacketTuple> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl + 4 {
                return None;
            }
            let proto = match pkt[9] {
                6 => L4Proto::Tcp,
                17 => L4Proto::Udp,
                _ => return None,
            };
            let src_ip = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
            let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            Some(PacketTuple {
                proto,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            })
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let src_bytes: [u8; 16] = pkt[8..24].try_into().ok()?;
            let dst_bytes: [u8; 16] = pkt[24..40].try_into().ok()?;
            let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

            let mut next_hdr = pkt[6];
            let mut offset = 40usize;
            for _ in 0..8 {
                match next_hdr {
                    6 => {
                        if pkt.len() < offset + 4 {
                            return None;
                        }
                        let src_port = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
                        let dst_port = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
                        return Some(PacketTuple {
                            proto: L4Proto::Tcp,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        });
                    }
                    17 => {
                        if pkt.len() < offset + 4 {
                            return None;
                        }
                        let src_port = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
                        let dst_port = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
                        return Some(PacketTuple {
                            proto: L4Proto::Udp,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        });
                    }
                    // Hop-by-Hop (0), Routing (43), Destination Options (60), Mobility (135)
                    0 | 43 | 60 | 135 => {
                        if pkt.len() < offset + 2 {
                            return None;
                        }
                        next_hdr = pkt[offset];
                        let hdr_len = (pkt[offset + 1] as usize + 1) * 8;
                        offset = offset.checked_add(hdr_len)?;
                    }
                    // Fragment header (44): fixed 8 bytes
                    44 => {
                        if pkt.len() < offset + 8 {
                            return None;
                        }
                        next_hdr = pkt[offset];
                        offset = offset.checked_add(8)?;
                    }
                    // Authentication Header (51, RFC 4302): (payload_len + 2) * 4 bytes
                    51 => {
                        if pkt.len() < offset + 2 {
                            return None;
                        }
                        next_hdr = pkt[offset];
                        let hdr_len = (pkt[offset + 1] as usize + 2) * 4;
                        offset = offset.checked_add(hdr_len)?;
                    }
                    _ => return None,
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nfqa_payload_attr_10_and_existing_mark_ignoring_hwaddr_9() {
        let mut attrs = Vec::new();
        // NFQA_PACKET_HDR (1): packet_id = 0x11223344, hw_protocol = 0x0800, hook = 3
        let mut hdr = [0u8; 7];
        hdr[0..4].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        push_nlattr(&mut attrs, NFQA_PACKET_HDR, &hdr);
        // NFQA_MARK (3): existing VPN mark 0x0008_ca6c
        push_nlattr(&mut attrs, NFQA_MARK, &0x0008_CA6Cu32.to_be_bytes());
        // NFQA_HWADDR (9): must NOT be confused with NFQA_PAYLOAD (10)
        push_nlattr(&mut attrs, 9, &[0xAA, 0xBB, 0xCC, 0xDD]);
        // NFQA_PAYLOAD (10): actual IP packet bytes
        let fake_ip = [0x45u8, 0x00, 0x00, 0x18];
        push_nlattr(&mut attrs, 10, &fake_ip);

        let (pkt_id, mark, payload) =
            parse_nfq_packet_attrs(&attrs).expect("parsed NFQ packet attrs");
        assert_eq!(pkt_id, 0x1122_3344);
        assert_eq!(mark, 0x0008_CA6C);
        assert_eq!(payload, Some(&fake_ip[..]));
    }

    #[test]
    fn returns_packet_id_even_when_payload_is_missing() {
        let mut attrs = Vec::new();
        let mut hdr = [0u8; 7];
        hdr[0..4].copy_from_slice(&42u32.to_be_bytes());
        push_nlattr(&mut attrs, NFQA_PACKET_HDR, &hdr);

        let (pkt_id, mark, payload) =
            parse_nfq_packet_attrs(&attrs).expect("packet_id returned without payload");
        assert_eq!(pkt_id, 42);
        assert_eq!(mark, 0);
        assert_eq!(payload, None);
    }

    #[test]
    fn parses_ipv4_tcp_packet() {
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 42]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&54321u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());

        let tuple = parse_ip_packet(&pkt).expect("parsed IPv4 TCP");
        assert_eq!(tuple.proto, L4Proto::Tcp);
        assert_eq!(tuple.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(tuple.dst_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(tuple.src_port, 54321);
        assert_eq!(tuple.dst_port, 443);
    }

    #[test]
    fn parses_ipv6_udp_packet() {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x60;
        pkt[6] = 17;
        pkt[23] = 1;
        pkt[24..40]
            .copy_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        pkt[40..42].copy_from_slice(&40000u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&443u16.to_be_bytes());

        let tuple = parse_ip_packet(&pkt).expect("parsed IPv6 UDP");
        assert_eq!(tuple.proto, L4Proto::Udp);
        assert_eq!(tuple.src_port, 40000);
        assert_eq!(tuple.dst_port, 443);
    }

    #[test]
    fn parses_ipv6_tcp_packet_with_extension_headers() {
        // 40B IPv6 base + 8B Hop-by-Hop (0) + 8B Fragment (44) + 16B AH (51) + 4B TCP ports
        let mut pkt = vec![0u8; 76];
        pkt[0] = 0x60;
        pkt[6] = 0; // Hop-by-Hop
        pkt[23] = 1;
        pkt[24..40]
            .copy_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        // Hop-by-Hop at offset 40: next=44 (Fragment), hdr_ext_len=0 (8 bytes)
        pkt[40] = 44;
        pkt[41] = 0;
        // Fragment at offset 48: next=51 (AH)
        pkt[48] = 51;
        // AH at offset 56: next=6 (TCP), payload_len=2 => (2 + 2) * 4 = 16 bytes
        pkt[56] = 6;
        pkt[57] = 2;
        // TCP ports at offset 72
        pkt[72..74].copy_from_slice(&51234u16.to_be_bytes());
        pkt[74..76].copy_from_slice(&443u16.to_be_bytes());

        let tuple = parse_ip_packet(&pkt).expect("parsed IPv6 TCP with extension headers + AH");
        assert_eq!(tuple.proto, L4Proto::Tcp);
        assert_eq!(tuple.src_port, 51234);
        assert_eq!(tuple.dst_port, 443);
    }

    #[test]
    fn resolve_verdict_prevents_nf_repeat_loop_and_preserves_vpn_mark() {
        let vpn_mark = 0x0008_CA6C;
        let gen_mark = 0x0200_0000;

        // First pass: packet has no Curb policy mark -> NF_REPEAT with merged mark.
        assert_eq!(
            resolve_verdict_and_mark(vpn_mark, NfqueueVerdict::AcceptAndMark(gen_mark)),
            (NF_REPEAT, Some(gen_mark | vpn_mark))
        );

        // If the packet somehow re-enters the queue already carrying the same Curb
        // policy mark (e.g. during a ruleset generation reload), downgrade to NF_ACCEPT
        // and clear only Curb's top byte so it never loops infinitely.
        assert_eq!(
            resolve_verdict_and_mark(gen_mark | vpn_mark, NfqueueVerdict::AcceptAndMark(gen_mark)),
            (NF_ACCEPT, Some(vpn_mark))
        );

        // Plain Accept also strips any stale Curb top-byte mark while preserving VPN mark.
        assert_eq!(
            resolve_verdict_and_mark(gen_mark | vpn_mark, NfqueueVerdict::Accept),
            (NF_ACCEPT, Some(vpn_mark))
        );
        assert_eq!(
            resolve_verdict_and_mark(vpn_mark, NfqueueVerdict::Accept),
            (NF_ACCEPT, None)
        );
    }
}
