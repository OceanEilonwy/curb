use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use curb_core::config::{BaselinePolicy, NetworkPolicy};
use tracing::{info, warn};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmNetEventCreateEnumHandle0,
    FwpmNetEventDestroyEnumHandle0, FwpmNetEventEnum0, FwpmProviderAdd0, FwpmSubLayerAdd0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_NET_EVENT0, FWPM_NET_EVENT_ENUM_TEMPLATE0, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
    FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
    FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT16,
    FWP_UINT32, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

use curb_core::cleanup::{CURB_PROVIDER_UUID, CURB_SUBLAYER_UUID};

/// Stable Curb WFP Provider GUID.
pub const CURB_PROVIDER_GUID: GUID = GUID::from_u128(CURB_PROVIDER_UUID);

/// Stable Curb WFP Sublayer GUID (high weight so Curb rules take precedence).
pub const CURB_SUBLAYER_GUID: GUID = GUID::from_u128(CURB_SUBLAYER_UUID);

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Manages both Curb's persistent default-deny WFP filters and its dynamic
/// per-session allow filters (`FWPM_SESSION_FLAG_DYNAMIC`).
pub struct WfpController {
    persistent_engine: HANDLE,
    dynamic_engine: HANDLE,
    persistent_filter_ids: Vec<u64>,
    service_dns_filter_ids: Vec<u64>,
}

unsafe impl Send for WfpController {}

impl WfpController {
    /// Opens persistent + dynamic WFP sessions, purges any stale persistent filters
    /// from prior runs, registers Curb's provider & sublayer, and enables WFP net event
    /// collection so classify drops against Curb's default-deny filters can be surfaced.
    pub fn open() -> Result<Self, String> {
        let _ = curb_core::cleanup::purge_all_curb_wfp_objects();

        let persistent_engine = open_engine(false)?;
        let dynamic_engine = open_engine(true)?;

        // Enable WFP net event collection so blocked connection attempts can be enumerated.
        let collect_val = FWP_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_VALUE0_0 { uint32: 1 },
        };
        unsafe {
            let _ = FwpmEngineSetOption0(
                persistent_engine,
                FWPM_ENGINE_COLLECT_NET_EVENTS,
                &collect_val,
            );
        }

        let ctrl = Self {
            persistent_engine,
            dynamic_engine,
            persistent_filter_ids: Vec::new(),
            service_dns_filter_ids: Vec::new(),
        };
        ctrl.ensure_provider_and_sublayer();
        Ok(ctrl)
    }

    fn ensure_provider_and_sublayer(&self) {
        let mut name: Vec<u16> = "Curb Internet Limiter\0".encode_utf16().collect();
        let mut desc: Vec<u16> = "Default-deny application firewall managed by Curb\0"
            .encode_utf16()
            .collect();

        let provider = FWPM_PROVIDER0 {
            providerKey: CURB_PROVIDER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(desc.as_mut_ptr()),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };

        unsafe {
            // FWP_E_ALREADY_EXISTS is expected on subsequent startups.
            let _ = FwpmProviderAdd0(self.persistent_engine, &provider, None);
        }

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: CURB_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(desc.as_mut_ptr()),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &CURB_PROVIDER_GUID as *const _ as *mut _,
            weight: 0xFFFF,
            ..Default::default()
        };

        unsafe {
            let _ = FwpmSubLayerAdd0(self.persistent_engine, &sublayer, None);
        }
    }

    /// Atomically installs persistent outbound default-deny filters across IPv4 and IPv6
    /// for TCP and UDP (leaving ICMPv4 PMTUD, ICMPv6 Neighbor Discovery, and inbound
    /// replies on established/UDP sockets unimpeded), plus the configured OS baseline
    /// rules (loopback, DHCP, NTP, and DNS resolution for `curb-service.exe` and
    /// Windows `Dnscache` / `svchost.exe`).
    pub fn install_default_deny_and_baseline(
        &mut self,
        baseline: &BaselinePolicy,
        service_exe_path: Option<&Path>,
    ) -> Result<(), String> {
        let outbound_layers = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ];

        let mut new_persistent = Vec::new();
        let old_persistent: Vec<u64> = self.persistent_filter_ids.drain(..).collect();

        let tx_ok = with_transaction(self.persistent_engine, || {
            for id in &old_persistent {
                unsafe {
                    let _ = FwpmFilterDeleteById0(self.persistent_engine, *id);
                }
            }

            // 1. Default-deny outbound TCP and UDP (lowest weight = 1).
            // Scoping to TCP and UDP ensures ICMPv4 (Path MTU Discovery) and ICMPv6
            // (Neighbor Discovery / Router Solicitation / Router Advertisement) are never blocked.
            for layer in outbound_layers {
                for proto in [IPPROTO_TCP, IPPROTO_UDP] {
                    let conds = [proto_condition(proto)];
                    if let Ok(id) = self.add_filter(
                        self.persistent_engine,
                        layer,
                        "Curb Default Deny",
                        FWP_ACTION_BLOCK,
                        1,
                        FWPM_FILTER_FLAG_PERSISTENT,
                        &conds,
                    ) {
                        new_persistent.push(id);
                    }
                }
            }

            // 2. Loopback baseline (weight = 10)
            if baseline.loopback {
                let cond = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_FLAGS,
                    matchType: FWP_MATCH_FLAGS_ALL_SET,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT32,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                        },
                    },
                };
                for layer in outbound_layers {
                    if let Ok(id) = self.add_filter(
                        self.persistent_engine,
                        layer,
                        "Curb Baseline Loopback",
                        FWP_ACTION_PERMIT,
                        10,
                        FWPM_FILTER_FLAG_PERSISTENT,
                        &[cond],
                    ) {
                        new_persistent.push(id);
                    }
                }
            }

            // 3. DHCP baseline (outbound requests)
            if baseline.dhcp {
                for (layer, port) in [
                    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, 67u16),
                    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, 68u16),
                    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, 547u16),
                    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, 546u16),
                ] {
                    let conds = [
                        proto_condition(IPPROTO_UDP),
                        remote_port_condition(port),
                    ];
                    if let Ok(id) = self.add_filter(
                        self.persistent_engine,
                        layer,
                        "Curb Baseline DHCP Outbound",
                        FWP_ACTION_PERMIT,
                        10,
                        FWPM_FILTER_FLAG_PERSISTENT,
                        &conds,
                    ) {
                        new_persistent.push(id);
                    }
                }
            }

            // 4. NTP baseline (UDP 123)
            if baseline.ntp {
                let conds = [proto_condition(IPPROTO_UDP), remote_port_condition(123)];
                for layer in outbound_layers {
                    if let Ok(id) = self.add_filter(
                        self.persistent_engine,
                        layer,
                        "Curb Baseline NTP",
                        FWP_ACTION_PERMIT,
                        10,
                        FWPM_FILTER_FLAG_PERSISTENT,
                        &conds,
                    ) {
                        new_persistent.push(id);
                    }
                }
            }

            Ok::<(), String>(())
        });

        if let Err(e) = tx_ok {
            return Err(e);
        }
        self.persistent_filter_ids = new_persistent;

        // 5. Permit ONLY `curb-service.exe` to send upstream DNS (UDP/TCP 53).
        // Windows DNS Client (`svchost.exe` / `Dnscache`) resolves through Curb's local
        // DNS proxy on `127.0.0.1:53` / `[::1]:53` via the loopback baseline, ensuring
        // all DNS traffic is inspected and populates `DnsCache` without allowing DNS
        // bypasses or tunneling over non-redirected adapters.
        let old_svc_ids: Vec<u64> = self.service_dns_filter_ids.drain(..).collect();
        self.remove_dynamic_filters(&old_svc_ids);

        let dns_policy = NetworkPolicy {
            allow_tcp: true,
            allow_udp: true,
            dns_whitelist: None,
        };
        let mut dns_filter_ids = Vec::new();
        if let Some(svc_path) = service_exe_path {
            match self.replace_app_dynamic(&[], svc_path, &dns_policy, None, Some(53)) {
                Ok(ids) => dns_filter_ids.extend(ids),
                Err(e) => warn!("Failed to permit curb-service.exe upstream DNS in WFP: {e}"),
            }
        }
        self.service_dns_filter_ids = dns_filter_ids;

        info!(
            "Installed {} persistent WFP default-deny & baseline filters (+ {} service DNS filters)",
            self.persistent_filter_ids.len(),
            self.service_dns_filter_ids.len()
        );
        Ok(())
    }

    /// Inserts dynamic session-scoped `PERMIT` filters for a verified running executable
    /// inside a single atomic WFP transaction.
    /// These filters vanish automatically if `curb-service` stops or crashes (fail-closed).
    #[allow(dead_code)]
    pub fn permit_app_dynamic(
        &self,
        exe_path: &Path,
        network: &NetworkPolicy,
        allowed_ips: Option<&[IpAddr]>,
        fixed_remote_port: Option<u16>,
    ) -> Result<Vec<u64>, String> {
        self.replace_app_dynamic(&[], exe_path, network, allowed_ips, fixed_remote_port)
    }

    /// Atomically replaces `old_ids` with a new set of dynamic `PERMIT` filters for
    /// `exe_path` inside a single WFP transaction, avoiding transient blocks or
    /// repeated ALE reauthorization waves.
    pub fn replace_app_dynamic(
        &self,
        old_ids: &[u64],
        exe_path: &Path,
        network: &NetworkPolicy,
        allowed_ips: Option<&[IpAddr]>,
        fixed_remote_port: Option<u16>,
    ) -> Result<Vec<u64>, String> {
        let ports = fixed_remote_port.map(|p| [p]);
        self.replace_app_dynamic_ports(
            old_ids,
            exe_path,
            network,
            allowed_ips,
            ports.as_ref().map_or(&[], |p| p.as_slice()),
        )
    }

    /// Atomically replaces `old_ids` with dynamic `PERMIT` filters for `exe_path`,
    /// optionally scoped to one or more `fixed_remote_ports` (e.g. TCP 80 & 443 for NCSI).
    pub fn replace_app_dynamic_ports(
        &self,
        old_ids: &[u64],
        exe_path: &Path,
        network: &NetworkPolicy,
        allowed_ips: Option<&[IpAddr]>,
        fixed_remote_ports: &[u16],
    ) -> Result<Vec<u64>, String> {
        let app_blob = get_app_id_blob(exe_path)?;
        let mut protos = Vec::new();
        if network.allow_tcp {
            protos.push(IPPROTO_TCP);
        }
        if network.allow_udp {
            protos.push(IPPROTO_UDP);
        }

        let port_opts: Vec<Option<u16>> = if fixed_remote_ports.is_empty() {
            vec![None]
        } else {
            fixed_remote_ports.iter().copied().map(Some).collect()
        };

        let app_cond = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_blob },
            },
        };

        let mut ids = Vec::new();
        let tx_res = with_transaction(self.dynamic_engine, || {
            for &id in old_ids {
                unsafe {
                    let _ = FwpmFilterDeleteById0(self.dynamic_engine, id);
                }
            }

            for &proto in &protos {
                for &fixed_port in &port_opts {
                    match allowed_ips {
                        None => {
                            let mut conds = vec![app_cond, proto_condition(proto)];
                            if let Some(port) = fixed_port {
                                conds.push(remote_port_condition(port));
                            }
                            for layer in [
                                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            ] {
                                let id = self.add_filter(
                                    self.dynamic_engine,
                                    layer,
                                    "Curb Dynamic App Allow",
                                    FWP_ACTION_PERMIT,
                                    15,
                                    Default::default(),
                                    &conds,
                                )?;
                                ids.push(id);
                            }
                        }
                        Some(ips) => {
                            for &ip in ips {
                                match ip {
                                    IpAddr::V4(v4) => {
                                        let ip_u32 = u32::from(v4);
                                        let ip_cond = FWPM_FILTER_CONDITION0 {
                                            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                            matchType: FWP_MATCH_EQUAL,
                                            conditionValue: FWP_CONDITION_VALUE0 {
                                                r#type: FWP_UINT32,
                                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                                    uint32: ip_u32,
                                                },
                                            },
                                        };
                                        let mut conds =
                                            vec![app_cond, proto_condition(proto), ip_cond];
                                        if let Some(port) = fixed_port {
                                            conds.push(remote_port_condition(port));
                                        }
                                        if let Ok(id) = self.add_filter(
                                            self.dynamic_engine,
                                            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                            "Curb Dynamic DNS-Scoped Allow v4",
                                            FWP_ACTION_PERMIT,
                                            15,
                                            Default::default(),
                                            &conds,
                                        ) {
                                            ids.push(id);
                                        }
                                    }
                                    IpAddr::V6(v6) => {
                                        let mut arr = FWP_BYTE_ARRAY16 {
                                            byteArray16: v6.octets(),
                                        };
                                        let ip_cond = FWPM_FILTER_CONDITION0 {
                                            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                            matchType: FWP_MATCH_EQUAL,
                                            conditionValue: FWP_CONDITION_VALUE0 {
                                                r#type: FWP_BYTE_ARRAY16_TYPE,
                                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                                    byteArray16: &mut arr,
                                                },
                                            },
                                        };
                                        let mut conds =
                                            vec![app_cond, proto_condition(proto), ip_cond];
                                        if let Some(port) = fixed_port {
                                            conds.push(remote_port_condition(port));
                                        }
                                        if let Ok(id) = self.add_filter(
                                            self.dynamic_engine,
                                            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                            "Curb Dynamic DNS-Scoped Allow v6",
                                            FWP_ACTION_PERMIT,
                                            15,
                                            Default::default(),
                                            &conds,
                                        ) {
                                            ids.push(id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Permit Media Router / Cast LAN multicast discovery (SSDP + mDNS) for
            // DNS-scoped apps with UDP enabled (such as `steamwebhelper.exe`), without
            // opening arbitrary UDP destinations.
            if allowed_ips.is_some() && network.allow_udp && fixed_remote_ports.is_empty() {
                for (v4, port, label) in [
                    (
                        Ipv4Addr::new(239, 255, 255, 250),
                        1900u16,
                        "Curb Dynamic Media Router SSDP v4",
                    ),
                    (
                        Ipv4Addr::new(224, 0, 0, 251),
                        5353u16,
                        "Curb Dynamic Media Router mDNS v4",
                    ),
                ] {
                    let ip_cond = FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT32,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint32: u32::from(v4),
                            },
                        },
                    };
                    let conds = [
                        app_cond,
                        proto_condition(IPPROTO_UDP),
                        ip_cond,
                        remote_port_condition(port),
                    ];
                    if let Ok(id) = self.add_filter(
                        self.dynamic_engine,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        label,
                        FWP_ACTION_PERMIT,
                        15,
                        Default::default(),
                        &conds,
                    ) {
                        ids.push(id);
                    }
                }

                for (v6, port, label) in [
                    (
                        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c),
                        1900u16,
                        "Curb Dynamic Media Router SSDP v6",
                    ),
                    (
                        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
                        5353u16,
                        "Curb Dynamic Media Router mDNS v6",
                    ),
                ] {
                    let mut arr = FWP_BYTE_ARRAY16 {
                        byteArray16: v6.octets(),
                    };
                    let ip_cond = FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_BYTE_ARRAY16_TYPE,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                byteArray16: &mut arr,
                            },
                        },
                    };
                    let conds = [
                        app_cond,
                        proto_condition(IPPROTO_UDP),
                        ip_cond,
                        remote_port_condition(port),
                    ];
                    if let Ok(id) = self.add_filter(
                        self.dynamic_engine,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        label,
                        FWP_ACTION_PERMIT,
                        15,
                        Default::default(),
                        &conds,
                    ) {
                        ids.push(id);
                    }
                }
            }

            Ok::<(), String>(())
        });

        unsafe {
            let mut raw = app_blob as *mut std::ffi::c_void;
            FwpmFreeMemory0(&mut raw);
        }

        tx_res?;
        Ok(ids)
    }

    pub fn remove_dynamic_filters(&self, ids: &[u64]) {
        if ids.is_empty() {
            return;
        }
        let _ = with_transaction(self.dynamic_engine, || {
            for &id in ids {
                unsafe {
                    let _ = FwpmFilterDeleteById0(self.dynamic_engine, id);
                }
            }
            Ok::<(), String>(())
        });
    }

    pub fn clear_persistent_filters(&mut self) {
        let persistent_ids: Vec<u64> = self.persistent_filter_ids.drain(..).collect();
        if !persistent_ids.is_empty() {
            let _ = with_transaction(self.persistent_engine, || {
                for id in persistent_ids {
                    unsafe {
                        let _ = FwpmFilterDeleteById0(self.persistent_engine, id);
                    }
                }
                Ok::<(), String>(())
            });
        }

        let svc_ids: Vec<u64> = self.service_dns_filter_ids.drain(..).collect();
        self.remove_dynamic_filters(&svc_ids);
    }

    /// Polls recent WFP `FWPM_NET_EVENT_TYPE_CLASSIFY_DROP` events triggered by Curb's
    /// persistent default-deny filters between `start_ft` and `end_ft`, returning
    /// `(win32_exe_path, remote_ip, remote_port)` tuples.
    pub fn poll_classify_drops(
        &self,
        start_ft: FILETIME,
        end_ft: FILETIME,
    ) -> Vec<(String, IpAddr, u16)> {
        if self.persistent_filter_ids.is_empty() {
            return Vec::new();
        }
        let template = FWPM_NET_EVENT_ENUM_TEMPLATE0 {
            startTime: start_ft,
            endTime: end_ft,
            numFilterConditions: 0,
            filterCondition: ptr::null_mut(),
        };

        let mut out = Vec::new();
        unsafe {
            let mut enum_handle = HANDLE::default();
            if FwpmNetEventCreateEnumHandle0(
                self.persistent_engine,
                Some(&template),
                &mut enum_handle,
            ) != 0
            {
                return out;
            }

            let mut entries: *mut *mut FWPM_NET_EVENT0 = ptr::null_mut();
            let mut num_entries = 0u32;
            let code = FwpmNetEventEnum0(
                self.persistent_engine,
                enum_handle,
                64,
                &mut entries,
                &mut num_entries,
            );
            if code == 0 && !entries.is_null() {
                let slice = std::slice::from_raw_parts(entries, num_entries as usize);
                for &ev_ptr in slice {
                    if ev_ptr.is_null() {
                        continue;
                    }
                    let ev = &*ev_ptr;
                    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                        continue;
                    }
                    let drop_ptr = ev.Anonymous.classifyDrop;
                    if drop_ptr.is_null() {
                        continue;
                    }
                    let filter_id = (*drop_ptr).filterId;
                    if !self.persistent_filter_ids.contains(&filter_id) {
                        continue;
                    }

                    let app_blob = &ev.header.appId;
                    if app_blob.size < 4 || app_blob.data.is_null() {
                        continue;
                    }
                    let u16_len = (app_blob.size as usize) / 2;
                    let u16_slice =
                        std::slice::from_raw_parts(app_blob.data as *const u16, u16_len);
                    let raw_path = String::from_utf16_lossy(u16_slice)
                        .trim_end_matches('\0')
                        .to_string();
                    if raw_path.is_empty() || raw_path.eq_ignore_ascii_case("System") {
                        continue;
                    }

                    let remote_ip = if ev.header.ipVersion == FWP_IP_VERSION_V4 {
                        IpAddr::V4(Ipv4Addr::from(ev.header.Anonymous2.remoteAddrV4))
                    } else if ev.header.ipVersion == FWP_IP_VERSION_V6 {
                        IpAddr::V6(Ipv6Addr::from(
                            ev.header.Anonymous2.remoteAddrV6.byteArray16,
                        ))
                    } else {
                        continue;
                    };

                    let win32_path = nt_device_path_to_win32(&raw_path);
                    out.push((win32_path, remote_ip, ev.header.remotePort));
                }
                let mut raw = entries as *mut std::ffi::c_void;
                FwpmFreeMemory0(&mut raw);
            }

            let _ = FwpmNetEventDestroyEnumHandle0(self.persistent_engine, enum_handle);
        }
        out
    }

    fn add_filter(
        &self,
        engine: HANDLE,
        layer: GUID,
        name: &str,
        action_type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
        weight: u8,
        flags: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAGS,
        conditions: &[FWPM_FILTER_CONDITION0],
    ) -> Result<u64, String> {
        let mut wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(wide_name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            flags,
            providerKey: &CURB_PROVIDER_GUID as *const _ as *mut _,
            layerKey: layer,
            subLayerKey: CURB_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                ptr::null_mut()
            } else {
                conditions.as_ptr() as *mut _
            },
            action: FWPM_ACTION0 {
                r#type: action_type,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut filter_id = 0u64;
        let code = unsafe { FwpmFilterAdd0(engine, &filter, None, Some(&mut filter_id)) };
        if code != 0 {
            warn!("FwpmFilterAdd0({name}) failed with code 0x{code:08x}");
            return Err(format!("FwpmFilterAdd0 failed: 0x{code:08x}"));
        }
        Ok(filter_id)
    }
}

impl Drop for WfpController {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.dynamic_engine);
            let _ = FwpmEngineClose0(self.persistent_engine);
        }
    }
}

fn with_transaction<T, F>(engine: HANDLE, f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let mut begin_code = 0u32;
    for attempt in 0..5 {
        begin_code = unsafe { FwpmTransactionBegin0(engine, 0) };
        if begin_code == 0 {
            break;
        }
        if attempt < 4 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    if begin_code != 0 {
        return Err(format!("FwpmTransactionBegin0 failed: 0x{begin_code:08x}"));
    }

    match f() {
        Ok(val) => {
            let commit_code = unsafe { FwpmTransactionCommit0(engine) };
            if commit_code != 0 {
                unsafe {
                    let _ = FwpmTransactionAbort0(engine);
                }
                Err(format!("FwpmTransactionCommit0 failed: 0x{commit_code:08x}"))
            } else {
                Ok(val)
            }
        }
        Err(e) => {
            unsafe {
                let _ = FwpmTransactionAbort0(engine);
            }
            Err(e)
        }
    }
}

fn open_engine(dynamic: bool) -> Result<HANDLE, String> {
    let mut session = FWPM_SESSION0::default();
    if dynamic {
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    }
    let mut handle = HANDLE::default();
    let code = unsafe {
        FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_DEFAULT as u32,
            None,
            Some(&session),
            &mut handle,
        )
    };
    if code != 0 {
        return Err(format!("FwpmEngineOpen0 failed: 0x{code:08x}"));
    }
    Ok(handle)
}

fn get_app_id_blob(exe_path: &Path) -> Result<*mut FWP_BYTE_BLOB, String> {
    let wide: Vec<u16> = OsStr::new(exe_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
    let code = unsafe { FwpmGetAppIdFromFileName0(windows::core::PCWSTR(wide.as_ptr()), &mut blob) };
    if code != 0 || blob.is_null() {
        return Err(format!(
            "FwpmGetAppIdFromFileName0({}) failed: 0x{code:08x}",
            exe_path.display()
        ));
    }
    Ok(blob)
}

fn proto_condition(proto: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_PROTOCOL,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: proto },
        },
    }
}

fn remote_port_condition(port: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
        },
    }
}

/// Converts a lowercased NT device path (e.g. `\device\harddiskvolume3\windows\system32\curl.exe`)
/// returned by WFP `ALE_APP_ID` blobs into a Win32 drive path (`C:\windows\system32\curl.exe`).
fn nt_device_path_to_win32(nt_path: &str) -> String {
    let norm = nt_path.replace('/', "\\");
    if !norm.to_ascii_lowercase().starts_with("\\device\\") {
        return norm;
    }
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wide_drive: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut target_buf = [0u16; 260];
        let len = unsafe { QueryDosDeviceW(PCWSTR(wide_drive.as_ptr()), Some(&mut target_buf)) };
        if len == 0 {
            continue;
        }
        let target = String::from_utf16_lossy(&target_buf[..len as usize])
            .split('\0')
            .next()
            .unwrap_or("")
            .to_string();
        if target.is_empty() {
            continue;
        }
        let prefix = format!("{}\\", target.to_ascii_lowercase());
        if norm.to_ascii_lowercase().starts_with(&prefix) {
            let rest = &norm[target.len()..];
            return format!("{drive}{rest}");
        }
    }
    norm
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    #[test]
    fn wfp_dynamic_permit_filters_install_replace_and_remove_cleanly() {
        let ctrl = WfpController::open().expect("open WFP controller as Administrator");
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let target_exe = PathBuf::from(root).join("System32").join("notepad.exe");
        assert!(target_exe.exists(), "notepad.exe must exist on Windows");

        let policy = NetworkPolicy {
            allow_tcp: true,
            allow_udp: true,
            dns_whitelist: None,
        };

        // 1. Unrestricted dynamic app permit (IPv4 + IPv6, TCP + UDP = 4 filters)
        let ids = ctrl
            .replace_app_dynamic(&[], &target_exe, &policy, None, None)
            .expect("install unrestricted dynamic permit filters");
        assert_eq!(ids.len(), 4);

        // 2. Atomically replace with DNS-scoped IP filters (1 v4 + 1 v6, TCP + UDP = 4 filters)
        let scoped_ips = [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)),
        ];
        let replaced_ids = ctrl
            .replace_app_dynamic(&ids, &target_exe, &policy, Some(&scoped_ips), Some(443))
            .expect("atomically replace with IP+port scoped dynamic permit filters");
        assert_eq!(replaced_ids.len(), 4);

        // 3. DNS-scoped app without fixed port also receives 4 Media Router SSDP/mDNS filters
        let media_router_ids = ctrl
            .replace_app_dynamic(&replaced_ids, &target_exe, &policy, Some(&scoped_ips), None)
            .expect("atomically replace with DNS-scoped + Media Router dynamic permit filters");
        assert_eq!(media_router_ids.len(), 8);

        // 4. Clean removal
        ctrl.remove_dynamic_filters(&media_router_ids);
        drop(ctrl);
        let _ = curb_core::cleanup::purge_all_curb_wfp_objects();
    }
}
