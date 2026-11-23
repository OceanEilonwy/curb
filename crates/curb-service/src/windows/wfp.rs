use std::ffi::OsStr;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use curb_core::config::{BaselinePolicy, NetworkPolicy};
use tracing::{info, warn};
use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16,
    FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_UINT16, FWP_UINT32, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0,
};
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
    /// Opens persistent + dynamic WFP sessions and registers Curb's provider & sublayer.
    pub fn open() -> Result<Self, String> {
        let persistent_engine = open_engine(false)?;
        let dynamic_engine = open_engine(true)?;

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

    /// Atomically installs persistent default-deny filters across IPv4 and IPv6 plus
    /// the configured OS baseline rules (loopback, DHCP outbound + inbound replies,
    /// NTP, and Curb's own upstream DNS service).
    pub fn install_default_deny_and_baseline(
        &mut self,
        baseline: &BaselinePolicy,
        service_exe_path: Option<&Path>,
    ) -> Result<(), String> {
        let layers = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ];

        let mut new_persistent = Vec::new();
        let old_persistent: Vec<u64> = self.persistent_filter_ids.drain(..).collect();

        let tx_ok = with_transaction(self.persistent_engine, || {
            for id in &old_persistent {
                unsafe {
                    let _ = FwpmFilterDeleteById0(self.persistent_engine, *id);
                }
            }

            // 1. Default-deny catch-all (lowest weight = 1)
            for layer in layers {
                if let Ok(id) = self.add_filter(
                    self.persistent_engine,
                    layer,
                    "Curb Default Deny",
                    FWP_ACTION_BLOCK,
                    1,
                    FWPM_FILTER_FLAG_PERSISTENT,
                    &[],
                ) {
                    new_persistent.push(id);
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
                for layer in layers {
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

            // 3. DHCP baseline (outbound requests + inbound DHCPOFFER/DHCPACK replies)
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

                // Permit inbound DHCPv4 (UDP local port 68) & DHCPv6 (UDP local port 546)
                // responses so Wi-Fi/Ethernet lease acquisition and renewals are never dropped.
                for (layer, local_port) in [
                    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, 68u16),
                    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 546u16),
                ] {
                    let conds = [
                        proto_condition(IPPROTO_UDP),
                        local_port_condition(local_port),
                    ];
                    if let Ok(id) = self.add_filter(
                        self.persistent_engine,
                        layer,
                        "Curb Baseline DHCP Inbound",
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
                for layer in [
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                ] {
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

        // 5. Permit `curb-service.exe` itself to send upstream DNS (UDP/TCP 53),
        // atomically replacing any prior service DNS filter IDs.
        let old_svc_ids: Vec<u64> = self.service_dns_filter_ids.drain(..).collect();
        if let Some(svc_path) = service_exe_path {
            match self.replace_app_dynamic(
                &old_svc_ids,
                svc_path,
                &NetworkPolicy {
                    allow_tcp: true,
                    allow_udp: true,
                    dns_whitelist: None,
                },
                None,
                Some(53),
            ) {
                Ok(ids) => self.service_dns_filter_ids = ids,
                Err(e) => warn!("Failed to permit curb-service.exe upstream DNS in WFP: {e}"),
            }
        } else if !old_svc_ids.is_empty() {
            self.remove_dynamic_filters(&old_svc_ids);
        }

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
        let app_blob = get_app_id_blob(exe_path)?;
        let mut protos = Vec::new();
        if network.allow_tcp {
            protos.push(IPPROTO_TCP);
        }
        if network.allow_udp {
            protos.push(IPPROTO_UDP);
        }

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
                match allowed_ips {
                    None => {
                        let mut conds = vec![app_cond, proto_condition(proto)];
                        if let Some(port) = fixed_remote_port {
                            conds.push(remote_port_condition(port));
                        }
                        for layer in [
                            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        ] {
                            if let Ok(id) = self.add_filter(
                                self.dynamic_engine,
                                layer,
                                "Curb Dynamic App Allow",
                                FWP_ACTION_PERMIT,
                                20,
                                Default::default(),
                                &conds,
                            ) {
                                ids.push(id);
                            }
                        }

                        // For allowed apps with unrestricted UDP (e.g. WebRTC / voice calls /
                        // multiplayer games), also allow inbound UDP scoped strictly to this app.
                        if proto == IPPROTO_UDP && fixed_remote_port.is_none() {
                            for layer in [
                                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                            ] {
                                if let Ok(id) = self.add_filter(
                                    self.dynamic_engine,
                                    layer,
                                    "Curb Dynamic App UDP Recv Allow",
                                    FWP_ACTION_PERMIT,
                                    20,
                                    Default::default(),
                                    &conds,
                                ) {
                                    ids.push(id);
                                }
                            }
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
                                            Anonymous: FWP_CONDITION_VALUE0_0 { uint32: ip_u32 },
                                        },
                                    };
                                    let mut conds = vec![app_cond, proto_condition(proto), ip_cond];
                                    if let Some(port) = fixed_remote_port {
                                        conds.push(remote_port_condition(port));
                                    }
                                    if let Ok(id) = self.add_filter(
                                        self.dynamic_engine,
                                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                        "Curb Dynamic DNS-Scoped Allow v4",
                                        FWP_ACTION_PERMIT,
                                        20,
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
                                    let mut conds = vec![app_cond, proto_condition(proto), ip_cond];
                                    if let Some(port) = fixed_remote_port {
                                        conds.push(remote_port_condition(port));
                                    }
                                    if let Ok(id) = self.add_filter(
                                        self.dynamic_engine,
                                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                        "Curb Dynamic DNS-Scoped Allow v6",
                                        FWP_ACTION_PERMIT,
                                        20,
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
    let begin_code = unsafe { FwpmTransactionBegin0(engine, 0) };
    if begin_code != 0 {
        // Fallback without transaction if another transaction is active.
        return f();
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

fn local_port_condition(port: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_PORT,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
        },
    }
}
