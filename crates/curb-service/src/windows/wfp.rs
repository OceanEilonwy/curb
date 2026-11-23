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
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmSubLayerAdd0,
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT32, FWP_UINT8,
    FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB_TYPE, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_ACTION0, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_FLAGS_ALL_SET, FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

/// Stable Curb WFP Provider GUID.
pub const CURB_PROVIDER_GUID: GUID = GUID::from_u128(0x7c8e94b1_4412_4f68_a13b_2210c8894e01);

/// Stable Curb WFP Sublayer GUID (high weight so Curb rules take precedence).
pub const CURB_SUBLAYER_GUID: GUID = GUID::from_u128(0x7c8e94b1_4412_4f68_a13b_2210c8894e02);

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Manages both Curb's persistent default-deny WFP filters and its dynamic
/// per-session allow filters (`FWPM_SESSION_FLAG_DYNAMIC`).
pub struct WfpController {
    persistent_engine: HANDLE,
    dynamic_engine: HANDLE,
    persistent_filter_ids: Vec<u64>,
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

    /// Installs persistent default-deny filters across IPv4 and IPv6 plus the
    /// configured OS baseline rules (loopback, DHCP, NTP, and Curb's own DNS service).
    pub fn install_default_deny_and_baseline(
        &mut self,
        baseline: &BaselinePolicy,
        service_exe_path: Option<&Path>,
    ) -> Result<(), String> {
        self.clear_persistent_filters();

        let layers = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ];

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
                self.persistent_filter_ids.push(id);
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
                    self.persistent_filter_ids.push(id);
                }
            }
        }

        // 3. DHCP baseline (UDP ports 67, 68, 546, 547)
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
                    "Curb Baseline DHCP",
                    FWP_ACTION_PERMIT,
                    10,
                    FWPM_FILTER_FLAG_PERSISTENT,
                    &conds,
                ) {
                    self.persistent_filter_ids.push(id);
                }
            }
        }

        // 4. NTP baseline (UDP 123)
        if baseline.ntp {
            let conds = [proto_condition(IPPROTO_UDP), remote_port_condition(123)];
            for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
                if let Ok(id) = self.add_filter(
                    self.persistent_engine,
                    layer,
                    "Curb Baseline NTP",
                    FWP_ACTION_PERMIT,
                    10,
                    FWPM_FILTER_FLAG_PERSISTENT,
                    &conds,
                ) {
                    self.persistent_filter_ids.push(id);
                }
            }
        }

        // 5. Permit `curb-service.exe` itself to send upstream DNS (UDP/TCP 53)
        if let Some(svc_path) = service_exe_path {
            let _ = self.permit_app_dynamic(
                svc_path,
                &NetworkPolicy {
                    allow_tcp: true,
                    allow_udp: true,
                    dns_whitelist: None,
                },
                None,
                Some(53),
            );
        }

        info!(
            "Installed {} persistent WFP default-deny & baseline filters",
            self.persistent_filter_ids.len()
        );
        Ok(())
    }

    /// Inserts dynamic session-scoped `PERMIT` filters for a verified running executable.
    /// These filters vanish automatically if `curb-service` stops or crashes (fail-closed).
    pub fn permit_app_dynamic(
        &self,
        exe_path: &Path,
        network: &NetworkPolicy,
        allowed_ips: Option<&[IpAddr]>,
        fixed_remote_port: Option<u16>,
    ) -> Result<Vec<u64>, String> {
        let app_blob = get_app_id_blob(exe_path)?;
        let mut ids = Vec::new();

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
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: app_blob,
                },
            },
        };

        for proto in protos {
            match allowed_ips {
                None => {
                    let mut conds = vec![app_cond, proto_condition(proto)];
                    if let Some(port) = fixed_remote_port {
                        conds.push(remote_port_condition(port));
                    }
                    for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
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
                                let conds = [app_cond, proto_condition(proto), ip_cond];
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
                                let conds = [app_cond, proto_condition(proto), ip_cond];
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

        unsafe {
            let mut raw = app_blob as *mut std::ffi::c_void;
            FwpmFreeMemory0(&mut raw);
        }

        Ok(ids)
    }

    pub fn remove_dynamic_filters(&self, ids: &[u64]) {
        for &id in ids {
            unsafe {
                let _ = FwpmFilterDeleteById0(self.dynamic_engine, id);
            }
        }
    }

    pub fn clear_persistent_filters(&mut self) {
        for id in self.persistent_filter_ids.drain(..) {
            unsafe {
                let _ = FwpmFilterDeleteById0(self.persistent_engine, id);
            }
        }
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
