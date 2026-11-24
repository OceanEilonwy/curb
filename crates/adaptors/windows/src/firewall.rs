use std::ptr;

use curb_core::adaptors::FirewallManager;
use curb_core::cleanup::{CURB_PROVIDER_UUID, CURB_SUBLAYER_UUID};
use curb_core::config::BaselinePolicy;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteById0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FwpmProviderDeleteByKey0,
    FwpmSubLayerDeleteByKey0, FWPM_FILTER0, FWPM_FILTER_ENUM_TEMPLATE0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

/// Windows Filtering Platform (WFP) cleanup & management adaptor.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsFirewallManager;

impl FirewallManager for WindowsFirewallManager {
    fn apply_enforcing(
        &self,
        _baseline: &BaselinePolicy,
        _dns_proxy_port: u16,
    ) -> Result<(), String> {
        Ok(())
    }

    fn purge_all(&self) -> Result<usize, String> {
        purge_all_curb_wfp_objects()
    }
}

/// Removes ALL WFP filters owned by Curb (including persistent default-deny filters),
/// plus Curb's WFP sublayer and provider.
pub fn purge_all_curb_wfp_objects() -> Result<usize, String> {
    let mut engine = HANDLE::default();
    let code = unsafe {
        FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_DEFAULT as u32,
            None,
            None,
            &mut engine,
        )
    };
    if code != 0 {
        return Err(format!("FwpmEngineOpen0 failed: 0x{code:08x}"));
    }

    let provider_guid = GUID::from_u128(CURB_PROVIDER_UUID);
    let sublayer_guid = GUID::from_u128(CURB_SUBLAYER_UUID);

    let template = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: &provider_guid as *const _ as *mut _,
        ..Default::default()
    };

    let mut enum_handle = HANDLE::default();
    let mut deleted = 0usize;

    let create_code =
        unsafe { FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle) };

    if create_code == 0 {
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut returned = 0u32;
            let enum_code = unsafe {
                FwpmFilterEnum0(engine, enum_handle, 256, &mut entries, &mut returned)
            };
            if enum_code != 0 || returned == 0 || entries.is_null() {
                break;
            }

            let slice = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
            for &filter_ptr in slice {
                if !filter_ptr.is_null() {
                    let filter_id = unsafe { (*filter_ptr).filterId };
                    if unsafe { FwpmFilterDeleteById0(engine, filter_id) } == 0 {
                        deleted += 1;
                    }
                }
            }

            unsafe {
                let mut raw = entries as *mut std::ffi::c_void;
                FwpmFreeMemory0(&mut raw);
            }

            if returned < 256 {
                break;
            }
        }

        unsafe {
            let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
        }
    }

    unsafe {
        let _ = FwpmSubLayerDeleteByKey0(engine, &sublayer_guid);
        let _ = FwpmProviderDeleteByKey0(engine, &provider_guid);
        let _ = FwpmEngineClose0(engine);
    }

    Ok(deleted)
}
