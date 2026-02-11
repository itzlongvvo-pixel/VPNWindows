//! App-based split tunneling via Windows Filtering Platform (WFP).
//!
//! WFP lets us intercept packets at the network layer and decide
//! routing based on the originating process (PID → exe path).
//!
//! Uses windows-sys for stable raw FFI bindings.

use crate::split_tunnel_v2::types::*;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const NERA_PROVIDER_NAME: &str = "Nera VPN Split Tunnel";
const NERA_SUBLAYER_WEIGHT: u16 = 0x8000;

// Error codes
const ERROR_SUCCESS: u32 = 0;
const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320002;

// FWP_ACTION_TYPE values (from fwpmtypes.h)
// FWP_ACTION_FLAG_TERMINATING = 0x00001000
// FWP_ACTION_PERMIT = 0x00001002 (0x1000 | 0x02)
const FWP_ACTION_PERMIT_VALUE: u32 = 0x00001002;

// Wrapper for GUID so it can be used as HashMap key
#[derive(Clone, Copy)]
struct GuidWrapper(GUID);

impl PartialEq for GuidWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.data1 == other.0.data1
            && self.0.data2 == other.0.data2
            && self.0.data3 == other.0.data3
            && self.0.data4 == other.0.data4
    }
}

impl Eq for GuidWrapper {}

impl std::hash::Hash for GuidWrapper {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.data1.hash(state);
        self.0.data2.hash(state);
        self.0.data3.hash(state);
        self.0.data4.hash(state);
    }
}

pub struct WfpManager {
    engine_handle: RwLock<HANDLE>,
    provider_guid: GUID,
    sublayer_guid: GUID,
    active_filters: RwLock<HashMap<GuidWrapper, PathBuf>>,
}

impl WfpManager {
    pub fn new() -> Self {
        Self {
            engine_handle: RwLock::new(0),
            provider_guid: Self::uuid_to_guid(Uuid::new_v4()),
            sublayer_guid: Self::uuid_to_guid(Uuid::new_v4()),
            active_filters: RwLock::new(HashMap::new()),
        }
    }

    /// Open a WFP engine session
    pub fn initialize(&self) -> Result<(), SplitTunnelError> {
        let mut session_name = Self::to_wide_string("Nera VPN Session");
        let mut session_desc = Self::to_wide_string("Split tunnel filter session");

        // Zero-initialize the session structure
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.displayData.name = session_name.as_mut_ptr();
        session.displayData.description = session_desc.as_mut_ptr();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        let mut handle: HANDLE = 0;

        let result = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut handle,
            )
        };

        if result != ERROR_SUCCESS {
            return Err(SplitTunnelError::WfpError(
                format!("FwpmEngineOpen0 failed: 0x{result:08X}")
            ));
        }

        info!("WFP engine opened successfully");
        *self.engine_handle.write().unwrap() = handle;

        self.register_provider()?;
        self.register_sublayer()?;

        Ok(())
    }

    fn register_provider(&self) -> Result<(), SplitTunnelError> {
        let handle = self.get_engine()?;

        let mut name = Self::to_wide_string(NERA_PROVIDER_NAME);
        let mut desc = Self::to_wide_string("Nera VPN split tunnel provider");

        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        provider.providerKey = self.provider_guid;
        provider.displayData.name = name.as_mut_ptr();
        provider.displayData.description = desc.as_mut_ptr();
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

        let result = unsafe { FwpmProviderAdd0(handle, &provider, ptr::null_mut()) };

        if result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS {
            return Err(SplitTunnelError::WfpError(
                format!("FwpmProviderAdd0 failed: 0x{result:08X}")
            ));
        }

        debug!("WFP provider registered");
        Ok(())
    }

    fn register_sublayer(&self) -> Result<(), SplitTunnelError> {
        let handle = self.get_engine()?;

        let mut name = Self::to_wide_string("Nera Split Tunnel Sublayer");
        let mut desc = Self::to_wide_string("Sublayer for app-based split tunnel filters");

        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = self.sublayer_guid;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.displayData.description = desc.as_mut_ptr();
        sublayer.providerKey = &self.provider_guid as *const GUID as *mut GUID;
        sublayer.weight = NERA_SUBLAYER_WEIGHT;

        let result = unsafe { FwpmSubLayerAdd0(handle, &sublayer, ptr::null_mut()) };

        if result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS {
            return Err(SplitTunnelError::WfpError(
                format!("FwpmSubLayerAdd0 failed: 0x{result:08X}")
            ));
        }

        debug!("WFP sublayer registered");
        Ok(())
    }

    /// Add a WFP filter that matches traffic from a specific application
    pub fn add_app_filter(
        &self,
        app_path: &PathBuf,
        _mode: &SplitTunnelMode,
    ) -> Result<GUID, SplitTunnelError> {
        let handle = self.get_engine()?;
        let filter_guid = Self::uuid_to_guid(Uuid::new_v4());

        // Get app ID blob from path
        let mut wide_path = Self::to_wide_string(&app_path.display().to_string());
        let mut blob_ptr: *mut FWP_BYTE_BLOB = ptr::null_mut();

        let result = unsafe {
            FwpmGetAppIdFromFileName0(wide_path.as_mut_ptr(), &mut blob_ptr)
        };

        if result != ERROR_SUCCESS || blob_ptr.is_null() {
            return Err(SplitTunnelError::WfpError(
                format!("FwpmGetAppIdFromFileName0 failed for {}: 0x{result:08X}", app_path.display())
            ));
        }

        let mut filter_name = Self::to_wide_string(&format!("Nera ST: {}", app_path.display()));
        let mut filter_desc = Self::to_wide_string("Split tunnel app filter");

        // Build condition - match app ID
        let mut condition: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        unsafe {
            condition.conditionValue.Anonymous.byteBlob = blob_ptr;
        }

        let mut conditions = [condition];

        // Build filter struct - zero-initialize first
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.filterKey = filter_guid;
        filter.displayData.name = filter_name.as_mut_ptr();
        filter.displayData.description = filter_desc.as_mut_ptr();
        filter.providerKey = &self.provider_guid as *const GUID as *mut GUID;
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey = self.sublayer_guid;
        filter.weight.r#type = FWP_UINT8;
        unsafe {
            filter.weight.Anonymous.uint8 = 10;
        }
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action.r#type = FWP_ACTION_PERMIT_VALUE;

        unsafe {
            let tx_result = FwpmTransactionBegin0(handle, 0);
            if tx_result != ERROR_SUCCESS {
                FwpmFreeMemory0(&mut (blob_ptr as *mut _));
                return Err(SplitTunnelError::WfpError(
                    format!("Transaction begin failed: 0x{tx_result:08X}")
                ));
            }

            let mut filter_id = 0u64;
            let add_result = FwpmFilterAdd0(handle, &filter, ptr::null_mut(), &mut filter_id);

            if add_result != ERROR_SUCCESS {
                let _ = FwpmTransactionAbort0(handle);
                FwpmFreeMemory0(&mut (blob_ptr as *mut _));
                return Err(SplitTunnelError::WfpError(
                    format!("FwpmFilterAdd0 failed: 0x{add_result:08X}")
                ));
            }

            let commit = FwpmTransactionCommit0(handle);
            FwpmFreeMemory0(&mut (blob_ptr as *mut _));

            if commit != ERROR_SUCCESS {
                return Err(SplitTunnelError::WfpError(
                    format!("Transaction commit failed: 0x{commit:08X}")
                ));
            }
        }

        info!("Added WFP app filter for: {}", app_path.display());
        self.active_filters.write().unwrap().insert(GuidWrapper(filter_guid), app_path.clone());

        Ok(filter_guid)
    }

    pub fn remove_app_filter(&self, filter_guid: &GUID) -> Result<(), SplitTunnelError> {
        let handle = self.get_engine()?;

        let result = unsafe { FwpmFilterDeleteByKey0(handle, filter_guid) };

        if result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND {
            return Err(SplitTunnelError::WfpError(
                format!("Filter delete failed: 0x{result:08X}")
            ));
        }

        self.active_filters.write().unwrap().remove(&GuidWrapper(*filter_guid));
        Ok(())
    }

    pub fn remove_all_filters(&self) -> Result<(), SplitTunnelError> {
        let filters: Vec<GUID> = {
            self.active_filters.read().unwrap().keys().map(|w| w.0).collect()
        };

        for guid in &filters {
            if let Err(e) = self.remove_app_filter(guid) {
                warn!("Failed to remove filter: {e}");
            }
        }

        info!("Removed all WFP app filters");
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), SplitTunnelError> {
        self.remove_all_filters()?;

        let handle = *self.engine_handle.read().unwrap();
        if handle != 0 {
            let result = unsafe { FwpmEngineClose0(handle) };
            if result != ERROR_SUCCESS {
                warn!("FwpmEngineClose0 returned: 0x{result:08X}");
            }
            *self.engine_handle.write().unwrap() = 0;
        }

        info!("WFP manager shut down");
        Ok(())
    }

    fn get_engine(&self) -> Result<HANDLE, SplitTunnelError> {
        let handle = *self.engine_handle.read().unwrap();
        if handle == 0 {
            Err(SplitTunnelError::WfpError("WFP engine not initialized".into()))
        } else {
            Ok(handle)
        }
    }

    fn uuid_to_guid(uuid: Uuid) -> GUID {
        let bytes = uuid.as_bytes();
        GUID {
            data1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_be_bytes([bytes[4], bytes[5]]),
            data3: u16::from_be_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ],
        }
    }

    fn to_wide_string(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }
}

impl Drop for WfpManager {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            error!("WFP shutdown error in drop: {e}");
        }
    }
}
