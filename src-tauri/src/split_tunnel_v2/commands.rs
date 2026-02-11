//! Tauri command handlers for WFP-based split tunneling.
//!
//! These commands interface with the SplitTunnelManager to provide
//! app-based split tunneling via Windows Filtering Platform.

use crate::split_tunnel_v2::types::*;
use crate::split_tunnel_v2::SplitTunnelManager;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;

/// Wrapper for thread-safe access to SplitTunnelManager
pub struct WfpSplitTunnelState {
    pub manager: Arc<RwLock<Option<SplitTunnelManager>>>,
    config_dir: PathBuf,
}

impl WfpSplitTunnelState {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            manager: Arc::new(RwLock::new(None)),
            config_dir,
        }
    }

    pub async fn get_or_init(&self) -> Result<(), SplitTunnelError> {
        let mut lock = self.manager.write().await;
        if lock.is_none() {
            *lock = Some(SplitTunnelManager::new(self.config_dir.clone())?);
        }
        Ok(())
    }
}

// ─── Tauri Commands ─────────────────────────────────────────

/// Get the current split tunnel configuration
#[tauri::command]
pub async fn wfp_get_config(
    state: State<'_, WfpSplitTunnelState>,
) -> Result<SplitTunnelConfig, String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    Ok(manager.get_config())
}

/// Set the split tunnel mode (Disabled, Bypass, Proxy)
#[tauri::command]
pub async fn wfp_set_mode(
    mode: String,
    state: State<'_, WfpSplitTunnelState>,
) -> Result<(), String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let mode = match mode.to_lowercase().as_str() {
        "disabled" => SplitTunnelMode::Disabled,
        "bypass" => SplitTunnelMode::Bypass,
        "proxy" => SplitTunnelMode::Proxy,
        _ => return Err(format!("Invalid mode: {}", mode)),
    };
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.set_mode(mode).map_err(|e| e.to_string())
}

/// Add an application to the split tunnel rules
#[tauri::command]
pub async fn wfp_add_app(
    name: String,
    exe_path: String,
    state: State<'_, WfpSplitTunnelState>,
) -> Result<(), String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let rule = SplitRule::App(AppRule {
        name,
        exe_path: PathBuf::from(exe_path),
    });
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.add_rule(rule).map_err(|e| e.to_string())
}

/// Remove an application from the split tunnel rules
#[tauri::command]
pub async fn wfp_remove_app(
    exe_path: String,
    state: State<'_, WfpSplitTunnelState>,
) -> Result<(), String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    // Find and remove the matching rule
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    
    let config = manager.get_config();
    for rule in &config.rules {
        if let SplitRule::App(app) = rule {
            if app.exe_path.to_string_lossy() == exe_path {
                manager.remove_rule(rule).map_err(|e| e.to_string())?;
                return Ok(());
            }
        }
    }
    
    Err(format!("App not found: {}", exe_path))
}

/// Add a CIDR or IP address rule
#[tauri::command]
pub async fn wfp_add_ip_rule(
    cidr: String,
    state: State<'_, WfpSplitTunnelState>,
) -> Result<(), String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let rule = SplitRule::Cidr(cidr);
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.add_rule(rule).map_err(|e| e.to_string())
}

/// Add a domain rule
#[tauri::command]
pub async fn wfp_add_domain(
    domain: String,
    state: State<'_, WfpSplitTunnelState>,
) -> Result<(), String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let rule = SplitRule::Domain(domain);
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.add_rule(rule).map_err(|e| e.to_string())
}

/// Get the current split tunnel status
#[tauri::command]
pub async fn wfp_get_status(
    state: State<'_, WfpSplitTunnelState>,
) -> Result<SplitTunnelStatus, String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.get_status().map_err(|e| e.to_string())
}

/// Activate split tunneling (call after VPN connects)
#[tauri::command]
pub async fn wfp_activate(
    state: State<'_, WfpSplitTunnelState>,
) -> Result<SplitTunnelStatus, String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.activate().map_err(|e| e.to_string())
}

/// Deactivate split tunneling (call before/after VPN disconnects)
#[tauri::command]
pub async fn wfp_deactivate(
    state: State<'_, WfpSplitTunnelState>,
) -> Result<(), String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.deactivate().map_err(|e| e.to_string())
}

/// Get list of installed applications for the app picker
#[tauri::command]
pub async fn wfp_get_installed_apps(
    state: State<'_, WfpSplitTunnelState>,
) -> Result<Vec<InstalledApp>, String> {
    state.get_or_init().await.map_err(|e| e.to_string())?;
    
    let lock = state.manager.read().await;
    let manager = lock.as_ref().ok_or("Manager not initialized")?;
    manager.get_installed_apps().map_err(|e| e.to_string())
}
