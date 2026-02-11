/*
  Nera VPN™ - Split Tunneling Module
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  
  This module implements application-based split tunneling by dynamically modifying
  the WireGuard AllowedIPs configuration.
*/

use std::collections::{HashSet, HashMap};
use std::sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use std::net::IpAddr;
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use sysinfo::{System, ProcessRefreshKind, RefreshKind, Pid, UpdateKind};
use windivert::prelude::*;
use ipnet::Ipv4Net;

// --- Constants ---

/// Delay before applying config changes (Debounce) - 15 seconds to reduce restart frequency
const IP_COLLECTION_WINDOW_MS: u64 = 15000;

// WireGuard executable path (standard install location)
const WIREGUARD_EXE: &str = r"C:\Program Files\WireGuard\wireguard.exe";

// --- Data Structures ---

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Manages excluded IPs via WireGuard AllowedIPs modification (Commercial-Grade Split Tunneling)
pub struct IpExclusionManager {
    /// Networks currently excluded from VPN tunnel
    excluded_networks: HashSet<std::net::Ipv4Addr>,
    /// Pending networks to be added on next commit
    pending_networks: HashSet<std::net::Ipv4Addr>,
    /// Time of last IP addition (for debouncing)
    last_update: Instant,
    /// Path to WireGuard config file
    pub config_path: PathBuf,
    /// Flag indicating if tunnel restart is needed
    needs_restart: bool,
}

/// Maximum number of /24 networks to exclude (keep low to avoid AllowedIPs explosion)
const MAX_EXCLUDED_NETWORKS: usize = 20;

impl IpExclusionManager {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            excluded_networks: HashSet::new(),
            pending_networks: HashSet::new(),
            last_update: Instant::now(),
            config_path,
            needs_restart: false,
        }
    }
    
    /// Convert IP to /24 network address
    fn ip_to_network(ip: std::net::Ipv4Addr) -> std::net::Ipv4Addr {
        let octets = ip.octets();
        std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 0)
    }
    
    /// Add an IP to exclusion list (converts to /24, returns true if new)
    pub fn add_ip(&mut self, ip: IpAddr) -> bool {
        if let IpAddr::V4(ipv4) = ip {
            // Skip special addresses
            if ipv4.is_loopback() || ipv4.is_private() || ipv4.is_multicast() {
                return false;
            }
            
            // Convert to /24 network
            let network = Self::ip_to_network(ipv4);
            
            // Check if already excluded or pending
            if self.excluded_networks.contains(&network) || self.pending_networks.contains(&network) {
                return false;
            }
            if self.excluded_networks.len() + self.pending_networks.len() >= MAX_EXCLUDED_NETWORKS {
                // At cap, don't add more
                return false;
            }
            
            if self.pending_networks.insert(network) {
                self.last_update = Instant::now();
                log_split(&format!("[SplitTunnel] New /24 network detected: {}/24 (from IP: {}) (pending: {})", 
                    network, ip, self.pending_networks.len()));
                return true;
            }
        }
        false
    }
    
    /// Check if we have pending networks that need to be applied
    pub fn has_pending(&self) -> bool {
        !self.pending_networks.is_empty()
    }
    
    /// Get count of pending networks
    pub fn pending_count(&self) -> usize {
        self.pending_networks.len()
    }

    /// Check if debounce window has passed
    pub fn can_commit(&self) -> bool {
         self.last_update.elapsed() > Duration::from_millis(IP_COLLECTION_WINDOW_MS)
    }
    
    /// Calculate AllowedIPs by excluding pending and existing networks from 0.0.0.0/0
    pub fn calculate_allowed_ips(&self) -> String {
        let all_excluded: HashSet<_> = self.excluded_networks.union(&self.pending_networks).collect();
        
        // If no exclusions, use full tunnel
        if all_excluded.is_empty() {
            return "0.0.0.0/0, ::/0".to_string();
        }
        
        // Start with 0.0.0.0/0 and subtract each /24 network
        let full_range = Ipv4Net::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 0).unwrap();
        let mut current_ranges = vec![full_range];
        
        for network in all_excluded {
            let exclude_net = Ipv4Net::new(*network, 24).unwrap();
            let mut new_ranges = Vec::new();
            
            for range in current_ranges {
                new_ranges.extend(subtract_network(range, exclude_net));
            }
            current_ranges = new_ranges;
        }
        
        // Format as comma-separated CIDR list
        let ipv4_list: Vec<String> = current_ranges.iter().map(|n| n.to_string()).collect();
        format!("{}, ::/0", ipv4_list.join(", "))
    }
    
    /// Update the WireGuard config file: Add Table=off and keep AllowedIPs=0.0.0.0/0
    /// Then we manually add/remove routes for excluded traffic
    fn update_config_for_split_tunnel(&self, enable: bool) -> Result<(), String> {
        // Read existing config
        let content = fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        
        let mut new_lines: Vec<String> = Vec::new();
        let mut in_interface = false;
        let mut table_added = false;
        
        for line in content.lines() {
            let trimmed = line.trim();
            
            // Track which section we're in
            if trimmed == "[Interface]" {
                in_interface = true;
            } else if trimmed.starts_with("[") {
                in_interface = false;
            }
            
            // Skip existing Table line (we'll add our own)
            if trimmed.starts_with("Table") {
                continue;
            }
            
            new_lines.push(line.to_string());
            
            // Add Table=off right after [Interface] when enabling split tunnel
            if in_interface && trimmed == "[Interface]" && enable && !table_added {
                new_lines.push("Table = off".to_string());
                table_added = true;
            }
        }
        
        let new_content = new_lines.join("\n");
        fs::write(&self.config_path, &new_content)
            .map_err(|e| format!("Failed to write config: {}", e))?;
        
        if enable {
            log_split("[SplitTunnel] Added Table=off to config (manual routing mode)");
        } else {
            log_split("[SplitTunnel] Removed Table=off from config (normal routing mode)");
        }
        
        Ok(())
    }
    
    /// Add manual routes for VPN traffic (when Table=off is set)
    fn add_vpn_routes(&self) -> Result<(), String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        // Get VPN interface IP first
        let content = fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        
        let mut vpn_ip = "10.66.66.2".to_string();
        for line in content.lines() {
            if line.trim().starts_with("Address") {
                if let Some(addr) = line.split('=').nth(1) {
                    vpn_ip = addr.trim().split('/').next().unwrap_or("10.66.66.2").to_string();
                }
            }
        }
        
        // Find WireGuard interface index using shared helper
        let wg_if_idx = crate::wg_nt::get_wireguard_interface_index()
            .map_err(|e| format!("WireGuard interface not found: {}", e))?;
            
        log_split(&format!("[SplitTunnel] Found WireGuard interface index: {}", wg_if_idx));
        
        // Add default route via WireGuard interface (low metric = high priority)
        // Note: Metric 5 is lower than typical interface metrics (25+), but higher than our specific exclusions (1)
        let result = Command::new("route")
            .args(&["add", "0.0.0.0", "mask", "0.0.0.0", &vpn_ip, "metric", "5", "if", &wg_if_idx.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        
        match result {
            Ok(out) if out.status.success() => {
                log_split(&format!("[SplitTunnel] Added VPN default route via {} (IF {})", vpn_ip, wg_if_idx));
            },
            Ok(out) => {
                // "The object already exists" is common and fine to ignore/log as warning
                log_split(&format!("[SplitTunnel] Route add result: {}", String::from_utf8_lossy(&out.stderr).trim()));
            },
            Err(e) => {
                log_split(&format!("[SplitTunnel] Failed to add VPN route: {}", e));
            }
        }
        Ok(())
    }
    
    /// Add exclusion route for a /24 network (goes via physical gateway)
    fn add_exclusion_route(&self, network: &std::net::Ipv4Addr, gateway: &str) -> Result<(), String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        let net_str = network.to_string();
        let output = Command::new("route")
            .args(&["add", &net_str, "mask", "255.255.255.0", gateway, "metric", "1"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to add route: {}", e))?;
        
        if output.status.success() {
            log_split(&format!("[SplitTunnel] Added exclusion route: {}/24 via {}", net_str, gateway));
        }
        Ok(())
    }
    
    /// Remove exclusion route
    fn remove_exclusion_route(&self, network: &std::net::Ipv4Addr) -> Result<(), String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        let net_str = network.to_string();
        let _ = Command::new("route")
            .args(&["delete", &net_str])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        
        Ok(())
    }
    
    /// Detect physical gateway
    fn detect_gateway(&self) -> Option<String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        let output = Command::new("route")
            .args(&["print", "0.0.0.0"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
            
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                    let gateway = parts[2];
                    if gateway != "On-link" && !gateway.starts_with("10.66.") {
                        log_split(&format!("[SplitTunnel] Detected physical gateway: {}", gateway));
                        return Some(gateway.to_string());
                    }
                }
            }
        }
        None
    }
    
    /// Restart the WireGuard tunnel to apply new AllowedIPs
    fn restart_tunnel(&self) -> Result<(), String> {
        log_split("[SplitTunnel] Restarting WireGuard tunnel to apply exclusions...");
        
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        // Get tunnel service name from config filename
        let service_name = self.config_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("nera-token");
        
        // Uninstall existing tunnel
        let uninstall = Command::new(WIREGUARD_EXE)
            .args(&["/uninstalltunnelservice", service_name])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to uninstall tunnel: {}", e))?;
        
        if !uninstall.status.success() {
            log_split(&format!("[SplitTunnel] Uninstall warning: {}", 
                String::from_utf8_lossy(&uninstall.stderr)));
        }
        
        // Wait for service to actually disappear
        // Poll every 500ms, up to 5 seconds
        let mut service_removed = false;
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(500));
            
            // Check if service still exists by trying to query it (sc query) logic
            // Or simpler: just proceed to install and handle "already exists" error?
            // "Tunnel already installed" error from WireGuard means the service name is still taken.
            // We can't easily check service existence without `sc` command or crates.
            // Let's rely on time + retry.
        }
        
        // Reinstall with updated config
        let config_str = self.config_path.to_string_lossy().to_string();
        
        // Retry install loop
        let mut install_result = Err("Initial attempt".to_string());
        for attempt in 1..=5 {
             let install = Command::new(WIREGUARD_EXE)
                .args(&["/installtunnelservice", &config_str])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
                
             match install {
                 Ok(out) => {
                     if out.status.success() {
                         install_result = Ok(());
                         break;
                     } else {
                         let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                         // If "already installed", wait and retry
                         if stderr.contains("already installed") || stderr.contains("already exist") {
                             log_split(&format!("[SplitTunnel] Tunnel still active (attempt {}/5), waiting...", attempt));
                             std::thread::sleep(Duration::from_millis(1000));
                             install_result = Err(stderr);
                         } else {
                             // Fatal error
                             install_result = Err(stderr);
                             break;
                         }
                     }
                 },
                 Err(e) => {
                     install_result = Err(e.to_string());
                     break; // Executing command failed, likely fatal
                 }
             }
        }
        
        if let Err(e) = install_result {
             return Err(format!("Tunnel restart failed after retries: {}", e));
        }
        
        log_split("[SplitTunnel] Tunnel restarted successfully with updated exclusions");
        Ok(())
    }
    
    /// Commit pending networks: Add routes for excluded traffic (NO TUNNEL RESTART!)
    pub fn commit_exclusions(&mut self) -> bool {
        if self.pending_networks.is_empty() {
            return false;
        }
        
        let pending_count = self.pending_networks.len();
        
        // Detect physical gateway first
        let gateway = match self.detect_gateway() {
            Some(gw) => gw,
            None => {
                log_split("[SplitTunnel] ERROR: Could not detect physical gateway");
                return false;
            }
        };
        
        // Collect pending networks first to avoid borrow issues
        let networks_to_add: Vec<_> = self.pending_networks.drain().collect();
        
        // Add routes for each pending network (via physical gateway, NOT VPN)
        for network in networks_to_add {
            if let Err(e) = self.add_exclusion_route(&network, &gateway) {
                log_split(&format!("[SplitTunnel] ERROR adding route: {}", e));
            }
            self.excluded_networks.insert(network);
        }
        
        self.last_update = Instant::now();
        
        log_split(&format!("[SplitTunnel] Applied {} new exclusions (Total: {} networks excluded)", 
            pending_count, self.excluded_networks.len()));
        log_split(&format!("[SplitTunnel] Excluded networks: {:?}", 
            self.excluded_networks.iter().map(|n| format!("{}/24", n)).collect::<Vec<_>>()));
            
        true
    }
    
    /// Reset to full tunnel (remove all exclusion routes)
    pub fn reset_to_full_tunnel(&mut self) -> Result<(), String> {
        if self.excluded_networks.is_empty() && self.pending_networks.is_empty() {
            return Ok(());
        }
        
        log_split("[SplitTunnel] Resetting to full tunnel mode (removing exclusion routes)...");
        
        // Collect networks first to avoid borrow issues
        let networks_to_remove: Vec<_> = self.excluded_networks.drain().collect();
        
        // Remove all exclusion routes
        for network in networks_to_remove {
            let _ = self.remove_exclusion_route(&network);
        }
        self.pending_networks.clear();
        
        log_split("[SplitTunnel] Full tunnel mode active - all traffic through VPN");
        Ok(())
    }
    
    /// Enable split tunnel mode: Add Table=off and restart tunnel
    pub fn enable_split_tunnel_mode(&mut self) -> Result<(), String> {
        log_split("[SplitTunnel] Enabling split tunnel mode (Table=off)...");
        
        // Update config to add Table=off
        self.update_config_for_split_tunnel(true)?;
        
        // Restart tunnel with new config
        self.restart_tunnel()?;
        
        // Wait for tunnel to stabilize
        std::thread::sleep(Duration::from_millis(2000));
        
        // Add VPN default route (since Table=off means WG won't add routes)
        self.add_vpn_routes()?;
        
        log_split("[SplitTunnel] Split tunnel mode enabled!");
        Ok(())
    }
    
    /// Disable split tunnel mode: Remove Table=off, cleanup routes, restart tunnel
    pub fn disable_split_tunnel_mode(&mut self) -> Result<(), String> {
        log_split("[SplitTunnel] Disabling split tunnel mode...");
        
        // Remove all exclusion routes
        self.reset_to_full_tunnel()?;
        
        // Update config to remove Table=off
        self.update_config_for_split_tunnel(false)?;
        
        // Restart tunnel with normal config (WG will add its own routes)
        self.restart_tunnel()?;
        
        log_split("[SplitTunnel] Split tunnel mode disabled!");
        Ok(())
    }
}

/// Subtract a /24 network from a larger network, returning the remaining ranges
fn subtract_network(parent: Ipv4Net, exclude: Ipv4Net) -> Vec<Ipv4Net> {
    if !parent.contains(&exclude.network()) {
        return vec![parent];
    }
    
    // If same size, nothing remains
    if parent.prefix_len() >= exclude.prefix_len() {
        return vec![];
    }
    
    let mut result = Vec::new();
    let mut current = parent;
    
    // Split down to the exclude size
    while current.prefix_len() < exclude.prefix_len() {
        if let Ok(mut subnets) = current.subnets(current.prefix_len() + 1) {
            let first = subnets.next().unwrap();
            let second = subnets.next().unwrap();
            
            if first.contains(&exclude.network()) {
                result.push(second);
                current = first;
            } else {
                result.push(first);
                current = second;
            }
        } else {
            break;
        }
    }
    
    result
}

/// Helper to subtract a single IP from a subnet
fn exclude_ip_from_subnet(subnet: Ipv4Net, ip: std::net::Ipv4Addr) -> Vec<Ipv4Net> {
    let mut result = Vec::new();
    let mut current = subnet;
    
    // While the subnet contains the IP and is larger than /32
    while current.contains(&ip) && current.prefix_len() < 32 {
        let subnets = current.subnets(current.prefix_len() + 1).unwrap();
        // One half contains the IP, the other doesn't.
        for sub in subnets {
            if sub.contains(&ip) {
                current = sub;
            } else {
                result.push(sub);
            }
        }
    }
    // At the end, current is /32 and equals the IP. We don't add it.
    result
}

// --- Main State ---

pub struct SplitTunnelState {
    // State for split tunneling
    enabled: Arc<AtomicBool>,
    excluded_apps: Arc<RwLock<Vec<String>>>,
    active_pids: Arc<RwLock<HashSet<u32>>>,
    
    // Thread control flags
    pid_watcher_flag: Arc<RwLock<Option<Arc<AtomicBool>>>>,
    
    // Flow tracking
    flow_table: Arc<RwLock<HashMap<FiveTuple, u32>>>,
    
    // IP Exclusion Manager
    exclusion_manager: Arc<RwLock<IpExclusionManager>>,
    

}

impl SplitTunnelState {
    pub fn new() -> Self {
        let config_path = dirs::document_dir()
            .unwrap_or(PathBuf::from("."))
            .join("NeraVPN")
            .join("nera-token.conf");

        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            excluded_apps: Arc::new(RwLock::new(Vec::new())),
            active_pids: Arc::new(RwLock::new(HashSet::new())),
            pid_watcher_flag: Arc::new(RwLock::new(None)),
            flow_table: Arc::new(RwLock::new(HashMap::new())),
            exclusion_manager: Arc::new(RwLock::new(IpExclusionManager::new(config_path))),

        }
    }
    

    
    /// Enable split tunneling
    pub fn start(&self) -> Result<(), String> {
        if self.enabled.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        // Verify admin rights
        if !is_admin() {
            return Err("Split tunneling requires Administrator privileges.".to_string());
        }
        
        // Verify WinDivert binaries exist
        self.verify_windivert_prerequisites()?;
        
        // Enable Table=off and restart tunnel
        {
            let mut manager = self.exclusion_manager.write().unwrap();
            if let Err(e) = manager.enable_split_tunnel_mode() {
                return Err(format!("Failed to enable split tunnel mode: {}", e));
            }
        }
        
        self.enabled.store(true, Ordering::Relaxed);
        
        // Start PID watcher thread
        self.start_pid_watcher()?;
        
        // Start FLOW layer tracker to monitor connections from excluded apps
        self.start_flow_tracker()?;
        
        log_split("Split tunneling started successfully (Table=off + Route mode)");
        Ok(())
    }
    
    /// Stop split tunneling (call when VPN disconnects)
    pub fn stop(&self) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        log_split("Stopping split tunneling...");
        self.enabled.store(false, Ordering::Relaxed);
        
        // Stop PID watcher
        if let Some(flag) = self.pid_watcher_flag.write().unwrap().take() {
            flag.store(false, Ordering::Relaxed);
        }
        
        // Disable split tunnel mode (remove Table=off, restart tunnel)
        {
            let mut manager = self.exclusion_manager.write().unwrap();
            if let Err(e) = manager.disable_split_tunnel_mode() {
                log_split(&format!("[SplitTunnel] Warning: Failed to disable split tunnel mode: {}", e));
            }
        }
        
        log_split("Split tunneling stopped");
    }
    
    /// Update list of excluded applications
    pub fn set_excluded_apps(&self, apps: Vec<String>) {
        *self.excluded_apps.write().unwrap() = apps;
        log_split("Updated exclusion list");
    }
    
    /// Legacy/Alias methods for main.rs compatibility
    pub fn get_apps(&self) -> Vec<String> {
        self.excluded_apps.read().unwrap().clone()
    }
    
    pub fn set_apps(&self, apps: Vec<String>) {
        self.set_excluded_apps(apps);
    }
    
    // --- Internal Helpers ---
    
    fn verify_windivert_prerequisites(&self) -> Result<(), String> {
        let exe_dir = std::env::current_exe()
            .map(|p| p.parent().unwrap_or(&PathBuf::from(".")).to_path_buf())
            .unwrap_or_else(|_| PathBuf::from("."));
            
        let driver = exe_dir.join("WinDivert64.sys");
        let dll = exe_dir.join("WinDivert.dll");
        
        if !driver.exists() {
            // Try development path
             let dev_path = PathBuf::from(r"C:\Users\EllVo\.gemini\antigravity\scratch\nera-vpn-desktop-main\src-tauri\binaries\WinDivert64.sys");
             if !dev_path.exists() {
                 return Err("WinDivert64.sys not found. Split tunneling requires this driver.".to_string());
             }
        }
        
        if !dll.exists() {
             let dev_path = PathBuf::from(r"C:\Users\EllVo\.gemini\antigravity\scratch\nera-vpn-desktop-main\src-tauri\binaries\WinDivert.dll");
             if !dev_path.exists() {
                return Err("WinDivert.dll not found. Split tunneling requires this library.".to_string());
             }
        }
        
        Ok(())
    }

    fn start_pid_watcher(&self) -> Result<(), String> {
        let flag = Arc::new(AtomicBool::new(true));
        *self.pid_watcher_flag.write().unwrap() = Some(flag.clone());
        
        let excluded_apps = self.excluded_apps.clone();
        let active_pids = self.active_pids.clone();
        
        thread::spawn(move || {
            log_split("PID watcher thread started");
            let mut system = System::new();
            
            while flag.load(Ordering::Relaxed) {
                // Refresh processes with exe path info - CRITICAL: must include exe!
                system.refresh_processes_specifics(
                    ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet)
                );
                
                let apps = excluded_apps.read().unwrap().clone();
                if apps.is_empty() {
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                
                // Debug: Log configured apps once per minute
                static DEBUG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let count = DEBUG_COUNTER.fetch_add(1, Ordering::Relaxed);
                if count % 30 == 0 { // Every ~60 seconds (2s sleep * 30)
                    log_split(&format!("[DEBUG] Configured excluded apps: {:?}", apps));
                }
                
                let mut current_pids = HashSet::new();
                
                for (pid, process) in system.processes() {
                    // Skip system processes (PID <= 4)
                    if pid.as_u32() <= 4 { continue; }

                    if let Some(exe_path) = process.exe() {
                        let path_str = exe_path.to_string_lossy().to_lowercase();
                        // Require minimum path length to avoid false matches
                        if path_str.len() < 5 { continue; }
                        
                        // Debug: Log if we find anything with "brave" in the path
                        if path_str.contains("brave") {
                            static BRAVE_FOUND_LOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                            if !BRAVE_FOUND_LOG.swap(true, Ordering::Relaxed) {
                                log_split(&format!("[DEBUG] Found Brave process: PID={} path={}", pid.as_u32(), path_str));
                                log_split(&format!("[DEBUG] Comparing against configured: {:?}", apps));
                            }
                        }

                        // Check if any excluded app path is contained within this process path
                        let is_excluded = apps.iter().any(|app_path| {
                            let app_lower = app_path.to_lowercase();
                            !app_lower.is_empty() && path_str.contains(&app_lower)
                        });
                        
                        if is_excluded {
                            current_pids.insert(pid.as_u32());
                            // Debug: Log first match for this PID
                            static FIRST_MATCH_LOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                            if !FIRST_MATCH_LOG.swap(true, Ordering::Relaxed) {
                                log_split(&format!("[DEBUG] First PID match: {} at path: {}", pid.as_u32(), path_str));
                            }
                        }
                    }
                }
                
                // Update shared state
                {
                    let mut pids = active_pids.write().unwrap();
                    let old_count = pids.len();
                    *pids = current_pids.clone();
                    if pids.len() != old_count {
                        log_split(&format!("Active excluded PIDs: {} -> {}", old_count, pids.len()));
                    }
                    // Debug: Log matched PIDs periodically
                    if count % 30 == 0 && !pids.is_empty() {
                        log_split(&format!("[DEBUG] Currently tracked {} PIDs: {:?}", pids.len(), pids.iter().take(5).collect::<Vec<_>>()));
                    }
                }
                
                thread::sleep(Duration::from_secs(2));
            }
            log_split("PID watcher thread stopped");
        });
        
        Ok(())
    }
    
    fn start_flow_tracker(&self) -> Result<(), String> {
        let active_pids = self.active_pids.clone();
        let flow_table = self.flow_table.clone();
        let exclusion_manager = self.exclusion_manager.clone();
        let enabled = self.enabled.clone();
        let excluded_apps = self.excluded_apps.clone();

        thread::spawn(move || {
            log_split("FLOW layer tracker thread started");

            // FLOW layer filter: capture all flow events
            let filter = "true";
            let flags = WinDivertFlags::new().set_sniff().set_recv_only();
            
            match WinDivert::flow(filter, 0, flags) {
                Ok(handle) => {
                    log_split("WinDivert FLOW handle opened successfully");
                    
                    while enabled.load(Ordering::Relaxed) {
                        // Check if we need to apply updates (Debounce logic)
                        {
                            let mut manager = exclusion_manager.write().unwrap();
                            if manager.has_pending() && manager.can_commit() {
                                log_split(&format!("[SplitTunnel] Debounce window elapsed! Applying {} pending exclusions...", manager.pending_count()));
                                manager.commit_exclusions();
                            }
                        }

                        // Use a short timeout so we keep checking debounce
                        // FLOW handle doesn't support timeout natively in basic recv, but we can poll?
                        // Actually, WinDivert recv blocks. If no traffic, we won't update debounce.
                        // THIS IS A PROBLEM. We need to unblock or use a separate timer thread.
                        // For Phase 1, we assume there IS traffic (user browsing), so recv will return frequently.
                        // Or we can rely on a separate thread to trigger the update?
                        // Let's stick to this for now, but be aware if traffic stops, update might be delayed until next packet.
                        // Since we are capturing "true", ALL network traffic events will wake us up, which is frequent enough.
                        
                        match handle.recv(None) {
                            Ok(packet) => {
                                let flow_addr = &packet.address;
                                let event = flow_addr.event();
                                
                                let tuple = FiveTuple {
                                    src_ip: flow_addr.local_address(),
                                    dst_ip: flow_addr.remote_address(),
                                    src_port: flow_addr.local_port(),
                                    dst_port: flow_addr.remote_port(),
                                    protocol: flow_addr.protocol(),
                                };
                                
                                match event {
                                    WinDivertEvent::FlowStablished => {
                                        let pid = flow_addr.process_id();
                                        flow_table.write().unwrap().insert(tuple.clone(), pid);
                                        
                                        // Debug: Log flow events periodically
                                        static FLOW_DEBUG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                        let flow_count = FLOW_DEBUG.fetch_add(1, Ordering::Relaxed);
                                        if flow_count % 100 == 0 {
                                            log_split(&format!("[DEBUG] Flow #{}: PID={} -> {}", flow_count, pid, tuple.dst_ip));
                                        }
                                        
                                        // Check if process is excluded
                                        // 1. Check known active PIDs
                                        let is_in_active = active_pids.read().unwrap().contains(&pid);
                                        let mut is_excluded = is_in_active;
                                        
                                        // 2. Fallback check
                                        if !is_excluded {
                                            let apps = excluded_apps.read().unwrap();
                                             if !apps.is_empty() {
                                                 if let Ok(pid_path) = get_process_path(pid) {
                                                     let matched = apps.iter().any(|app| pid_path.to_lowercase().contains(&app.to_lowercase()));
                                                     if matched {
                                                         active_pids.write().unwrap().insert(pid);
                                                         is_excluded = true;
                                                         log_split(&format!("[DEBUG] Matched PID {} at path: {}", pid, pid_path));
                                                     }
                                                 }
                                             }
                                        }

                                        if is_excluded && enabled.load(Ordering::Relaxed) {
                                            // Add IP to exclusion manager (only if still enabled)
                                            let mut manager = exclusion_manager.write().unwrap();
                                            if manager.add_ip(tuple.dst_ip) {
                                                log_split(&format!("New excluded IP detected: {} (PID: {})", tuple.dst_ip, pid));
                                            }
                                        }
                                    }
                                    WinDivertEvent::FlowDeleted => {
                                        flow_table.write().unwrap().remove(&tuple);
                                    }
                                    _ => {}
                                }
                            }
                            Err(e) => {
                                // If error is not NoData, log it
                                // WinDivert recv blocks, implies NoData shouldn't happen unless we used async/poll.
                                log_split(&format!("Error receiving FLOW event: {:?}", e));
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                }
                Err(e) => {
                    log_split(&format!("Failed to open WinDivert FLOW handle: {}", e));
                }
            }
            log_split("FLOW layer tracker thread stopped");
            
            // Note: DO NOT reset tunnel here - stop() already handles this
            // Having both causes a race condition where two resets happen simultaneously
        });
        
        Ok(())
    }
}

// Obsolete helpers (restart_vpn_service, etc) removed


/// Check if running as Administrator (Windows)
#[cfg(windows)]
fn is_admin() -> bool {
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
fn is_admin() -> bool {
    true
}

fn get_process_path(pid: u32) -> Result<String, String> {
    let mut system = System::new();
    // Must include exe in refresh kind!
    system.refresh_process_specifics(
        Pid::from_u32(pid), 
        ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet)
    );
    if let Some(process) = system.process(Pid::from_u32(pid)) {
        if let Some(exe_path) = process.exe() {
            return Ok(exe_path.to_string_lossy().to_string());
        }
    }
    Err("Process not found".to_string())
}

/// Helper to log to file (and console)
fn log_split(message: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_msg = format!("[{}] {}", timestamp, message);
    println!("[Split Tunnel] {}", message);
    
    // Log to file
    if let Some(mut path) = dirs::document_dir() {
        path.push("NeraVPN");
        if !path.exists() {
            let _ = std::fs::create_dir_all(&path);
        }
        path.push("split_tunnel.log");
        
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{}", log_msg);
        }
    }
}
