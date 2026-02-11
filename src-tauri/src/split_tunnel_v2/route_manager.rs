//! IP-based split tunneling via OS routing table manipulation.
//! Windows: uses `route add/delete` commands.

use crate::split_tunnel_v2::types::*;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::RwLock;
use tracing::{debug, error, info, warn};

/// LAN ranges that should always bypass the VPN when allow_lan is true
const LAN_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",  // link-local
    "224.0.0.0/4",     // multicast
    "255.255.255.255/32", // broadcast
];

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AppliedRoute {
    destination: String,
    mask: String,
    gateway: String,
    interface_index: u32,
    metric: u32,
}

pub struct RouteManager {
    /// Routes we've added — needed for cleanup
    applied_routes: RwLock<HashSet<AppliedRoute>>,
    /// The VPN tunnel interface index
    tunnel_iface_index: RwLock<Option<u32>>,
    /// The default gateway before VPN connected
    original_gateway: RwLock<Option<Ipv4Addr>>,
    /// Original default interface index
    original_iface_index: RwLock<Option<u32>>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self {
            applied_routes: RwLock::new(HashSet::new()),
            tunnel_iface_index: RwLock::new(None),
            original_gateway: RwLock::new(None),
            original_iface_index: RwLock::new(None),
        }
    }

    /// Snapshot the current default route before VPN changes it
    pub fn capture_original_route(&self) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let output = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | 
                   Sort-Object RouteMetric | 
                   Select-Object -First 1 | 
                   ConvertTo-Json"#
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| SplitTunnelError::RouteError(e.to_string()))?;

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| SplitTunnelError::RouteError(
                format!("Failed to parse route info: {e}")
            ))?;

        if let Some(gw) = json.get("NextHop").and_then(|v| v.as_str()) {
            let gateway: Ipv4Addr = gw.parse()
                .map_err(|e| SplitTunnelError::RouteError(format!("Bad gateway: {e}")))?;
            *self.original_gateway.write().unwrap() = Some(gateway);
            info!("Captured original gateway: {gateway}");
        }

        if let Some(idx) = json.get("InterfaceIndex").and_then(|v| v.as_u64()) {
            *self.original_iface_index.write().unwrap() = Some(idx as u32);
            info!("Captured original interface index: {idx}");
        }

        Ok(())
    }

    /// Set the WireGuard tunnel interface index
    pub fn set_tunnel_interface(&self, iface_index: u32) {
        *self.tunnel_iface_index.write().unwrap() = Some(iface_index);
        info!("Tunnel interface index set to {iface_index}");
    }

    /// Detect the WireGuard tunnel interface automatically
    pub fn detect_tunnel_interface(&self) -> Result<u32, SplitTunnelError> {
        // Reuse existing helper from wg_nt module
        crate::wg_nt::get_wireguard_interface_index()
            .map(|idx| {
                self.set_tunnel_interface(idx);
                idx
            })
            .map_err(|e| SplitTunnelError::RouteError(e))
    }

    // ─── Apply Split Tunnel Routes ──────────────────────────

    /// Apply IP-based split tunnel rules
    pub fn apply_ip_rules(
        &self,
        mode: &SplitTunnelMode,
        ip_ranges: &[IpNet],
        allow_lan: bool,
    ) -> Result<usize, SplitTunnelError> {
        let tunnel_idx = self.tunnel_iface_index.read().unwrap()
            .ok_or(SplitTunnelError::RouteError("Tunnel interface not set".into()))?;

        let orig_gateway = self.original_gateway.read().unwrap()
            .ok_or(SplitTunnelError::RouteError("Original gateway not captured".into()))?;

        let orig_iface = self.original_iface_index.read().unwrap()
            .ok_or(SplitTunnelError::RouteError("Original interface not captured".into()))?;

        let mut count = 0;

        match mode {
            SplitTunnelMode::Bypass => {
                // Default: everything through tunnel
                // Exception routes: listed IPs go through original gateway
                for range in ip_ranges {
                    self.add_bypass_route(range, &orig_gateway, orig_iface)?;
                    count += 1;
                }
            }
            SplitTunnelMode::Proxy => {
                // Default: everything through original gateway
                // Only listed IPs go through tunnel
                // First: remove the VPN's default route
                self.remove_tunnel_default_route(tunnel_idx)?;

                for range in ip_ranges {
                    self.add_proxy_route(range, tunnel_idx)?;
                    count += 1;
                }
            }
            SplitTunnelMode::Disabled => {
                return Ok(0);
            }
        }

        // Always allow LAN if configured
        if allow_lan && *mode != SplitTunnelMode::Disabled {
            self.apply_lan_bypass_routes(&orig_gateway, orig_iface)?;
        }

        info!("Applied {count} split tunnel route rules (mode: {mode:?})");
        Ok(count)
    }

    /// Route specific range OUTSIDE the tunnel (Bypass mode)
    fn add_bypass_route(
        &self,
        range: &IpNet,
        gateway: &Ipv4Addr,
        iface_index: u32,
    ) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let dest = range.addr().to_string();
        let mask = Self::prefix_to_mask(range.prefix_len());
        let gw = gateway.to_string();

        let route = AppliedRoute {
            destination: dest.clone(),
            mask: mask.clone(),
            gateway: gw.clone(),
            interface_index: iface_index,
            metric: 5,
        };

        let output = Command::new("route")
            .args([
                "add", &dest, "mask", &mask, &gw,
                "metric", "5",
                "if", &iface_index.to_string(),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| SplitTunnelError::RouteError(e.to_string()))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            // Route might already exist — try change instead
            let retry = Command::new("route")
                .args([
                    "change", &dest, "mask", &mask, &gw,
                    "metric", "5",
                    "if", &iface_index.to_string(),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| SplitTunnelError::RouteError(e.to_string()))?;

            if !retry.status.success() {
                warn!("Failed to add bypass route for {range}: {err}");
                return Err(SplitTunnelError::RouteError(
                    format!("route add failed for {range}: {err}")
                ));
            }
        }

        debug!("Added bypass route: {range} → gateway {gw}");
        self.applied_routes.write().unwrap().insert(route);
        Ok(())
    }

    /// Route specific range THROUGH the tunnel (Proxy mode)
    fn add_proxy_route(
        &self,
        range: &IpNet,
        tunnel_iface: u32,
    ) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let dest = range.addr().to_string();
        let mask = Self::prefix_to_mask(range.prefix_len());

        let route = AppliedRoute {
            destination: dest.clone(),
            mask: mask.clone(),
            gateway: "0.0.0.0".into(),
            interface_index: tunnel_iface,
            metric: 5,
        };

        let output = Command::new("route")
            .args([
                "add", &dest, "mask", &mask,
                "0.0.0.0",
                "metric", "5",
                "if", &tunnel_iface.to_string(),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| SplitTunnelError::RouteError(e.to_string()))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(SplitTunnelError::RouteError(
                format!("proxy route add failed for {range}: {err}")
            ));
        }

        debug!("Added proxy route: {range} → tunnel iface {tunnel_iface}");
        self.applied_routes.write().unwrap().insert(route);
        Ok(())
    }

    /// Remove the VPN's default catch-all route (for Proxy mode)
    fn remove_tunnel_default_route(&self, tunnel_iface: u32) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Remove 0.0.0.0/0 via tunnel — traffic defaults to original gateway
        let _ = Command::new("route")
            .args([
                "delete", "0.0.0.0", "mask", "0.0.0.0",
                "if", &tunnel_iface.to_string(),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        // Also remove the two /1 routes WireGuard commonly adds
        for dest in ["0.0.0.0", "128.0.0.0"] {
            let _ = Command::new("route")
                .args([
                    "delete", dest,
                    "if", &tunnel_iface.to_string(),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        }

        info!("Removed tunnel default routes for Proxy mode");
        Ok(())
    }

    /// Ensure LAN traffic always bypasses the tunnel
    fn apply_lan_bypass_routes(
        &self,
        gateway: &Ipv4Addr,
        iface_index: u32,
    ) -> Result<(), SplitTunnelError> {
        for range_str in LAN_RANGES {
            if let Ok(range) = range_str.parse::<IpNet>() {
                // Don't fail on individual LAN routes
                if let Err(e) = self.add_bypass_route(&range, gateway, iface_index) {
                    warn!("Failed to add LAN bypass for {range_str}: {e}");
                }
            }
        }
        info!("LAN bypass routes applied");
        Ok(())
    }

    // ─── Cleanup ────────────────────────────────────────────

    /// Remove ALL routes we added — called on disconnect or mode change
    pub fn remove_all_routes(&self) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let routes: Vec<AppliedRoute> = {
            let mut lock = self.applied_routes.write().unwrap();
            lock.drain().collect()
        };

        let total = routes.len();
        let mut failures = 0;

        for route in &routes {
            let output = Command::new("route")
                .args([
                    "delete",
                    &route.destination,
                    "mask", &route.mask,
                    &route.gateway,
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output();

            match output {
                Ok(o) if !o.status.success() => {
                    warn!("Failed to remove route: {} mask {}", route.destination, route.mask);
                    failures += 1;
                }
                Err(e) => {
                    error!("Route delete command failed: {e}");
                    failures += 1;
                }
                _ => {}
            }
        }

        if failures > 0 {
            warn!("Route cleanup: {failures}/{total} routes failed to remove");
        } else {
            info!("Route cleanup: all {total} routes removed successfully");
        }

        Ok(())
    }

    // ─── WireGuard Config Manipulation ─────────────────────

    /// Modify WireGuard config to add/remove `Table = off`
    /// When Table=off, WG won't add its own routes, letting us control routing manually
    pub fn modify_wg_config(&self, config_path: &std::path::Path, enable_table_off: bool) -> Result<(), SplitTunnelError> {
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| SplitTunnelError::RouteError(format!("Failed to read WG config: {e}")))?;

        let mut new_lines: Vec<String> = Vec::new();
        let mut in_interface = false;
        let mut table_added = false;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "[Interface]" {
                in_interface = true;
            } else if trimmed.starts_with('[') {
                in_interface = false;
            }

            // Skip existing Table line
            if trimmed.starts_with("Table") {
                continue;
            }

            new_lines.push(line.to_string());

            // Add Table=off right after [Interface]
            if in_interface && trimmed == "[Interface]" && enable_table_off && !table_added {
                new_lines.push("Table = off".to_string());
                table_added = true;
            }
        }

        let new_content = new_lines.join("\n");
        std::fs::write(config_path, &new_content)
            .map_err(|e| SplitTunnelError::RouteError(format!("Failed to write WG config: {e}")))?;

        if enable_table_off {
            info!("Added Table=off to WG config (manual routing mode)");
        } else {
            info!("Removed Table=off from WG config (normal routing mode)");
        }

        Ok(())
    }

    /// Restart the WireGuard tunnel service to apply config changes
    pub fn restart_tunnel(&self, config_path: &std::path::Path) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const WIREGUARD_EXE: &str = r"C:\Program Files\WireGuard\wireguard.exe";

        info!("Restarting WireGuard tunnel to apply split tunnel changes...");

        let service_name = config_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("nera-token");

        // Uninstall existing tunnel
        let _ = Command::new(WIREGUARD_EXE)
            .args(["/uninstalltunnelservice", service_name])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        // Wait for service removal
        std::thread::sleep(std::time::Duration::from_millis(3000));

        // Retry install up to 5 times
        let config_str = config_path.to_string_lossy().to_string();
        for attempt in 1..=5 {
            let install = Command::new(WIREGUARD_EXE)
                .args(["/installtunnelservice", &config_str])
                .creation_flags(CREATE_NO_WINDOW)
                .output();

            match install {
                Ok(out) if out.status.success() => {
                    info!("Tunnel restarted successfully on attempt {attempt}");
                    // Wait for tunnel to stabilize
                    std::thread::sleep(std::time::Duration::from_millis(2000));
                    return Ok(());
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    if stderr.contains("already") && attempt < 5 {
                        warn!("Tunnel still active (attempt {attempt}/5), waiting...");
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    } else if attempt == 5 {
                        return Err(SplitTunnelError::RouteError(
                            format!("Tunnel restart failed after 5 attempts: {stderr}")
                        ));
                    }
                }
                Err(e) => {
                    return Err(SplitTunnelError::RouteError(
                        format!("Failed to execute WireGuard: {e}")
                    ));
                }
            }
        }

        Ok(())
    }

    /// Add VPN default route manually (used when Table=off)
    pub fn add_vpn_default_route(&self, config_path: &std::path::Path) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Read VPN IP from config
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| SplitTunnelError::RouteError(format!("Failed to read config: {e}")))?;

        let mut vpn_ip = "10.66.66.2".to_string();
        for line in content.lines() {
            if line.trim().starts_with("Address") {
                if let Some(addr) = line.split('=').nth(1) {
                    vpn_ip = addr.trim().split('/').next().unwrap_or("10.66.66.2").to_string();
                }
            }
        }

        // Get WireGuard interface index
        let wg_if_idx = crate::wg_nt::get_wireguard_interface_index()
            .map_err(|e| SplitTunnelError::RouteError(format!("WG interface not found: {e}")))?;

        info!("Adding VPN default route via {vpn_ip} (IF {wg_if_idx}, metric 5)");

        // Add default route via WG interface with metric 5
        let result = Command::new("route")
            .args(["add", "0.0.0.0", "mask", "0.0.0.0", &vpn_ip, "metric", "5", "if", &wg_if_idx.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match result {
            Ok(out) if out.status.success() => {
                info!("VPN default route added successfully");
                let route = AppliedRoute {
                    destination: "0.0.0.0".into(),
                    mask: "0.0.0.0".into(),
                    gateway: vpn_ip,
                    interface_index: wg_if_idx,
                    metric: 5,
                };
                self.applied_routes.write().unwrap().insert(route);
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!("VPN route add result: {stderr}");
            }
            Err(e) => {
                warn!("Failed to add VPN route: {e}");
            }
        }

        // Store WG interface index
        self.set_tunnel_interface(wg_if_idx);

        Ok(())
    }

    /// Add an exclusion route for a /24 network via the physical gateway
    /// This makes traffic to that network bypass the VPN
    pub fn add_exclusion_route(&self, network: &Ipv4Addr, gateway: &str) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let net_str = network.to_string();
        let output = Command::new("route")
            .args(["add", &net_str, "mask", "255.255.255.0", gateway, "metric", "1"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| SplitTunnelError::RouteError(format!("Failed to add exclusion route: {e}")))?;

        if output.status.success() {
            info!("Added exclusion route: {net_str}/24 via {gateway} (metric 1)");
            let route = AppliedRoute {
                destination: net_str,
                mask: "255.255.255.0".into(),
                gateway: gateway.to_string(),
                interface_index: 0, // physical adapter
                metric: 1,
            };
            self.applied_routes.write().unwrap().insert(route);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Exclusion route add warning: {stderr}");
        }

        Ok(())
    }

    /// Remove an exclusion route
    pub fn remove_exclusion_route(&self, network: &Ipv4Addr) -> Result<(), SplitTunnelError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let net_str = network.to_string();
        let _ = Command::new("route")
            .args(["delete", &net_str])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        Ok(())
    }

    /// Detect the physical adapter's gateway (non-VPN)
    pub fn detect_physical_gateway(&self) -> Option<String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let output = Command::new("route")
            .args(["print", "0.0.0.0"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                    let gateway = parts[2];
                    // Skip VPN gateways (On-link or 10.66.x.x)
                    if gateway != "On-link" && !gateway.starts_with("10.66.") {
                        info!("Detected physical gateway: {gateway}");
                        return Some(gateway.to_string());
                    }
                }
            }
        }

        None
    }

    // ─── Utility ────────────────────────────────────────────

    fn prefix_to_mask(prefix: u8) -> String {
        if prefix == 0 {
            return "0.0.0.0".into();
        }
        let mask: u32 = !0u32 << (32 - prefix);
        format!(
            "{}.{}.{}.{}",
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF
        )
    }

    /// Verify a route actually exists in the routing table
    pub fn verify_route(&self, destination: &str) -> bool {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let output = Command::new("route")
            .args(["print", destination])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains(destination)
            }
            Err(_) => false,
        }
    }
}
