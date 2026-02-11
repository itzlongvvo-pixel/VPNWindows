//! WireGuard-NT native tunnel management
//! 
//! This module uses the wireguard-nt embeddable DLL to create and manage
//! WireGuard tunnels directly, bypassing the WireGuard Windows service.
//! This gives us full control over routing for split tunneling.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use ipnet::Ipv4Net;

/// Global tunnel state
static TUNNEL: Lazy<Arc<Mutex<Option<TunnelState>>>> = Lazy::new(|| Arc::new(Mutex::new(None)));
static WIREGUARD: Lazy<Arc<Mutex<Option<wireguard_nt::Wireguard>>>> = Lazy::new(|| Arc::new(Mutex::new(None)));

/// Represents an active WireGuard tunnel
struct TunnelState {
    adapter: wireguard_nt::Adapter,
    interface_name: String,
    local_ip: Ipv4Addr,
    dns: Ipv4Addr,
    server_ip: String,
}

/// WireGuard configuration parsed from .conf file
#[derive(Debug, Clone)]
pub struct WgConfig {
    pub private_key: [u8; 32],
    pub address: Ipv4Addr,
    pub address_prefix: u8,
    pub dns: Ipv4Addr,
    pub mtu: u16,
    pub peer_public_key: [u8; 32],
    pub peer_endpoint: SocketAddr,
    pub peer_allowed_ips: Vec<Ipv4Net>,
    pub persistent_keepalive: u16,
}

/// Decode base64 key to bytes
fn decode_key(b64: &str) -> Result<[u8; 32], String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let bytes = STANDARD.decode(b64.trim())
        .map_err(|e| format!("Invalid base64 key: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

impl WgConfig {
    /// Parse a WireGuard config file
    pub fn from_file(path: &PathBuf) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        
        let mut private_key_b64 = String::new();
        let mut address = Ipv4Addr::new(10, 66, 66, 2);
        let mut address_prefix = 24u8;
        let mut dns = Ipv4Addr::new(9, 9, 9, 9);
        let mut mtu = 1280u16;
        let mut peer_public_key_b64 = String::new();
        let mut peer_endpoint = "127.0.0.1:51820".parse::<SocketAddr>().unwrap();
        let mut peer_allowed_ips: Vec<Ipv4Net> = vec![];
        let mut persistent_keepalive = 25u16;
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            
            // Skip Table=off line (we handle routing ourselves)
            if line.to_lowercase().starts_with("table") {
                continue;
            }
            
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                
                match key {
                    "PrivateKey" => private_key_b64 = value.to_string(),
                    "Address" => {
                        // Parse Address = 10.66.66.2/24
                        if let Some((addr_str, prefix_str)) = value.split_once('/') {
                            if let Ok(ip) = addr_str.trim().parse::<Ipv4Addr>() {
                                address = ip;
                            }
                            if let Ok(p) = prefix_str.trim().split_whitespace().next().unwrap_or("24").parse::<u8>() {
                                address_prefix = p;
                            }
                        } else if let Ok(ip) = value.parse::<Ipv4Addr>() {
                            address = ip;
                        }
                    }
                    "DNS" => {
                        // Take first DNS if multiple
                        let first_dns = value.split(',').next().unwrap_or("9.9.9.9").trim();
                        if let Ok(ip) = first_dns.parse::<Ipv4Addr>() {
                            dns = ip;
                        }
                    }
                    "MTU" => {
                        if let Ok(m) = value.parse::<u16>() {
                            mtu = m;
                        }
                    }
                    "PublicKey" => peer_public_key_b64 = value.to_string(),
                    "Endpoint" => {
                        if let Ok(ep) = value.parse::<SocketAddr>() {
                            peer_endpoint = ep;
                        }
                    }
                    "AllowedIPs" => {
                        for ip_str in value.split(',') {
                            let ip_str = ip_str.trim();
                            // Skip IPv6
                            if ip_str.contains(':') {
                                continue;
                            }
                            if let Ok(net) = ip_str.parse::<Ipv4Net>() {
                                peer_allowed_ips.push(net);
                            }
                        }
                    }
                    "PersistentKeepalive" => {
                        if let Ok(k) = value.parse::<u16>() {
                            persistent_keepalive = k;
                        }
                    }
                    _ => {}
                }
            }
        }
        
        // Default to 0.0.0.0/0 if no allowed IPs
        if peer_allowed_ips.is_empty() {
            peer_allowed_ips.push("0.0.0.0/0".parse().unwrap());
        }
        
        let private_key = decode_key(&private_key_b64)?;
        let peer_public_key = decode_key(&peer_public_key_b64)?;
        
        Ok(Self {
            private_key,
            address,
            address_prefix,
            dns,
            mtu,
            peer_public_key,
            peer_endpoint,
            peer_allowed_ips,
            persistent_keepalive,
        })
    }
}

/// Get the path to the binaries directory
fn get_binaries_path() -> PathBuf {
    // Get exe directory
    let exe_dir = std::env::current_exe()
        .map(|p| p.parent().unwrap_or(&PathBuf::from(".")).to_path_buf())
        .unwrap_or_else(|_| PathBuf::from("."));
    
    // Development paths to try
    let dev_paths = [
        PathBuf::from("binaries"),
        PathBuf::from("src-tauri/binaries"),
        PathBuf::from(r"C:\Users\EllVo\.gemini\antigravity\scratch\nera-vpn-desktop-main\src-tauri\binaries"),
        exe_dir.join("binaries"),
        exe_dir.clone(),
    ];
    
    for path in &dev_paths {
        if path.join("wireguard.dll").exists() {
            log::info!("[WG-NT] Found binaries at: {:?}", path);
            return path.clone();
        }
    }
    
    // If not found, log and return first option (will fail with clear error)
    log::warn!("[WG-NT] wireguard.dll not found in any search path!");
    dev_paths[0].clone()
}

/// Start the WireGuard tunnel using wireguard-nt
pub fn start_tunnel(config: &WgConfig) -> Result<(), String> {
    log::info!("[WG-NT] Starting tunnel...");
    
    {
        let tunnel = TUNNEL.lock().unwrap();
        if tunnel.is_some() {
            return Err("Tunnel already running".to_string());
        }
    }
    
    // Load the wireguard.dll
    let dll_path = get_binaries_path().join("wireguard.dll");
    log::info!("[WG-NT] Loading DLL from: {:?}", dll_path);
    
    if !dll_path.exists() {
        return Err(format!("wireguard.dll not found at {:?}", dll_path));
    }
    
    // Load the DLL - unsafe because we're loading arbitrary code
    let wireguard = unsafe {
        wireguard_nt::load_from_path(&dll_path)
            .map_err(|e| format!("Failed to load wireguard.dll: {:?}", e))?
    };
    
    log::info!("[WG-NT] DLL loaded successfully");
    
    // Always create a fresh adapter to ensure new config is applied
    // First try to delete any existing adapter with this name
    let adapter_name = "NeraVPN";
    if let Ok(existing) = wireguard_nt::Adapter::open(&wireguard, adapter_name) {
        log::info!("[WG-NT] Deleting existing adapter to apply fresh config...");
        drop(existing);
        // Brief pause to let Windows clean up
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    
    log::info!("[WG-NT] Creating new adapter: {}", adapter_name);
    let adapter = wireguard_nt::Adapter::create(&wireguard, "WireGuard", adapter_name, None)
        .map_err(|e| format!("Failed to create adapter: {:?}", e))?;
    
    log::info!("[WG-NT] Adapter created: {}", adapter_name);
    
    // Build interface configuration
    let interface = wireguard_nt::SetInterface {
        listen_port: None, // Let OS pick a port
        public_key: None,  // Generated from private key
        private_key: Some(config.private_key),
        peers: vec![wireguard_nt::SetPeer {
            public_key: Some(config.peer_public_key),
            preshared_key: None,
            keep_alive: Some(config.persistent_keepalive),
            allowed_ips: config.peer_allowed_ips
                .iter()
                .map(|net| (*net).into())
                .collect(),
            endpoint: config.peer_endpoint,
        }],
    };
    
    // Apply configuration
    adapter.set_config(&interface)
        .map_err(|e| format!("Failed to set config: {:?}", e))?;
    
    log::info!("[WG-NT] Configuration applied");
    
    // CRITICAL: Add server exception route BEFORE VPN routes
    // This ensures traffic to the VPN server itself goes via physical gateway
    let server_ip = config.peer_endpoint.ip().to_string();
    add_server_exception_route(&server_ip)?;
    
    // Set up interface IP using wireguard-nt's helper
    let internal_ipnet = Ipv4Net::new(config.address, config.address_prefix)
        .map_err(|e| format!("Invalid IP/prefix: {}", e))?;
    
    // Let wireguard-nt try to set up the interface IP
    if let Err(e) = adapter.set_default_route(&[internal_ipnet.into()], &interface) {
        log::warn!("[WG-NT] set_default_route failed: {:?}, will configure manually", e);
    }
    
    // ALWAYS manually configure the interface IP (set_default_route may not work properly)
    configure_interface_ip(adapter_name, &config.address.to_string(), config.address_prefix)?;
    
    // Add VPN routes via WireGuard interface
    add_vpn_routes(adapter_name, &config.address.to_string())?;
    
    log::info!("[WG-NT] Routes configured for {}/{}", config.address, config.address_prefix);
    
    // Configure DNS using netsh
    configure_dns(adapter_name, config.dns)?;
    
    // Store state
    {
        let mut tunnel = TUNNEL.lock().unwrap();
        *tunnel = Some(TunnelState {
            adapter,
            interface_name: adapter_name.to_string(),
            local_ip: config.address,
            dns: config.dns,
            server_ip: server_ip.clone(),
        });
    }
    
    // Store wireguard reference
    {
        let mut wg = WIREGUARD.lock().unwrap();
        *wg = Some(wireguard);
    }
    
    log::info!("[WG-NT] Tunnel started successfully!");
    Ok(())
}

/// Stop the WireGuard tunnel
pub fn stop_tunnel() -> Result<(), String> {
    log::info!("[WG-NT] Stopping tunnel...");
    
    // Remove VPN routes first
    remove_vpn_routes();
    
    // Take and drop the tunnel (adapter closes on drop)
    {
        let mut tunnel = TUNNEL.lock().unwrap();
        if let Some(state) = tunnel.take() {
            // Remove server exception route
            remove_server_exception_route(&state.server_ip);
            
            log::info!("[WG-NT] Closing adapter: {}", state.interface_name);
            drop(state.adapter);
        }
    }
    
    // Clear wireguard reference
    {
        let mut wg = WIREGUARD.lock().unwrap();
        *wg = None;
    }
    
    log::info!("[WG-NT] Tunnel stopped");
    Ok(())
}

/// Check if tunnel is running
pub fn is_running() -> bool {
    TUNNEL.lock().unwrap().is_some()
}

/// Get the interface name if tunnel is running
pub fn get_interface_name() -> Option<String> {
    TUNNEL.lock().unwrap().as_ref().map(|t| t.interface_name.clone())
}

/// Add a route exception for the VPN server (must go via physical gateway)
fn add_server_exception_route(server_ip: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    // First detect the physical gateway
    let gateway = detect_physical_gateway()
        .ok_or("Could not detect physical gateway")?;
    
    log::info!("[WG-NT] Adding server exception route: {} via {}", server_ip, gateway);
    
    // Add route for VPN server via physical gateway
    let output = Command::new("route")
        .args(&["add", server_ip, "mask", "255.255.255.255", &gateway, "metric", "1"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to add server route: {}", e))?;
    
    if output.status.success() {
        log::info!("[WG-NT] Server exception route added successfully");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Route may already exist
        if !stderr.contains("already exists") {
            log::warn!("[WG-NT] Server route warning: {}", stderr);
        }
    }
    
    Ok(())
}

/// Remove server exception route
fn remove_server_exception_route(server_ip: &str) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    let _ = Command::new("route")
        .args(&["delete", server_ip])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    
    log::info!("[WG-NT] Server exception route removed: {}", server_ip);
}

/// Configure IP address on WireGuard interface using netsh
fn configure_interface_ip(_interface_name: &str, ip: &str, prefix_len: u8) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    // Windows registers the adapter as "WireGuard", not "NeraVPN"
    let windows_interface_name = "WireGuard";
    
    log::info!("[WG-NT] Configuring interface IP: {}/{} on {}", ip, prefix_len, windows_interface_name);
    
    // First, try to remove any existing IP
    let _ = Command::new("netsh")
        .args(&["interface", "ipv4", "delete", "address", windows_interface_name, ip])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    
    // Set the IP address using netsh
    let output = Command::new("netsh")
        .args(&[
            "interface", "ipv4", "add", "address",
            windows_interface_name, ip, &format!("255.255.255.0")  // /24 subnet mask
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to run netsh: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // If already exists, that's fine
        if !stderr.contains("already") && !stdout.contains("already") {
            log::warn!("[WG-NT] IP config warning: {} / {}", stdout.trim(), stderr.trim());
        }
    }
    
    log::info!("[WG-NT] Interface IP configured");
    Ok(())
}

/// Add VPN routes via WireGuard interface
fn add_vpn_routes(_interface_name: &str, _vpn_gateway: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    log::info!("[WG-NT] Adding VPN routes...");
    
    // Get the interface index for the WireGuard adapter
    // The adapter shows up as "WireGuard" in Windows, not "NeraVPN"
    let if_index = get_wireguard_interface_index()?;
    log::info!("[WG-NT] Found WireGuard interface index: {}", if_index);
    
    // Add routes using 'route add' with interface index
    // Routes: 0.0.0.0/1 and 128.0.0.0/1 (captures all traffic without overriding default route)
    for (dest, mask) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        // Delete existing route first (ignore errors)
        let _ = Command::new("route")
            .args(&["delete", dest, "mask", mask])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        
        // Add route via VPN interface
        let result = Command::new("route")
            .args(&[
                "add", dest, "mask", mask, "0.0.0.0", 
                "metric", "5", "if", &if_index.to_string()
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        
        match result {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                if out.status.success() || stdout.contains("OK") {
                    log::info!("[WG-NT] Added VPN route: {}/{}", dest, mask);
                } else {
                    log::warn!("[WG-NT] Route add warning: {} / {}", stdout.trim(), stderr.trim());
                }
            }
            Err(e) => {
                log::warn!("[WG-NT] Failed to add route: {}", e);
            }
        }
    }
    
    Ok(())
}

/// Get the interface index for the WireGuard adapter
pub fn get_wireguard_interface_index() -> Result<u32, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    // Retry a few times since interface may take a moment to register
    for attempt in 0..5 {
        if attempt > 0 {
            log::info!("[WG-NT] Waiting for interface to register (attempt {}/5)...", attempt + 1);
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        
        let output = Command::new("netsh")
            .args(&["interface", "ipv4", "show", "interfaces"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to query interfaces: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        log::debug!("[WG-NT] Interface list:\n{}", stdout);
        
        // Parse output to find WireGuard interface index
        // Format: "Idx     Met         MTU          State                Name"
        for line in stdout.lines() {
            // Check for WireGuard (default) or nera-token (service mode name)
            if line.contains("WireGuard") || line.contains("nera-token") {
                log::info!("[WG-NT] Found WireGuard interface line: {}", line.trim());
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx_str) = parts.first() {
                    if let Ok(idx) = idx_str.parse::<u32>() {
                        log::info!("[WG-NT] WireGuard interface index: {}", idx);
                        return Ok(idx);
                    }
                }
            }
        }
    }
    
    log::error!("[WG-NT] WireGuard interface not found after 5 attempts!");
    Err("WireGuard interface not found".to_string())
}

/// Remove VPN routes  
fn remove_vpn_routes() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    for (dest, mask) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        let _ = Command::new("route")
            .args(&["delete", dest, "mask", mask])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    log::info!("[WG-NT] VPN routes removed");
}

/// Configure DNS using netsh
fn configure_dns(_interface_name: &str, dns: Ipv4Addr) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    // Windows registers the adapter as "WireGuard", not "NeraVPN"
    let windows_interface_name = "WireGuard";
    
    let output = Command::new("netsh")
        .args(&[
            "interface", "ipv4", "set", "dnsservers",
            &format!("name=\"{}\"", windows_interface_name),
            "static",
            &dns.to_string(),
            "primary",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to set DNS: {}", e))?;
    
    if !output.status.success() {
        log::warn!("[WG-NT] DNS config warning: {}", String::from_utf8_lossy(&output.stderr));
    } else {
        log::info!("[WG-NT] DNS configured: {}", dns);
    }
    
    Ok(())
}

/// Add an exclusion route for split tunneling (traffic goes via physical gateway)
pub fn add_exclusion_route(network: Ipv4Addr, physical_gateway: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    let net_str = network.to_string();
    let output = Command::new("route")
        .args(&["add", &net_str, "mask", "255.255.255.0", physical_gateway, "metric", "1"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to add exclusion route: {}", e))?;
    
    if output.status.success() {
        log::info!("[WG-NT] Exclusion route added: {}/24 via {}", network, physical_gateway);
    }
    
    Ok(())
}

/// Remove an exclusion route
pub fn remove_exclusion_route(network: Ipv4Addr) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    let net_str = network.to_string();
    let _ = Command::new("route")
        .args(&["delete", &net_str])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    
    log::info!("[WG-NT] Exclusion route removed: {}/24", network);
    Ok(())
}

/// Detect the physical (non-VPN) gateway
pub fn detect_physical_gateway() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    let output = Command::new("route")
        .args(&["print", "0.0.0.0"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            let gateway = parts[2];
            // Skip VPN gateways (10.x.x.x) and on-link
            if gateway != "On-link" && !gateway.starts_with("10.") {
                return Some(gateway.to_string());
            }
        }
    }
    
    None
}
