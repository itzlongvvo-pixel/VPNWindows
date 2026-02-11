/*
  Nera VPN™ - Token-Based VPN Connection
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  
  This module handles the token-authenticated VPN connection flow:
  1. Exchange access_token for WireGuard credentials via API
  2. Generate WireGuard config dynamically
  3. Start the WireGuard tunnel service
*/

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::os::windows::process::CommandExt;
use tauri::{AppHandle, Emitter, Manager, State};

// --- Windows API Imports ---
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute, MIB_IPFORWARDROW};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{SOCKADDR_IN, AF_INET};
#[cfg(windows)]
use std::ffi::CString;

// Native WireGuard executable path
const WIREGUARD_EXE: &str = r"C:\Program Files\WireGuard\wireguard.exe";
const API_BASE: &str = "http://45.76.106.63:3000/api";

// --- Request/Response Structs ---

#[derive(Serialize)]
struct AuthPayload {
    server_id: String,
    access_token: String,
}

#[derive(Deserialize, Clone)]
pub struct VpnCredentials {
    pub private_key: String,
    pub address: String,
    pub dns: String,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    pub allowed_ips: String,
}

/// Payload for vpn-status-changed event
#[derive(Clone, Serialize)]
pub struct VpnStatusPayload {
    pub connected: bool,
}

// --- Helper Functions ---

fn vpn_conf_path() -> Result<PathBuf, String> {
    let mut dir = dirs::document_dir()
        .ok_or_else(|| "Could not find Documents folder.".to_string())?;
    dir.push("NeraVPN");
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create VPN config directory: {e}"))?;
    }
    dir.push("nera-token.conf");
    Ok(dir)
}

fn generate_wireguard_config(creds: &VpnCredentials, split_tunnel_enabled: bool) -> String {
    // Strip /32 from address if it's already there
    let address = creds.address.trim_end_matches("/32");
    
    let table_line = if split_tunnel_enabled {
        log_vpn("[SplitTunnel] Adding Table=off to WireGuard config (manual routing mode)");
        "Table = off\n"
    } else {
        ""
    };
    
    format!(
        "[Interface]\n\
         {}PrivateKey = {}\n\
         Address = {}/24\n\
         DNS = 9.9.9.9\n\
         MTU = 1280\n\
         \n\
         [Peer]\n\
         PublicKey = {}\n\
         Endpoint = {}\n\
         AllowedIPs = 0.0.0.0/0\n\
         PersistentKeepalive = 25\n",
        table_line,
        creds.private_key,
        address,
        creds.peer_public_key,
        creds.peer_endpoint
    )
}

/// Feature flag: Use wireguard-nt embeddable DLL instead of WireGuard service
/// Set to true for proper split tunneling support
const USE_WG_NT: bool = false; // Changed to false to use WireGuard.exe service (wg-nt handshake failing)

fn start_wireguard_tunnel(config_path: &PathBuf, _address_cidr: &str) -> Result<(), String> {
    if USE_WG_NT {
        start_wireguard_tunnel_nt(config_path)
    } else {
        start_wireguard_tunnel_service(config_path)
    }
}

/// Start tunnel using wireguard-nt embeddable DLL (for split tunneling)
fn start_wireguard_tunnel_nt(config_path: &PathBuf) -> Result<(), String> {
    log_vpn("Starting WireGuard tunnel via wireguard-nt...");
    
    // Stop any existing tunnel first
    if crate::wg_nt::is_running() {
        log_vpn("Stopping existing wg_nt tunnel...");
        crate::wg_nt::stop_tunnel()?;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    
    // Also stop any legacy WireGuard service
    let service_name = config_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("nera-token");
    
    let _ = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        .arg(service_name)
        .creation_flags(0x08000000)
        .output();
    
    std::thread::sleep(std::time::Duration::from_millis(300));
    
    // Parse config and start tunnel
    let config = crate::wg_nt::WgConfig::from_file(config_path)?;
    crate::wg_nt::start_tunnel(&config)?;
    
    log_vpn("Tunnel started via wireguard-nt!");
    Ok(())
}

/// Start tunnel using WireGuard Windows service (legacy)
fn start_wireguard_tunnel_service(config_path: &PathBuf) -> Result<(), String> {
    log_vpn("Starting WireGuard tunnel via native service...");
    
    // First, try to uninstall any existing tunnel with the same name
    let service_name = config_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("nera-token");
    
    log_vpn(&format!("Cleaning up existing tunnel: {}", service_name));
    let _ = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        .arg(service_name)
        .creation_flags(0x08000000)
        .output();
    
    // Brief pause to let service cleanup complete
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    // Install the new tunnel service
    log_vpn(&format!("Installing tunnel service from: {:?}", config_path));
    let status = Command::new(WIREGUARD_EXE)
        .arg("/installtunnelservice")
        .arg(config_path)
        .creation_flags(0x08000000)
        .status()
        .map_err(|e| format!("Failed to start WireGuard: {}", e))?;
    
    if !status.success() {
        return Err(format!("WireGuard exited with status: {}", status));
    }
    
    log_vpn("Tunnel service installed successfully!");
    Ok(())
}


fn get_best_route(dest_ip_str: &str) -> Option<(String, u32)> {
    #[cfg(windows)]
    unsafe {
        use std::net::Ipv4Addr;
        
        let dest_ip: Ipv4Addr = dest_ip_str.parse().ok()?;
        let dest_addr_int: u32 = std::mem::transmute::<[u8; 4], u32>(dest_ip.octets());
        
        let mut row: MIB_IPFORWARDROW = std::mem::zeroed();
        let result = GetBestRoute(dest_addr_int, 0, &mut row);
        
        if result == 0 {
            // Success
            // Gateway IP is in row.dwForwardNextHop
            let gateway_int = row.dwForwardNextHop;
            let gateway_bytes: [u8; 4] = std::mem::transmute(gateway_int);
            let gateway_ip = Ipv4Addr::from(gateway_bytes).to_string();
            let if_index = row.dwForwardIfIndex;
            
            return Some((gateway_ip, if_index));
        } else {
             log_vpn(&format!("GetBestRoute failed with error: {}", result));
        }
    }
    None
}

fn add_server_exception_route(server_ip: &str) -> Result<(), String> {
    log_vpn(&format!("Attempting to add exception route for server: {}", server_ip));
    
    // 1. Get the physical gateway for this destination *before* we mess with routes
    let (gateway_ip, if_index) = get_best_route(server_ip)
        .ok_or_else(|| "Failed to determine best route to server".to_string())?;
        
    log_vpn(&format!("Detected physical gateway: {} on Interface Index: {}", gateway_ip, if_index));
    
    // 2. Delete any existing route to this server first
    let _ = Command::new("route")
        .args(&["delete", server_ip])
        .creation_flags(0x08000000)
        .output();
    
    // 3. Add the specific host route with PERSISTENCE
    // -p makes it survive reboots and interface changes
    // metric 1 is minimum on Windows (0 is rejected)
    let output = Command::new("route")
        .args(&[
            "-p",           // PERSISTENT
            "add", 
            server_ip, 
            "mask", "255.255.255.255", 
            &gateway_ip, 
            "metric", "1",  // Metric 1 (Windows minimum)
            "if", &if_index.to_string()
        ])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("Failed to execute route command: {}", e))?;
        
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "The object already exists" is fine
        if !stderr.contains("already exists") {
             return Err(format!("Route add failed: {}", stderr));
        } else {
             log_vpn("Route already exists, skipping.");
        }
    } else {
        log_vpn("Exception route added successfully (PERSISTENT).");
    }
    
    Ok(())
}

fn ensure_route_persists(server_ip: String, gateway_ip: String, if_index: u32) {
    // Run in background to FORCE the route after WireGuard fully initializes
    std::thread::spawn(move || {
        // Wait longer for WireGuard to fully settle and add its routes
        std::thread::sleep(std::time::Duration::from_secs(3));
        
        log_vpn("Re-verifying exception route after WireGuard initialization...");
        
        // DELETE the route first to ensure clean state
        let _ = Command::new("route")
            .args(&["delete", &server_ip])
            .creation_flags(0x08000000)
            .output();
        
        //Sleep briefly
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        // Re-add route with PERSISTENCE and METRIC 1
        let output = Command::new("route")
            .args(&[
                "-p",
                "add", 
                &server_ip, 
                "mask", "255.255.255.255", 
                &gateway_ip, 
                "metric", "1",
                "if", &if_index.to_string()
            ])
            .creation_flags(0x08000000)
            .output();
            
        if let Ok(out) = output {
            if out.status.success() || String::from_utf8_lossy(&out.stderr).contains("already exists") {
                log_vpn("[SUCCESS] Route persistence verified - server traffic will use physical gateway");
            } else {
                log_vpn(&format!("[ERROR] Route re-add failed: {}", String::from_utf8_lossy(&out.stderr)));
            }
        }
    });
}

async fn start_direct_vpn(
    server_id: &str,
    mut creds: VpnCredentials, 
    _state: &tauri::State<'_, crate::VpnState>
) -> Result<String, String> {
    log_vpn("Starting DIRECT VPN connection...");
    
    // 1. Add exception route for the server so we don't route-loop
    // The peer_endpoint usually comes as host:port, we need just the IP
    let server_ip = creds.peer_endpoint.split(':').next().unwrap_or(&creds.peer_endpoint);
    
    // Get route info for later persistence check
    let route_info = get_best_route(server_ip);
    
    // If server_id is an IP, used that. If it's a hostname, we rely on peer_endpoint being an IP
    // For Nera currently, peer_endpoint is 45.76.106.63:51820
    if let Err(e) = add_server_exception_route(server_ip) {
        log_vpn(&format!("Warning: Failed to add exception route: {}", e));
        // Proceeding anyway? Maybe risky, but let's try.
    }
    
    // 2. Generate Config (check if split tunnel is enabled)
    let split_tunnel_enabled = is_split_tunnel_enabled();
    let config_content = generate_wireguard_config(&creds, split_tunnel_enabled);
    let conf_path = vpn_conf_path()?;
    fs::write(&conf_path, &config_content).map_err(|e| e.to_string())?;
    
    // 3. Start WireGuard
    start_wireguard_tunnel(&conf_path, &creds.address)?;
    
    // 4. Ensure route persists after WireGuard initializes
    if let Some((gateway_ip, if_index)) = route_info {
        ensure_route_persists(server_ip.to_string(), gateway_ip, if_index);
    }
    
    Ok(format!("Connected to {} (Direct)", server_id))
}

async fn start_stealth_vpn(
    server_id: &str,
    mut creds: VpnCredentials,
    state: &tauri::State<'_, crate::VpnState>
) -> Result<String, String> {
    log_vpn("Starting STEALTH VPN connection...");
    
    // 1. Initialize Stealth Transport
    log_vpn("Initializing Stealth Transport layer...");
    
    // Hardcoded target for Phase 2.5
    let target_str = "45.76.106.63:443"; 
    let endpoint: std::net::SocketAddr = target_str.parse().unwrap(); 
    
    let transport_options = crate::transport::TransportOptions::TlsBridge {
        sni_hostname: "cdn.neravpn.com".to_string(),
        cert_fingerprint: Some("DC:DE:CD:47:2D:6B:D2:06:6B:46:35:30:89:C0:71:F6:81:E0:02:A5:AC:5A:32:9F:EC:3E:7C:A3:F5:36:5C:8D".to_string()),
        obfuscate: true,
    };

    let config = crate::transport::TransportConfig {
        endpoint,
        local_port: 51821,
        options: transport_options.clone(),
    };

    let mut transport = crate::create_transport(&transport_options);
    
    transport.connect(&config).await.map_err(|e| {
        let msg = format!("Transport connection failed: {e}");
        log_vpn(&msg);
        msg
    })?;

    let wg_endpoint = transport.wireguard_endpoint();
    log_vpn(&format!("Transport established. WireGuard will connect to: {}", wg_endpoint));

    // 2. Point WireGuard to Local Bridge
    creds.peer_endpoint = wg_endpoint.to_string();
    
    // Save transport
    *state.active_transport.lock().unwrap() = Some(transport);
    
    // 3. Generate Config
    let split_tunnel_enabled = is_split_tunnel_enabled();
    let config_content = generate_wireguard_config(&creds, split_tunnel_enabled);
    let conf_path = vpn_conf_path()?;
    fs::write(&conf_path, &config_content).map_err(|e| e.to_string())?;
    
    // 4. Start WireGuard
    if let Err(e) = start_wireguard_tunnel(&conf_path, &creds.address) {
         let transport_opt = state.active_transport.lock().unwrap().take();
         if let Some(mut t) = transport_opt {
             let _ = t.disconnect().await;
         }
         return Err(e);
    }
    
    Ok(format!("Connected to {} (Stealth)", server_id))
}

// --- Helper: Check if split tunnel is enabled ---

fn is_split_tunnel_enabled() -> bool {
    // Read the split_tunnel_v2.json config to check mode
    if let Some(config_dir) = dirs::config_dir() {
        let config_path = config_dir.join("NeraVPN").join("split_tunnel_v2.json");
        if let Ok(data) = fs::read_to_string(&config_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(mode) = json.get("mode").and_then(|v| v.as_str()) {
                    let enabled = mode != "disabled";
                    if enabled {
                        log_vpn(&format!("[SplitTunnel] Config detected: mode={mode} — will use Table=off"));
                    }
                    return enabled;
                }
            }
        }
    }
    false
}

fn log_vpn(msg: &str) {
    println!("[VPN] {}", msg);
    // Also write to our log file
    if let Ok(mut path) = dirs::document_dir().ok_or(()) {
        path.push("NeraVPN");
        let _ = fs::create_dir_all(&path);
        path.push("vpn.log");
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            use std::io::Write;
            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(file, "[{}] {}", ts, msg);
        }
    }
}

fn get_mock_credentials(server_id: &str) -> VpnCredentials {
    // Use the ACTUAL Tokyo server that's already configured in the app
    // This ensures the mock mode can actually connect if WireGuard is installed
    // Port 51820 for direct WireGuard (stealth mode overrides this to localhost)
    let (endpoint, dns) = match server_id {
        "la" => ("45.76.106.63:51820", "9.9.9.9"),        // Using Tokyo for now
        "singapore" => ("45.76.106.63:51820", "9.9.9.9"), // Using Tokyo for now  
        "london" => ("45.76.106.63:51820", "9.9.9.9"),    // Using Tokyo for now
        _ => ("45.76.106.63:51820", "9.9.9.9"),           // Tokyo (default)
    };
    
    log_vpn(&format!("Mock mode: Using endpoint {} for server '{}'", endpoint, server_id));
    
    // ⚠️ DEPRECATED: Mock credentials with hardcoded server key.
    // If the server's WireGuard key changes, this MUST be updated!
    // TODO: Remove mock mode entirely - always require API connectivity.
    VpnCredentials {
        // Using the shared fallback key from main.rs for testing
        private_key: "uKpimIYznJOJQxirEee7xE3MLPipJ90mYVtYMaMqQ3g=".to_string(),
        address: "10.66.66.5/32".to_string(),
        dns: dns.to_string(),
        peer_public_key: "gT2LorzRb5Gz1K/Rkr3Z8zIKyMC78QI1JOhrdCvEmnY=".to_string(),
        peer_endpoint: endpoint.to_string(),
        allowed_ips: "0.0.0.0/0, ::/0".to_string(),
    }
}

// --- Tauri Commands ---

/// Connects to VPN using the anonymous access token.
/// 
/// 1. Exchanges access_token with API for WireGuard credentials
/// 2. Generates config file dynamically
/// 3. Starts WireGuard tunnel service
#[tauri::command]
pub async fn connect_with_token(
    app_handle: AppHandle,
    server_id: String, 
    access_token: String,
    state: tauri::State<'_, crate::VpnState>,
    split_state: State<'_, crate::split_tunnel::SplitTunnelState>,
) -> Result<String, String> {
    log_vpn(&format!("connect_with_token called - server: {}, token: {}...", 
        server_id, 
        &access_token[..std::cmp::min(15, access_token.len())]
    ));

    // Use Direct Mode - simple and works with existing server
    // Stealth Mode requires server TLS bridge setup
    let stealth_mode = false;
    log_vpn(&format!("Stealth Mode: {} (Direct Mode - simple connection)", stealth_mode));
    
    // --- MOCK MODE ---
    // If token starts with "MOCK-", use local mock credentials
    let mut creds = if access_token.starts_with("MOCK-") {
        log_vpn("Using MOCK credentials (token starts with MOCK-)");
        get_mock_credentials(&server_id)
    } else {
        // --- PRODUCTION MODE ---
        log_vpn("Using PRODUCTION mode - calling API");
        // 1. Call the VPN API to exchange Access Token for WireGuard Credentials
        let client = Client::new();
        let res = client
            .post(format!("{}/connect", API_BASE))
            .json(&AuthPayload {
                server_id: server_id.clone(),
                access_token,
            })
            .send()
            .await
            .map_err(|e| {
                let msg = format!("Network error: {e}");
                log_vpn(&msg);
                msg
            })?;
        
        if !res.status().is_success() {
            let status = res.status();
            let error_text = res.text().await.unwrap_or_default();
            let msg = format!("Server rejected token ({}): {}", status, error_text);
            log_vpn(&msg);
            return Err(msg);
        }
        
        res.json::<VpnCredentials>()
            .await
            .map_err(|e| {
                let msg = format!("Failed to parse server response: {e}");
                log_vpn(&msg);
                msg
            })?
    };

    // 2. Branch based on mode
    let result = if stealth_mode {
        start_stealth_vpn(&server_id, creds, &state).await
    } else {
        // Direct mode: Ensure active transport is cleared
        *state.active_transport.lock().unwrap() = None;
        start_direct_vpn(&server_id, creds, &state).await
    };
    
    result?;

    // 2.5. Sync Kill Switch Rules
    // Get KS setting. Since we can't easily access the raw Mutex<bool> in settings from here without loading file
    // We can check the state provided arg
    let ks_enabled = *state.kill_switch_enabled.lock().unwrap();
    if ks_enabled {
        log_vpn("Kill switch enabled. Updating rules for current mode...");
        // Use the main function which we made public
        if let Err(e) = crate::enable_kill_switch_internal(stealth_mode) {
             log_vpn(&format!("Warning: Failed to update kill switch rules: {}", e));
             // Should we fail connection? Probably yes for security.
             // But existing code just logged it. We'll return err to be safe.
             return Err(e);
        }
    }
    
    // 3. Post-Connection Kill Switch Sync (Common)

    
    // 4. Emit vpn-status-changed event so frontend knows we're connected
    log_vpn("Emitting vpn-status-changed event...");
    // Update connected state
    *state.connected.lock().unwrap() = true;

    app_handle
        .emit("vpn-status-changed", VpnStatusPayload { connected: true })
        .map_err(|e| format!("Failed to emit event: {e}"))?;
    
    // 5. Start Split Tunneling if configured
    if !split_state.get_apps().is_empty() {
        log_vpn("Starting split tunneling...");
        if let Err(e) = split_state.start() {
            log_vpn(&format!("Warning: Failed to start split tunneling: {}", e));
            // Don't fail the connection, split tunneling is optional
        }
    }
    
    // ─── Shield Zero: Re-apply DNS override after WireGuard sets its own DNS ───
    // WireGuard tunnel service sets DNS from the .conf file, overwriting our proxy DNS.
    {
        let proxy_state = app_handle.state::<crate::DnsProxyState>();
        let shield_enabled = *proxy_state.shield_state.enabled.lock().unwrap();
        if shield_enabled {
            log_vpn("Shield Zero active — re-applying DNS override...");
            // Delay to let WireGuard's DNS config finish applying
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let _ = crate::swap_wireguard_dns("127.0.0.1");
            log_vpn("Shield Zero DNS re-applied: 127.0.0.1");
        }
    }
    
    log_vpn(&format!("Successfully connected to {}", server_id));
    Ok(format!("Connected to {} successfully", server_id))
}

#[tauri::command]
pub async fn disconnect_token_vpn(
    app_handle: AppHandle,
    state: tauri::State<'_, crate::VpnState>,
    split_state: State<'_, crate::split_tunnel::SplitTunnelState>,
) -> Result<String, String> {
    log_vpn("disconnect_token_vpn called");
    
    // 0. Stop Split Tunneling first
    log_vpn("Stopping split tunneling...");
    split_state.stop();
    
    // 1. Stop WireGuard tunnel
    if USE_WG_NT && crate::wg_nt::is_running() {
        log_vpn("Stopping wg_nt tunnel...");
        if let Err(e) = crate::wg_nt::stop_tunnel() {
            log_vpn(&format!("Warning stopping wg_nt: {}", e));
        }
    }
    
    // Also stop legacy WireGuard service (in case it's running)
    log_vpn("Uninstalling WireGuard tunnel service...");
    let output = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        .arg("nera-token")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Failed to stop WireGuard: {e}"))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "service does not exist" is fine
        if !stderr.is_empty() && !stderr.to_lowercase().contains("does not exist") {
             log_vpn(&format!("Warning stopping WireGuard: {}", stderr.trim()));
        }
    }
    
    // 2. Clean up Transport if it exists
    let transport_opt = state.active_transport.lock().unwrap().take();
    if let Some(mut transport) = transport_opt {
        log_vpn("Cleaning up active transport...");
        if let Err(e) = transport.disconnect().await {
            log_vpn(&format!("Warning: Transport disconnect error: {}", e));
        }
    }
    
    // 3. Update connected state
    *state.connected.lock().unwrap() = false;
    
    // 4. Emit vpn-status-changed event so frontend knows we're disconnected
    log_vpn("Emitting vpn-status-changed event (disconnected)...");
    
    // Remove the unused result binding to suppress warning/error if emit returns Result
    if let Err(e) = app_handle.emit("vpn-status-changed", VpnStatusPayload { connected: false }) {
        log_vpn(&format!("Failed to emit event: {}", e));
    }
    
    log_vpn("Disconnected successfully");
    Ok("Disconnected successfully".to_string())
}
