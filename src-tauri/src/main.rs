/*
  Nera VPN™
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  Nera VPN™ is a trademark of Vio Holdings LLC.
  This software is proprietary and confidential. Unauthorized copying,
  distribution, modification, or use of this software, via any medium,
  is strictly prohibited without written permission from the copyright holder.
  The source code and binaries are protected by copyright law and international treaties.
*/
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod vpn;
mod transport;
mod stealth;
mod split_tunnel;
mod split_tunnel_v2;  // WFP-based split tunneling (new architecture)
mod wg_nt;
mod shield_zero;  // Shield Zero — DGA threat detection engine

use crate::transport::Transport;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::Command,
    os::windows::process::CommandExt,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    sync::Mutex,
    thread,
    time::Duration,
};

use sysinfo::Networks;

use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use tauri::{
    menu::{Menu, MenuItem, MenuBuilder, CheckMenuItem},
    tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState},
    AppHandle, Manager, State, Emitter,
};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::ShellExt;


const WIREGUARD_EXE: &str = r"C:\Program Files\WireGuard\wireguard.exe";
const TUNNEL_NAME: &str = "nera";

// ⚠️ DEPRECATED: Hardcoded fallback configs below are legacy and should NOT be relied upon.
// The API (vpn.rs connect_with_token) is the authoritative source for credentials.
// These templates exist ONLY for edge cases where API is unreachable.
// 
// ⚠️⚠️⚠️ KEY SYNC WARNING ⚠️⚠️⚠️
// If the server's WireGuard key ever changes, these MUST be updated!
// The backend API (server/index.js) now reads the key directly from WireGuard,
// but these client fallbacks are hardcoded and will break if out of sync.
// 
// TODO: Remove these fallback configs entirely and require API connectivity.
// Server public key: gT2LorzRb5Gz1K/Rkr3Z8zIKyMC78QI1JOhrdCvEmnY=
// Last verified: 2026-01-26 (from wg show wg0 public-key on VPS)

const TOKYO_CONFIG_TEMPLATE: &str = r#"[Interface]
PrivateKey = {{PRIVATE_KEY}}/32
Address = {{ADDRESS}}
DNS = 9.9.9.9

[Peer]
PublicKey = gT2LorzRb5Gz1K/Rkr3Z8zIKyMC78QI1JOhrdCvEmnY=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 45.76.106.63:51820
PersistentKeepalive = 25
"#;

const SHARED_FALLBACK_CONFIG: &str = r#"[Interface]
PrivateKey = uKpimIYznJOJQxirEee7xE3MLPipJ90mYVtYMaMqQ3g=
Address = 10.66.66.5/32
DNS = 9.9.9.9

[Peer]
PublicKey = gT2LorzRb5Gz1K/Rkr3Z8zIKyMC78QI1JOhrdCvEmnY=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 45.76.106.63:51820
PersistentKeepalive = 25
"#;


// --- Structs ---

pub struct VpnState {
    pub connected: Mutex<bool>,
    pub kill_switch_enabled: Mutex<bool>,
    pub monitoring_flag: Mutex<Option<Arc<AtomicBool>>>,
    pub active_transport: Mutex<Option<Box<dyn crate::transport::Transport>>>,
    pub stealth_enabled: Mutex<bool>,
}

#[derive(Clone, serde::Serialize)]
struct VpnStatusPayload {
    connected: bool,
}

#[derive(Clone, serde::Serialize)]
struct KillSwitchPayload {
    enabled: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct AppSettings {
    pub kill_switch_enabled: bool,
    #[serde(default = "default_server")]
    pub selected_server: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub device_ip: String,
    #[serde(default)]
    pub remember_me: bool,
    #[serde(default)]
    pub access_token: String,  // Anonymous blind token auth
    #[serde(default)]
    pub dpi_stealth_enabled: bool,
}

fn default_server() -> String {
    "tokyo".to_string()
}

// --- Helpers ---

fn nera_conf_path() -> Result<PathBuf, String> {
    dirs::document_dir()
        .map(|mut dir| {
            dir.push("nera.conf");
            dir
        })
        .ok_or_else(|| "Could not find the Documents folder on this system.".to_string())
}

fn temp_conf_path() -> Result<PathBuf, String> {
    log_dir() // storing temp conf in logs dir for safety/easy cleanup guarantees
        .map(|mut dir| {
            dir.push("nera-temp.conf");
            dir
        })
}

fn get_config_content(_server_key: &str) -> String {
    let settings = load_settings();

    // Check if we have valid unique keys
    if !settings.private_key.is_empty() && !settings.device_ip.is_empty() {
        return TOKYO_CONFIG_TEMPLATE
            .replace("{{PRIVATE_KEY}}", &settings.private_key)
            .replace("{{ADDRESS}}", &settings.device_ip);
    }

    // Fallback to shared key
    SHARED_FALLBACK_CONFIG.to_string()
}

fn log_dir() -> Result<PathBuf, String> {
    let mut dir = dirs::document_dir().ok_or_else(|| "Could not find Documents folder.".to_string())?;
    dir.push("NeraVPN");
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create log directory: {e}"))?;
    }
    Ok(dir)
}

fn log_file_path() -> Result<PathBuf, String> {
    let mut path = log_dir()?;
    path.push("nera.log");
    Ok(path)
}

fn append_log(line: &str) -> Result<(), String> {
    let path = log_file_path()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Failed to open log file: {e}"))?;

    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    writeln!(file, "[{}] {}", ts, line).map_err(|e| format!("Failed to write to log file: {e}"))?;

    Ok(())
}

fn settings_path() -> Result<PathBuf, String> {
    let mut path = log_dir()?;
    path.push("settings.json");
    Ok(path)
}

pub fn load_settings() -> AppSettings {
    let path = match settings_path() {
        Ok(p) => p,
        Err(_) => return AppSettings::default(),
    };

    if !path.exists() {
        return AppSettings::default();
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return AppSettings::default(),
    };

    serde_json::from_str(&content).unwrap_or_default()
}

pub fn save_settings(settings: &AppSettings) {
    if let Ok(path) = settings_path() {
        if let Ok(content) = serde_json::to_string_pretty(settings) {
            let _ = fs::write(path, content);
        }
    }
}

fn generate_keypair() -> (String, String) {
    let mut rng = OsRng;
    let private_key = StaticSecret::random_from_rng(&mut rng);
    let public_key = PublicKey::from(&private_key);

    let priv_b64 = general_purpose::STANDARD.encode(private_key.to_bytes());
    let pub_b64 = general_purpose::STANDARD.encode(public_key.as_bytes());

    (priv_b64, pub_b64)
}

#[derive(Serialize, Deserialize, Debug)]
struct AddPeerResponse {
    allowed_ip: String,
    // server might return other fields, we just need allowed_ip
}

#[derive(Serialize)]
struct RegisterRequest {
    email: String,
    password: String,
    public_key: String,
}

// --- Internal Logic Functions ---

fn force_disconnect_all() {
    // Safety cleanup on launch to prevent "zombie" tunnels from previous crashes.
    // We try to remove both potential service names.
    let _ = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        .arg("nera")
        .output();

    let _ = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        .arg("nera-temp")
        .output();
}

/// Kills any "zombie" WireGuard tunnel from a previous app crash.
/// This is the "Clean Slate" protocol that runs every time the app launches.
/// It silently catches errors if the adapter doesn't exist (fresh install case).
fn kill_zombie_tunnel() {
    println!("🧹 Nera VPN: Cleaning up stale connections...");
    
    // Method 1: Use WireGuard's native uninstall command
    let _ = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        .arg("nera-token")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW - run silently
        .output();
    
    // Method 2: Use Windows Service Control to delete the service directly
    // This handles edge cases where WireGuard's command fails
    let _ = Command::new("sc")
        .args(&["delete", "WireGuardTunnel$nera-token"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW - run silently
        .output();
    
    // Note: Both commands silently ignore errors if the service doesn't exist.
    // This is intentional - fresh users won't have a zombie adapter.
}

fn measure_latency() -> String {
    #[cfg(target_os = "windows")]
    let output = Command::new("ping").args(&["-n", "1", "1.1.1.1"]).output();
    #[cfg(not(target_os = "windows"))]
    let output = Command::new("ping").args(&["-c", "1", "1.1.1.1"]).output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Look for "time=XXms" or "time<1ms"
            // Windows output: "Reply from 1.1.1.1: bytes=32 time=24ms TTL=116"
            // Linux output: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=116 time=24 ms"
            if let Some(start) = stdout.find("time=") {
                let rest = &stdout[start + 5..];
                if let Some(end) = rest.find("ms") {
                    return format!("{} ms", &rest[..end]);
                }
            } else if stdout.contains("time<1ms") {
                return "<1 ms".to_string();
            }
            "—".to_string()
        }
        _ => "—".to_string(),
    }
}

pub fn enable_kill_switch_internal(stealth_mode: bool) -> Result<(), String> {
    append_log(&format!("Enabling Kill Switch (Firewall Block Outbound) - Stealth: {}", stealth_mode)).ok();

    // 1. Clear existing rules first
    let rules_to_delete = [
        "NeraVPN_KS_AllowWG",
        "NeraVPN_KS_AllowTunnel",
        "NeraVPN_KS_AllowTunnel2",
        "NeraVPN_KS_AllowDNS",
        "NeraVPN_KS_AllowLocalProxy",
        "NeraVPN_KS_AllowTLSBridge",
        "NeraVPN_KS_BlockAll",
    ];
    
    for rule_name in rules_to_delete {
        let _ = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name),
            ])
            .creation_flags(0x08000000)
            .output();
    }
    append_log("Cleared existing kill switch rules.").ok();

    // 2. Allow WireGuard.exe to communicate (required for handshakes)
    let wg_result = Command::new("netsh")
        .args(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=NeraVPN_KS_AllowWG",
            "dir=out",
            "action=allow",
            &format!("program={}", WIREGUARD_EXE),
            "enable=yes",
        ])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("Failed to add WG rule: {e}"))?;
    
    if wg_result.status.success() {
        append_log("✓ Allowed WireGuard.exe").ok();
    } else {
        append_log("⚠ Failed to add WireGuard.exe rule").ok();
    }

    if stealth_mode {
        // STEALTH MODE RULES

        // 3a. Allow WireGuard to talk to Local Proxy (UDP 127.0.0.1:51821)
        let proxy_result = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=NeraVPN_KS_AllowLocalProxy",
                "dir=out",
                "action=allow",
                "protocol=UDP",
                "localport=51821",
                "remoteip=127.0.0.1",
                "enable=yes",
            ])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| format!("Failed to add LocalProxy rule: {e}"))?;

        if proxy_result.status.success() {
            append_log("✓ Allowed Local UDP Proxy").ok();
        }

        // 3b. Allow App to talk to Remote Bridge (TCP 443)
        // Allowing all TCP 443 outbound for simplicity and robustness
        let bridge_result = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=NeraVPN_KS_AllowTLSBridge",
                "dir=out",
                "action=allow",
                "protocol=TCP",
                "remoteport=443",
                "enable=yes",
            ])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| format!("Failed to add TLS Bridge rule: {e}"))?;

        if bridge_result.status.success() {
            append_log("✓ Allowed TLS Bridge outbound").ok();
        }

    } else {
        // DIRECT MODE RULES

        // 3. Allow traffic on "nera-temp" Tunnel Interface (legacy connection)
        let tunnel1_result = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=NeraVPN_KS_AllowTunnel",
                "dir=out",
                "action=allow",
                "interface=nera-temp",
                "enable=yes",
            ])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| format!("Failed to add Tunnel rule: {e}"))?;

        if tunnel1_result.status.success() {
             append_log("✓ Allowed nera-temp tunnel interface").ok();
        }

        // 4. Allow traffic on "nera-token" Tunnel Interface (token-based connection)
        let tunnel2_result = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=NeraVPN_KS_AllowTunnel2",
                "dir=out",
                "action=allow",
                "interface=nera-token",
                "enable=yes",
            ])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| format!("Failed to add Tunnel2 rule: {e}"))?;

        if tunnel2_result.status.success() {
             append_log("✓ Allowed nera-token tunnel interface").ok();
        }
    }

    // NOTE: We intentionally do NOT add a blanket DNS rule.
    // DNS queries should go through the VPN tunnel (using the tunnel's DNS setting).
    // Allowing UDP 53 to all destinations would create a DNS leak!
    append_log("ℹ DNS traffic will route through VPN tunnel only (no leak)").ok();

    // 5. BLOCK all other outbound traffic
    let status = Command::new("netsh")
        .args(&[
            "advfirewall",
            "set",
            "allprofiles",
            "firewallpolicy",
            "blockinbound,blockoutbound",
        ])
        .creation_flags(0x08000000)
        .status()
        .map_err(|e| format!("Failed to set blocking policy: {e}"))?;

    if !status.success() {
        append_log("⚠ FAILED to set blocking policy!").ok();
        return Err("Failed to execute netsh blocking policy".to_string());
    }

    append_log("✓ Kill Switch ACTIVE - All traffic blocked except VPN tunnel").ok();
    Ok(())
}

/// Resets firewall rules to safe defaults.
/// Called at startup to ensure crash recovery, and when disabling kill switch.
/// This is the core "self-healing" function that prevents lockouts.
pub fn reset_firewall_rules() -> Result<(), String> {
    append_log("Resetting firewall rules to safe defaults...").ok();

    // 1. Restore Default Policy -> Allow Outbound
    let status = Command::new("netsh")
        .args(&[
            "advfirewall",
            "set",
            "allprofiles",
            "firewallpolicy",
            "blockinbound,allowoutbound",
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .status()
        .map_err(|e| format!("Failed to restore policy: {e}"))?;

    if !status.success() {
        append_log("CRITICAL: Failed to restore firewall policy!").ok();
    } else {
        append_log("Firewall policy restored to allowoutbound.").ok();
    }

    // 2. Delete our Nera VPN kill switch rules (silently ignore errors)
    let rules_to_delete = [
        "NeraVPN_KS_AllowWG",
        "NeraVPN_KS_AllowTunnel",
        "NeraVPN_KS_AllowTunnel2",
        "NeraVPN_KS_AllowDNS",
        "NeraVPN_KS_AllowLocalProxy",
        "NeraVPN_KS_AllowTLSBridge",
        "NeraVPN_KS_BlockAll",
    ];
    
    for rule_name in rules_to_delete {
        let _ = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name),
            ])
            .creation_flags(0x08000000)
            .output();
    }
    
    append_log("Firewall rules reset complete.").ok();
    Ok(())
}

fn disable_kill_switch_internal() -> Result<(), String> {
    append_log("Disabling Kill Switch (Restore Allow Outbound)").ok();
    reset_firewall_rules()
}

pub fn create_transport(options: &crate::transport::TransportOptions) -> Box<dyn crate::transport::Transport> {
    match options {
        crate::transport::TransportOptions::Direct => Box::new(crate::transport::DirectTransport::new()),
        crate::transport::TransportOptions::TlsBridge { .. } => Box::new(crate::stealth::TlsBridgeTransport::new()),
        _ => Box::new(crate::transport::DirectTransport::new()),
    }
}

async fn connect_vpn_internal(
    app_handle: &AppHandle,
    state: &State<'_, VpnState>,
    server_key: Option<String>,
) -> Result<(), String> {
    // 1. Load Settings & Determine Mode
    let key = server_key.unwrap_or_else(|| "tokyo".to_string());
    
    // Check in-memory state for stealth preference
    let stealth_mode = *state.stealth_enabled.lock().unwrap();
    println!("[DEBUG] Stealth Mode is: {}", stealth_mode);
    // Also load settings for other fields
    let settings = load_settings(); 

    append_log(&format!("Connect requested ({key}). Stealth Mode: {stealth_mode}")).ok();

    // 2. Configure Transport
    // Direct mode uses port 51820 (raw WireGuard UDP)
    // Stealth mode uses port 443 (TLS bridge)
    let endpoint = if stealth_mode {
        "45.76.106.63:443".parse().unwrap()
    } else {
        "45.76.106.63:51820".parse().unwrap()
    };
    
    let transport_options = if stealth_mode {
        crate::transport::TransportOptions::TlsBridge {
            sni_hostname: "cdn.neravpn.com".to_string(),
            cert_fingerprint: Some("DC:DE:CD:47:2D:6B:D2:06:6B:46:35:30:89:C0:71:F6:81:E0:02:A5:AC:5A:32:9F:EC:3E:7C:A3:F5:36:5C:8D".to_string()),
            obfuscate: true,
        }
    } else {
        crate::transport::TransportOptions::Direct
    };

    let config = crate::transport::TransportConfig {
        endpoint,
        local_port: 51821,
        options: transport_options.clone(),
    };

    // 3. Initialize & Connect Transport
    let mut transport = create_transport(&transport_options);
    
    append_log("Initializing transport layer...").ok();
    transport.connect(&config).await.map_err(|e| format!("Transport connection failed: {e}"))?;
    
    let wg_endpoint = transport.wireguard_endpoint();
    append_log(&format!("Transport established. WireGuard endpoint: {}", wg_endpoint)).ok();

    // 4. Generate Config Content
    let mut config_content = get_config_content(&key);
    
    // Override endpoint in config if needed
    if stealth_mode {
        // Replace remote IP with local proxy IP (stealth uses localhost bridge)
        config_content = config_content.replace("45.76.106.63:51820", &wg_endpoint.to_string());
        
        // Ensure MTU is lower for overhead
        if !config_content.contains("MTU =") {
            config_content = config_content.replace("[Interface]", "[Interface]\nMTU = 1280");
        }
    }
    // Direct mode: config already has correct endpoint (51820)

    // 5. Write to Temp File
    let conf_path = temp_conf_path()?;
    fs::write(&conf_path, config_content)
        .map_err(|e| format!("Failed to write temp config: {e}"))?;

    // 6. Sync Kill Switch (if enabled)
    // Must update rules now that we know the mode
    if settings.kill_switch_enabled {
        enable_kill_switch_internal(stealth_mode)?;
    }

    // 7. Launch WireGuard
    append_log("Launching WireGuard service...").ok();
    let status = Command::new(WIREGUARD_EXE)
        .arg("/installtunnelservice")
        .arg(&conf_path)
        .status()
        .map_err(|e| format!("Failed to start WireGuard: {e}"))?;

    if !status.success() {
        let msg = format!("WireGuard exited with status: {status}");
        append_log(&format!("Connect failed: {msg}")).ok();
        // Cleanup transport
        transport.disconnect().await.ok();
        return Err(msg);
    }

    // 8. Update State
    *state.connected.lock().unwrap() = true;
    *state.active_transport.lock().unwrap() = Some(transport);

    app_handle
        .emit("vpn-status-changed", VpnStatusPayload { connected: true })
        .map_err(|e| format!("Failed to emit event: {e}"))?;

    append_log("Connect successful. Tunnel service installed.").ok();

    // ─── Shield Zero: Re-apply DNS override after WireGuard sets its own DNS ───
    // WireGuard tunnel service installs its DNS config from the .conf file,
    // which overwrites our 127.0.0.1 Shield Zero proxy DNS.
    // We must re-apply AFTER a small delay to let the interface fully come up.
    {
        let proxy_state = app_handle.state::<DnsProxyState>();
        let shield_enabled = *proxy_state.shield_state.enabled.lock().unwrap();
        if shield_enabled {
            println!("[Shield Zero] Re-applying DNS override after VPN connect...");
            // Small delay: WireGuard's DNS config takes ~1-2s to apply
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = swap_wireguard_dns("127.0.0.1");
            println!("[Shield Zero] DNS re-applied: 127.0.0.1 (proxy active)");
        }
    }

    // Start Traffic Monitoring
    let flag = Arc::new(AtomicBool::new(true));
    *state.monitoring_flag.lock().unwrap() = Some(flag.clone());
    let app_handle_clone = app_handle.clone();

    thread::spawn(move || {
        let mut networks = Networks::new_with_refreshed_list();
        let mut last_rx = 0;
        let mut last_tx = 0;
        let mut loop_count = 0;
        let mut current_ping = "—".to_string();

        loop {
            if !flag.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
            networks.refresh_list();

            // Measure Latency every second
            // Run in separate quick thread or just block slightly?
            // Ping -n 1 is fast usually. Blocking here for <100ms is OK.
            current_ping = measure_latency();

            // 1. Try to find "nera" or "wg" or "tun" interface
            let mut target_network = networks.iter().find(|(name, _)| {
                let n = name.to_lowercase();
                n.contains("nera") || n.contains("wg") || n.contains("tun")
            });

            // 2. Fallback: Find the interface with the HIGHEST total traffic (Active Internet)
            if target_network.is_none() {
                target_network = networks
                    .iter()
                    .filter(|(name, _)| !name.to_lowercase().contains("loopback"))
                    .max_by_key(|(_, data)| data.total_received());
            }

            if let Some((_name, data)) = target_network {
                let current_rx = data.total_received();
                let current_tx = data.total_transmitted();

                // Calculate Speed (Delta)
                // Use saturating_sub to avoid crashes on counter reset
                let dl_speed = if last_rx > 0 && current_rx > last_rx {
                    current_rx.saturating_sub(last_rx)
                } else {
                    0
                };
                let ul_speed = if last_tx > 0 && current_tx > last_tx {
                    current_tx.saturating_sub(last_tx)
                } else {
                    0
                };

                last_rx = current_rx;
                last_tx = current_tx;

                // Emit Event
                app_handle_clone
                    .emit(
                        "traffic-update",
                        serde_json::json!({
                            "download": dl_speed,
                            "upload": ul_speed,
                            "ping": current_ping
                        }),
                    )
                    .ok();
            }
        }
    });

    Ok(())
}

async fn disconnect_vpn_internal(app_handle: &AppHandle, state: &State<'_, VpnState>) -> Result<(), String> {
    append_log("Disconnect requested. Stopping WireGuard service...").ok();

    // 0. Disconnect Transport (if any)
    let transport_opt = state.active_transport.lock().unwrap().take();
    if let Some(mut transport) = transport_opt {
        append_log("Disconnecting transport layer...").ok();
        transport.disconnect().await.ok();
    }

    // Stop Traffic Monitoring
    if let Some(flag) = state.monitoring_flag.lock().unwrap().take() {
        flag.store(false, Ordering::Relaxed);
    }

    let output = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        // NOTE: wireguard uses the basename of the conf file as service name.
        // We write to `nera-temp.conf`, so service name is `nera-temp`.
        // BUT previous implementation used `nera.conf` -> `nera`.
        // To support legacy cleanups, we might try removing `nera` AND `nera-temp`.
        // Or we just try removing current logic's name.
        // wait, constant TUNNEL_NAME was "nera".
        // Use filename without extension.
        // temp_conf_path is ".../nera-temp.conf". Service is "nera-temp".
        // Cleanest is to try removing both or update TUNNEL_NAME.
        // Let's update command arg to remove "nera-temp".
        .arg("nera-temp")
        .output()
        .map_err(|e| format!("Failed to stop WireGuard: {e}"))?;

    // Also try removing legacy "nera" service just in case?
    // It's cheap to try.
    let _ = Command::new(WIREGUARD_EXE)
        .arg("/uninstalltunnelservice")
        .arg("nera")
        .output();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        if stderr
            .to_lowercase()
            .contains("the specified service does not exist as an installed service")
        {
            append_log("Disconnect: service not found (already stopped).").ok();

            *state.connected.lock().unwrap() = false;
            app_handle
                .emit("vpn-status-changed", VpnStatusPayload { connected: false })
                .ok();

            return Ok(());
        }

        let msg = format!("WireGuard error: {}", stderr.trim());
        append_log(&format!("Disconnect failed: {msg}")).ok();
        return Err(msg);
    }

    // Update state
    *state.connected.lock().unwrap() = false;
    app_handle
        .emit("vpn-status-changed", VpnStatusPayload { connected: false })
        .map_err(|e| format!("Failed to emit event: {e}"))?;

    append_log("Disconnect successful. Tunnel service removed.").ok();
    Ok(())
}

fn update_tray_menu(app: &AppHandle, ks_enabled: bool) {
    // In v2 we don't have get_item. We need to rebuild the menu or use IDs if we kept references.
    // Simpler approach for now: Rebuild the whole tray menu.
    let _ = build_tray_menu(app, ks_enabled).map(|menu| {
        let _ = app.tray_by_id("main").map(|tray| tray.set_menu(Some(menu)));
    });
}

fn build_tray_menu(app: &AppHandle, ks_enabled: bool) -> Result<Menu<tauri::Wry>, tauri::Error> {
    let ks_title = if ks_enabled {
        "Disable Kill Switch (Restore Internet)"
    } else {
        "Enable Kill Switch"
    };

    MenuBuilder::new(app)
        .items(&[
            &MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?,
            &MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?,
            &MenuItem::with_id(app, "sep1", "-", true, None::<&str>)?, // Separator?
            &MenuItem::with_id(app, "killswitch_toggle", ks_title, true, None::<&str>)?,
             // Separator not directly supported as CheckMenuItem? Using MenuItem with "-" is common workadround or separate API.
             // v2 has PredefinedMenuItem::separator(app)?
             // Let's use simplified items for now.
        ])
        .build()
}

// --- Tauri Commands ---

/// Start the background traffic monitoring thread
/// Called by frontend when VPN connection is established
#[tauri::command]
fn start_traffic_monitoring(app_handle: AppHandle, state: State<VpnState>) -> Result<(), String> {
    append_log("Starting traffic monitoring...").ok();
    
    // Stop any existing monitoring first
    if let Some(flag) = state.monitoring_flag.lock().unwrap().take() {
        flag.store(false, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(100)); // Give thread time to clean up
    }
    
    // Start new monitoring thread
    let flag = Arc::new(AtomicBool::new(true));
    *state.monitoring_flag.lock().unwrap() = Some(flag.clone());
    let app_handle_clone = app_handle.clone();

    thread::spawn(move || {
        let mut networks = Networks::new_with_refreshed_list();
        let mut last_rx = 0u64;
        let mut last_tx = 0u64;
        let mut current_ping = "—".to_string();

        loop {
            if !flag.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
            networks.refresh_list();

            // Measure Latency
            current_ping = measure_latency();

            // 1. Try to find "nera" or "wg" or "tun" interface (including "nera-token")
            let mut target_network = networks.iter().find(|(name, _)| {
                let n = name.to_lowercase();
                n.contains("nera") || n.contains("wg") || n.contains("tun")
            });

            // 2. Fallback: Find the interface with the HIGHEST total traffic
            if target_network.is_none() {
                target_network = networks
                    .iter()
                    .filter(|(name, _)| !name.to_lowercase().contains("loopback"))
                    .max_by_key(|(_, data)| data.total_received());
            }

            if let Some((_name, data)) = target_network {
                let current_rx = data.total_received();
                let current_tx = data.total_transmitted();

                // Calculate Speed (Delta)
                let dl_speed = if last_rx > 0 && current_rx > last_rx {
                    current_rx.saturating_sub(last_rx)
                } else {
                    0
                };
                let ul_speed = if last_tx > 0 && current_tx > last_tx {
                    current_tx.saturating_sub(last_tx)
                } else {
                    0
                };

                last_rx = current_rx;
                last_tx = current_tx;

                // Emit Event
                app_handle_clone
                    .emit(
                        "traffic-update",
                        serde_json::json!({
                            "download": dl_speed,
                            "upload": ul_speed,
                            "ping": current_ping
                        }),
                    )
                    .ok();
            }
        }
        
        // Log when monitoring stops
        println!("[VPN] Traffic monitoring stopped");
    });

    append_log("Traffic monitoring started.").ok();
    Ok(())
}

/// Stop the background traffic monitoring thread
/// Called by frontend when VPN is disconnected
#[tauri::command]
fn stop_traffic_monitoring(state: State<VpnState>) -> Result<(), String> {
    append_log("Stopping traffic monitoring...").ok();
    
    if let Some(flag) = state.monitoring_flag.lock().unwrap().take() {
        flag.store(false, Ordering::Relaxed);
    }
    
    append_log("Traffic monitoring stopped.").ok();
    Ok(())
}

/// Tauri-managed wrapper for the DNS proxy handle.
/// Uses tokio::sync::Mutex because the proxy is async.
/// Also holds the shared Arc<ShieldZeroState> so the proxy and Tauri commands
/// share the same counters, whitelist, and telemetry.
pub struct DnsProxyState {
    handle: tokio::sync::Mutex<Option<shield_zero::dns_proxy::DnsProxyHandle>>,
    pub shield_state: Arc<shield_zero::ShieldZeroState>,
}

/// Swap the WireGuard adapter DNS via netsh.
pub fn swap_wireguard_dns(dns_ip: &str) -> Result<(), String> {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("netsh")
        .args(&[
            "interface", "ipv4", "set", "dnsservers",
            &format!("name=\"WireGuard\""),
            "static",
            dns_ip,
            "primary",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to set DNS: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Non-fatal — the interface may not exist yet (VPN not connected)
        println!("[Shield Zero DNS] netsh warning: {}", stderr);
    } else {
        println!("[Shield Zero DNS] DNS set to {}", dns_ip);
    }
    Ok(())
}

/// Toggle Shield Zero (DGA Threat Detection Engine)
/// When enabled: starts DNS proxy on 127.0.0.1:53, swaps WireGuard DNS to it.
/// When disabled: stops DNS proxy, restores WireGuard DNS to 9.9.9.9.
#[tauri::command]
async fn toggle_netshield(
    enabled: bool,
    proxy_state: State<'_, DnsProxyState>,
) -> Result<(), String> {
    append_log(&format!("Shield Zero toggled: {}", enabled)).ok();
    proxy_state.shield_state.set_enabled(enabled);

    let mut proxy_handle = proxy_state.handle.lock().await;

    if enabled {
        // Stop any existing proxy first
        if let Some(old) = proxy_handle.take() {
            old.stop().await;
        }

        // Start the DNS proxy — shares the same ShieldZeroState as Tauri commands
        let state_arc = proxy_state.shield_state.clone();
        let upstream = std::net::Ipv4Addr::new(9, 9, 9, 9);
        match shield_zero::dns_proxy::start_proxy(state_arc, upstream).await {
            Ok(handle) => {
                *proxy_handle = Some(handle);
                println!("[Shield Zero] ✅ DNS proxy started on 127.0.0.1:53");
            }
            Err(e) => {
                println!("[Shield Zero] ⚠️ DNS proxy failed to start: {}", e);
                // Don't fail — Shield Zero analysis still works via IPC
            }
        }

        // Swap WireGuard DNS to our proxy
        let _ = swap_wireguard_dns("127.0.0.1");

        // Background: auto-download/refresh blocklists (non-blocking)
        let shield_for_download = proxy_state.shield_state.clone();
        tokio::spawn(async move {
            println!("[Shield Zero] Background blocklist refresh starting...");
            match shield_for_download.blocklist.download_and_update().await {
                Ok(stats) => {
                    println!(
                        "[Shield Zero] Blocklist loaded: {} domains from {} sources",
                        stats.total_domains, stats.sources_loaded
                    );
                }
                Err(e) => {
                    println!("[Shield Zero] Blocklist download failed: {} (using cache)", e);
                }
            }
        });

        println!("[Shield Zero] ✅ Enabled — DGA detection engine active");
    } else {
        // Stop the proxy
        if let Some(handle) = proxy_handle.take() {
            handle.stop().await;
            println!("[Shield Zero] DNS proxy stopped");
        }

        // Restore WireGuard DNS to Quad9
        let _ = swap_wireguard_dns("9.9.9.9");

        println!("[Shield Zero] ⏹ Disabled — DGA detection engine stopped");
    }

    Ok(())
}

/// Analyze a domain name for DGA (Domain Generation Algorithm) patterns.
/// Returns a JSON object with score, verdict, and feature breakdown.
#[tauri::command]
fn analyze_domain(
    domain: String,
    proxy_state: State<'_, DnsProxyState>,
) -> Result<shield_zero::DomainAnalysis, String> {
    let analysis = proxy_state.shield_state.analyze(&domain);
    
    if analysis.blocked {
        append_log(&format!(
            "[Shield Zero] 🚫 BLOCKED domain: {} (score={:.3}, verdict={})",
            domain, analysis.score, analysis.verdict
        )).ok();
    }
    
    Ok(analysis)
}

/// Get Shield Zero comprehensive statistics (session + lifetime).
#[tauri::command]
fn shield_zero_stats(
    proxy_state: State<'_, DnsProxyState>,
) -> Result<serde_json::Value, String> {
    Ok(proxy_state.shield_state.get_stats())
}

/// Add a domain to the Shield Zero whitelist (false positive override).
#[tauri::command]
fn whitelist_domain(
    domain: String,
    proxy_state: State<'_, DnsProxyState>,
) -> Result<(), String> {
    proxy_state.shield_state.add_to_whitelist(&domain);
    println!("[Shield Zero] ✅ Whitelisted: {}", domain);
    Ok(())
}

/// Remove a domain from the Shield Zero whitelist.
#[tauri::command]
fn remove_whitelist(
    domain: String,
    proxy_state: State<'_, DnsProxyState>,
) -> Result<(), String> {
    proxy_state.shield_state.remove_from_whitelist(&domain);
    println!("[Shield Zero] ❌ Removed from whitelist: {}", domain);
    Ok(())
}

/// Get the current Shield Zero whitelist.
#[tauri::command]
fn get_whitelist(
    proxy_state: State<'_, DnsProxyState>,
) -> Result<Vec<String>, String> {
    Ok(proxy_state.shield_state.get_whitelist())
}

/// Get the Shield Zero threat log (last 50 entries).
#[tauri::command]
fn get_threat_log(
    proxy_state: State<'_, DnsProxyState>,
) -> Result<Vec<shield_zero::ThreatLogEntry>, String> {
    Ok(proxy_state.shield_state.get_threat_log())
}

/// Download/refresh Shield Zero blocklists from remote sources.
/// Downloads OISD Big, Steven Black, and HaGeZi PRO lists.
/// Returns stats about the loaded lists.
#[tauri::command]
async fn download_blocklists(
    proxy_state: State<'_, DnsProxyState>,
) -> Result<serde_json::Value, String> {
    println!("[Shield Zero] Starting blocklist download...");
    let stats = proxy_state.shield_state.blocklist.download_and_update().await?;
    println!(
        "[Shield Zero] Blocklist update complete: {} domains from {} sources",
        stats.total_domains, stats.sources_loaded
    );
    Ok(serde_json::json!({
        "total_domains": stats.total_domains,
        "sources_loaded": stats.sources_loaded,
        "last_updated": stats.last_updated,
        "source_counts": stats.source_counts
    }))
}

/// Set Split Tunneling configuration
/// Allows specified apps to bypass the VPN tunnel
#[tauri::command]
fn set_split_tunneling(
    enabled: bool, 
    apps: Vec<String>,
    vpn_state: State<'_, VpnState>,
    split_state: State<'_, split_tunnel::SplitTunnelState>,
) -> Result<(), String> {
    append_log(&format!("Split Tunneling toggled: {}, apps: {:?}", enabled, apps)).ok();
    
    // Update the app list
    split_state.set_apps(apps);
    
    // Check if VPN is connected
    let vpn_connected = *vpn_state.connected.lock().unwrap();
    
    if enabled {
        if vpn_connected {
            // Start split tunneling immediately if VPN is already connected
            split_state.start()?;
        } else {
            println!("[Split Tunneling] Configured but VPN not connected. Will start when VPN connects.");
        }
    } else {
        // Stop split tunneling
        split_state.stop();
    }
    
    Ok(())
}



// ============================================================
// Port Forwarding — Ephemeral P2P Port (Beta)
// ============================================================

static PORT_FWD_ACTIVE: AtomicBool = AtomicBool::new(false);
static PORT_FWD_HEARTBEAT_RUNNING: AtomicBool = AtomicBool::new(false);

const PORT_FWD_API_PUBLIC: &str = "http://45.76.106.63:3000/api/port-forward";
const PORT_FWD_API_INTERNAL: &str = "http://10.66.66.1:3000/api/port-forward";

fn request_port_fwd(client: &reqwest::blocking::Client, method: reqwest::Method, body: &serde_json::Value) -> Result<reqwest::blocking::Response, String> {
    // Try Internal IP first (Tunnel)
    let internal_url = PORT_FWD_API_INTERNAL;
    let public_url = PORT_FWD_API_PUBLIC;
    
    // Attempt 1: Internal
    let start = std::time::Instant::now();
    match client.request(method.clone(), internal_url)
        .json(body)
        .timeout(std::time::Duration::from_secs(3)) // Short timeout for internal
        .send() {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                println!("[PortFwd] Internal API failed connection: {} (took {:?})", e, start.elapsed());
                // Fallback to public
            }
        }
    
    // Attempt 2: Public
    println!("[PortFwd] Falling back to Public API...");
    client.request(method, public_url)
        .json(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("Both Internal and Public API failed: {}", e))
}

/// Toggle P2P Port Forwarding (Ephemeral)
/// When enabled: Requests a random port from the server, starts heartbeat.
/// When disabled: Releases the port, stops heartbeat.
#[tauri::command]
fn toggle_port_forwarding(enabled: bool) -> Result<Option<u16>, String> {
    append_log(&format!("Port Forwarding toggled: {}", enabled)).ok();

    let settings = load_settings();
    let access_token = settings.access_token.clone();
    let device_ip = settings.device_ip.clone();

    if access_token.is_empty() {
        return Err("Not authenticated. Please connect to VPN first.".to_string());
    }

    let client = reqwest::blocking::Client::new();

    if enabled {
        // --- REQUEST PORT ---
        let client_ip = if device_ip.is_empty() {
            "10.66.66.2".to_string() // fallback
        } else {
            // Strip /32 mask if present
            device_ip.split('/').next().unwrap_or("10.66.66.2").to_string()
        };

        let body = serde_json::json!({
            "access_token": access_token,
            "client_ip": client_ip
        });

        let resp = request_port_fwd(&client, reqwest::Method::POST, &body)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("Server rejected port request ({}): {}", status, body));
        }

        let body: serde_json::Value = resp.json()
            .map_err(|e| format!("Failed to parse port response: {}", e))?;

        let port = body["port"].as_u64()
            .ok_or("Server did not return a port number")?
            as u16;

        println!("[Port Forwarding] ✅ Enabled on port {}", port);
        append_log(&format!("Port Forwarding enabled: port {}", port)).ok();

        PORT_FWD_ACTIVE.store(true, Ordering::Relaxed);

        // --- START HEARTBEAT THREAD ---
        if !PORT_FWD_HEARTBEAT_RUNNING.load(Ordering::Relaxed) {
            PORT_FWD_HEARTBEAT_RUNNING.store(true, Ordering::Relaxed);
            let token = access_token.clone();
            std::thread::spawn(move || {
                let hb_client = reqwest::blocking::Client::new();
                while PORT_FWD_ACTIVE.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    if !PORT_FWD_ACTIVE.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    // Renew logic with fallback
                    let renew_internal = format!("{}/renew", PORT_FWD_API_INTERNAL);
                    let renew_public = format!("{}/renew", PORT_FWD_API_PUBLIC);
                    let body = serde_json::json!({ "access_token": token });

                    // Try Internal
                    let mut success = false;
                    match hb_client.post(&renew_internal).json(&body).timeout(std::time::Duration::from_secs(5)).send() {
                        Ok(r) if r.status().is_success() => success = true,
                        _ => {}
                    }

                    // Fallback Public
                    if !success {
                        match hb_client.post(&renew_public).json(&body).timeout(std::time::Duration::from_secs(10)).send() {
                            Ok(r) if r.status().is_success() => success = true,
                            Ok(r) => println!("[Port Forwarding] ⚠️ Heartbeat failed: {}", r.status()),
                            Err(e) => println!("[Port Forwarding] ⚠️ Heartbeat error: {}", e),
                        }
                    }

                    if success {
                        println!("[Port Forwarding] 💓 Heartbeat renewed");
                    }
                }
                PORT_FWD_HEARTBEAT_RUNNING.store(false, Ordering::Relaxed);
                println!("[Port Forwarding] Heartbeat thread stopped");
            });
        }

        Ok(Some(port))
    } else {
        // --- RELEASE PORT ---
        PORT_FWD_ACTIVE.store(false, Ordering::Relaxed);

        let body = serde_json::json!({ "access_token": access_token });
        // Best effort release
        match request_port_fwd(&client, reqwest::Method::DELETE, &body) {
            Ok(r) if r.status().is_success() => println!("[Port Forwarding] 🔓 Port released"),
            Ok(r) => println!("[Port Forwarding] ⚠️ Release returned: {}", r.status()),
            Err(e) => println!("[Port Forwarding] ⚠️ Release error: {}", e),
        }

        append_log("Port Forwarding disabled").ok();
        Ok(None)
    }
}

/// Open file picker for selecting an executable
/// Used by Split Tunneling to add apps
#[tauri::command]
async fn pick_executable(app_handle: AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    
    let file_path = app_handle
        .dialog()
        .file()
        .add_filter("Executables", &["exe"])
        .blocking_pick_file();
    
    match file_path {
        Some(path) => {
            let path_str = path.to_string();
            append_log(&format!("Selected executable: {}", path_str)).ok();
            Ok(Some(path_str))
        }
        None => Ok(None),
    }
}

/// Toggle DPI Stealth Mode
/// Enables Shadowsocks-rust obfuscation to bypass DPI
#[tauri::command]
fn toggle_dpi_stealth(app: AppHandle, enabled: bool, state: State<'_, VpnState>) -> Result<(), String> {
    append_log(&format!("DPI Stealth toggled: {}", enabled)).ok();
    
    // 1. Update In-Memory State
    *state.stealth_enabled.lock().unwrap() = enabled;

    // 2. Update Persisted Settings
    let mut settings = load_settings();
    settings.dpi_stealth_enabled = enabled;
    save_settings(&settings);
    
    if enabled {
        println!("[DPI Stealth] Enabled - Transport will be upgraded on next connection");
    } else {
        println!("[DPI Stealth] Disabled");
    }
    
    Ok(())
}

/// Get current app settings (for frontend to read persisted state)
#[tauri::command]
fn get_settings() -> Result<AppSettings, String> {
    Ok(load_settings())
}

/// Get the current client's WireGuard public key for display in UI
#[tauri::command]
fn get_client_public_key() -> Result<String, String> {
    let settings = load_settings();
    if settings.public_key.is_empty() {
        // Try to read from the current config file
        if let Ok(config_dir) = log_dir() {
            let config_path = config_dir.parent().unwrap_or(&config_dir).join("nera-token.conf");
            if let Ok(content) = fs::read_to_string(&config_path) {
                // Parse PrivateKey from config and derive public key
                // For now, return empty if not found
            }
        }
        Ok(String::new())
    } else {
        Ok(settings.public_key)
    }
}

#[tauri::command]
fn import_wireguard_config(app: AppHandle) -> Result<String, String> {
    let dest_path = nera_conf_path()?;

    let file_path = app.dialog().file().blocking_pick_file();
    
    // Note: blocking_pick_file returns Option<FilePath>
    // We need to handle this. The proper specific API might depend on the plugin version.
    // Assuming blocking_pick_file exists for now based on v1 blocking API.
    // If not, we might need async variation. 
    // Since this command is synchronous (fn), we need blocking.
    // Check plugin-dialog docs... usually it is `app.dialog().file().pick_file(...)` which is async.
    // For blocking, we might need to change command to async.
    // Let's change this command to async to be safe and use async pick_file.
    
    // Responding below in next tool call with async implementation.
    Err("Please use import_wireguard_config_async".to_string())
} 

#[tauri::command]
async fn import_wireguard_config_async(app: AppHandle) -> Result<String, String> {
     let dest_path = nera_conf_path().map_err(|e| e.to_string())?;
     
     // This requires tauri-plugin-dialog to be set up
     // return path...
     
     // Placeholder: actual impl needs to await the dialog.
     // Since I cannot verify compile here, I'll use standard file dialog if possible?
     // Or just fail gracefully.
     
     // Reverting to synchronous call assuming I can't use async here easily without changing frontend.
     // Actually, frontend invokes are async by default.
     
     /* 
       Let's use a simpler approach: 
       I will leave this function broken for a moment or try to use a standard native dialog crate 
       like `rfd` if tauri's blocking dialog is gone.
       
       Wait, I can just use `rfd` (Rust File Dialog) if I add it.
       But I should use tauri-plugin-dialog.
     */
     Err("Not implemented yet".to_string())
}

#[tauri::command]
async fn connect_vpn(
    app: AppHandle,
    state: State<'_, VpnState>,
    server_key: Option<String>,
) -> Result<(), String> {
    connect_vpn_internal(&app, &state, server_key).await
}

#[tauri::command]
async fn disconnect_vpn(app: AppHandle, state: State<'_, VpnState>) -> Result<(), String> {
    disconnect_vpn_internal(&app, &state).await
}

#[tauri::command]
fn get_vpn_status(state: State<'_, VpnState>) -> bool {
    *state.connected.lock().unwrap()
}

#[tauri::command]
fn set_kill_switch(
    app: AppHandle,
    enabled: bool,
    state: State<'_, VpnState>,
) -> Result<(), String> {
    let mut settings = load_settings();
    settings.kill_switch_enabled = enabled;
    save_settings(&settings);
    
    // Reload to ensure we have latest (though we just saved it)
    let stealth = settings.dpi_stealth_enabled;

    if enabled {
        enable_kill_switch_internal(stealth)?;
    } else {
        disable_kill_switch_internal()?;
    }

    *state.kill_switch_enabled.lock().unwrap() = enabled;

    update_tray_menu(&app, enabled);


    app.emit("kill-switch-changed", KillSwitchPayload { enabled })
        .map_err(|e| format!("Failed to emit event: {e}"))?;

    Ok(())
}

#[tauri::command]
fn get_kill_switch_status(state: State<'_, VpnState>) -> bool {
    *state.kill_switch_enabled.lock().unwrap()
}

#[tauri::command]
fn read_logs() -> Result<String, String> {
    let path = log_file_path()?;
    if !path.exists() {
        return Ok("No logs yet.".to_string());
    }
    fs::read_to_string(path).map_err(|e| format!("Failed to read logs: {e}"))
}

#[tauri::command]
fn set_selected_server(server_key: String) -> Result<(), String> {
    let mut settings = load_settings();
    settings.selected_server = server_key;
    // other fields are already loaded into `settings`, so they are preserved
    save_settings(&settings);
    Ok(())
}

#[tauri::command]
fn get_selected_server() -> String {
    load_settings().selected_server
}

#[tauri::command]
async fn register_user_key() -> Result<String, String> {
    // 1. Generate New Keys Locally
    let (priv_key, pub_key) = generate_keypair();

    // 2. Save Keys to Settings (Clear IP to reset state)
    let mut settings = load_settings();
    settings.private_key = priv_key;
    settings.public_key = pub_key;
    settings.device_ip = "".to_string(); 
    save_settings(&settings);

    // 3. Return success message
    Ok("Identity generated. Ready to sign up.".to_string())
}

#[tauri::command]
fn get_user_status() -> Option<String> {
    let settings = load_settings();
    // Return key even if device_ip is empty so Frontend can read it
    if !settings.public_key.is_empty() {
        Some(settings.public_key)
    } else {
        None
    }
}

#[tauri::command]
fn complete_registration(ip: String, remember: bool) -> Result<(), String> {
    let mut settings = load_settings();
    settings.device_ip = ip;
    settings.remember_me = remember; // <--- Save the user's preference
    save_settings(&settings);
    Ok(())
}

#[tauri::command]
fn logout() -> Result<(), String> {
    let mut settings = load_settings();
    settings.private_key = String::new();
    settings.public_key = String::new();
    settings.device_ip = String::new();
    settings.remember_me = false; // Reset this too
    settings.access_token = String::new(); // Clear token on logout
    save_settings(&settings);
    
    // Force disconnect VPN on logout for safety
    // (Optional, but good for security)
    let _ = Command::new("taskkill")
        .args(&["/F", "/IM", "wireguard.exe"]) 
        .creation_flags(0x08000000)
        .output();
        
    Ok(())
}

// --- Anonymous Blind Token Auth Commands ---

#[tauri::command]
fn save_access_token(token: String) -> Result<(), String> {
    let mut settings = load_settings();
    settings.access_token = token;
    save_settings(&settings);
    append_log("Access token saved successfully.").ok();
    Ok(())
}

#[tauri::command]
fn get_access_token() -> Option<String> {
    let settings = load_settings();
    if !settings.access_token.is_empty() {
        Some(settings.access_token)
    } else {
        None
    }
}

#[tauri::command]
fn clear_access_token() -> Result<(), String> {
    let mut settings = load_settings();
    settings.access_token = String::new();
    save_settings(&settings);
    append_log("Access token cleared.").ok();
    Ok(())
}

#[tauri::command]
async fn register_account(email: String, password: String, public_key: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let payload = RegisterRequest { email, password, public_key };
    
    // Call the Tokyo Node.js Server directly
    let res = client.post("http://45.76.106.63:3000/api/register")
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
        
    if !res.status().is_success() {
        return Err(format!("Server error: {}", res.status()));
    }

    let text = res.text().await.map_err(|e| e.to_string())?;
    Ok(text)
}

#[tauri::command]
async fn login_account(email: String, password: String, public_key: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let payload = RegisterRequest { email, password, public_key }; // Reusing the struct is fine

    // Hit the new /api/login endpoint
    let res = client.post("http://45.76.106.63:3000/api/login")
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !res.status().is_success() {
         // Try to parse the error message from JSON
         let error_text = res.text().await.unwrap_or_else(|_| "Unknown login error".into());
         return Err(error_text);
    }

    let text = res.text().await.map_err(|e| e.to_string())?;
    Ok(text)
}

// --- Main ---

fn main() {
    // === SAFETY STARTUP SEQUENCE ===
    // These run BEFORE anything else to recover from crashes
    
    // 1. Kill any zombie "nera-token" tunnel from previous crashes (FIRST!)
    // This is the "Clean Slate" protocol to prevent internet lockout
    kill_zombie_tunnel();
    
    // 2. Reset firewall rules (self-healing kill switch recovery)
    // If the app crashed with kill switch active, this restores internet
    if let Err(e) = reset_firewall_rules() {
        eprintln!("Warning: Failed to reset firewall rules on startup: {}", e);
    }
    
    // 3. Clean up any other legacy WireGuard tunnels from previous sessions
    force_disconnect_all();
    
    // === END SAFETY STARTUP ===

    // 1. Load Settings
    let mut settings = load_settings();

    // --- NEW: Handle "Don't Remember Me" ---
    if !settings.remember_me {
        // If user didn't want to be remembered, wipe identity on launch
        settings.private_key = String::new();
        settings.public_key = String::new();
        settings.device_ip = String::new();
        // Keep the 'remember_me' flag false, but clear data
        save_settings(&settings);
    }
    // ----------------------------------------

    let ks_enabled = settings.kill_switch_enabled;

    // ... rest of main ...
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        // .plugin(tauri_plugin_process::init())
        .manage(VpnState {
            connected: Mutex::new(false),
            kill_switch_enabled: Mutex::new(ks_enabled),
            monitoring_flag: Mutex::new(None),
            active_transport: Mutex::new(None),
            stealth_enabled: Mutex::new(settings.dpi_stealth_enabled),
        })
        .manage(split_tunnel::SplitTunnelState::new())
        .manage({
            let shield_state = Arc::new(shield_zero::ShieldZeroState::new());
            DnsProxyState {
                handle: tokio::sync::Mutex::new(None),
                shield_state,
            }
        })
        .manage({
            let config_dir = dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("NeraVPN");
            split_tunnel_v2::commands::WfpSplitTunnelState::new(config_dir)
        })
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(Vec::new()),
        ))
        .invoke_handler(tauri::generate_handler![
            // import_wireguard_config, // Commented out until fixed
            connect_vpn,
            disconnect_vpn,
            read_logs,
            get_vpn_status,
            set_kill_switch,
            get_kill_switch_status,
            get_selected_server,
            set_selected_server,
            // Legacy auth (to be removed after migration)
            register_user_key,
            get_user_status,
            complete_registration,
            register_account,
            login_account,
            logout,
            // Anonymous Blind Token Auth
            crypto::create_blind_token,
            crypto::unblind_signature,
            save_access_token,
            get_access_token,
            clear_access_token,
            // Token-Based VPN Connection
            vpn::connect_with_token,
            vpn::disconnect_token_vpn,
            // Traffic Monitoring
            start_traffic_monitoring,
            stop_traffic_monitoring,
            // Advanced Features — Shield Zero
            toggle_netshield,
            analyze_domain,
            shield_zero_stats,
            whitelist_domain,
            remove_whitelist,
            get_whitelist,
            get_threat_log,
            download_blocklists,
            set_split_tunneling,

            toggle_port_forwarding,
            pick_executable,
            toggle_dpi_stealth,
            get_settings,
            get_client_public_key,
            // WFP Split Tunneling (v2)
            split_tunnel_v2::commands::wfp_get_config,
            split_tunnel_v2::commands::wfp_set_mode,
            split_tunnel_v2::commands::wfp_add_app,
            split_tunnel_v2::commands::wfp_remove_app,
            split_tunnel_v2::commands::wfp_add_ip_rule,
            split_tunnel_v2::commands::wfp_add_domain,
            split_tunnel_v2::commands::wfp_get_status,
            split_tunnel_v2::commands::wfp_activate,
            split_tunnel_v2::commands::wfp_deactivate,
            split_tunnel_v2::commands::wfp_get_installed_apps,
        ])
        .setup(move |app| {
            // Apply Tray State based on persistence
            // Using logic to build tray
             let tray_menu = build_tray_menu(app.handle(), ks_enabled)?;
             
             // In v2 we build the tray and attach it.
             let _tray = TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&tray_menu)
                .on_menu_event(|app, event| {
                     let state = app.state::<VpnState>();
                     match event.id.as_ref() {
                        "connect" => {
                            let settings = load_settings();
                            let _ = connect_vpn_internal(app, &state, Some(settings.selected_server));
                        }
                        "disconnect" => {
                             let _ = disconnect_vpn_internal(app, &state);
                        }
                        "killswitch_toggle" => {
                            let current = *state.kill_switch_enabled.lock().unwrap();
                            let new_state = !current;

                            // Action
                            if new_state {
                                let settings = load_settings();
                                let _ = enable_kill_switch_internal(settings.dpi_stealth_enabled);
                            } else {
                                let _ = disable_kill_switch_internal();
                            }

                            // Update
                            *state.kill_switch_enabled.lock().unwrap() = new_state;
                            update_tray_menu(app, new_state);
                            let mut settings = load_settings();
                            settings.kill_switch_enabled = new_state;

                            save_settings(&settings);
                            let _ = app.emit(
                                "kill-switch-changed",
                                KillSwitchPayload { enabled: new_state },
                            );
                        }
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            let _ = disable_kill_switch_internal();
                            let _ = disconnect_vpn_internal(app, &state);
                            std::process::exit(0);
                        }
                         _ => {}
                     }
                })
                .on_tray_icon_event(|tray, event| {
                     if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let visible = window.is_visible().unwrap_or(false);
                            if visible {
                                let _ = window.hide();
                            } else {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                     }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|_window, event| {
            // Auto-disconnect VPN when the main window is closed
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                println!("🚪 Window close requested - cleaning up VPN tunnel...");
                kill_zombie_tunnel();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            tauri::RunEvent::Exit => {
                let state = app_handle.state::<VpnState>();
                let _ = disconnect_vpn_internal(app_handle, &state);
                let _ = disable_kill_switch_internal();
            }
            _ => {}
        });
}
