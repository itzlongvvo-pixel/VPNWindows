//! Split Tunnel Manager — orchestrates all split tunnel components.
//!
//! This module provides a unified interface for managing split tunneling,
//! coordinating between route manipulation (Table=off + exclusion routes),
//! WinDivert FLOW-based PID detection, and WFP app identification.

pub mod types;
pub mod route_manager;
pub mod wfp_manager;
pub mod dns_resolver;
pub mod process_scanner;
pub mod commands;

use self::dns_resolver::DnsResolver;
use self::process_scanner::ProcessScanner;
use self::route_manager::RouteManager;
use self::types::*;
use self::wfp_manager::WfpManager;

use std::collections::{HashSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use sysinfo::{System, ProcessRefreshKind, Pid, UpdateKind};
use windivert::prelude::*;

/// Delay before applying route changes (debounce) — 15 seconds
const IP_COLLECTION_WINDOW_MS: u64 = 15000;

/// Max /24 networks to exclude (prevent route table explosion)
const MAX_EXCLUDED_NETWORKS: usize = 30;

pub struct SplitTunnelManager {
    config: RwLock<SplitTunnelConfig>,
    route_mgr: RouteManager,
    wfp_mgr: WfpManager,
    dns_resolver: Option<DnsResolver>,
    process_scanner: ProcessScanner,
    is_active: RwLock<bool>,
    /// Path to persist config
    config_path: PathBuf,
    /// WireGuard config file path
    wg_config_path: PathBuf,
    /// Thread control flags
    flow_tracker_flag: RwLock<Option<Arc<AtomicBool>>>,
    pid_watcher_flag: RwLock<Option<Arc<AtomicBool>>>,
    /// Active PIDs of excluded apps
    active_pids: Arc<RwLock<HashSet<u32>>>,
    /// Excluded /24 networks (already routed via physical gateway)
    excluded_networks: Arc<RwLock<HashSet<std::net::Ipv4Addr>>>,
    /// Pending networks (debounce buffer)
    pending_networks: Arc<RwLock<HashSet<std::net::Ipv4Addr>>>,
    /// Last IP addition time (for debounce)
    last_update: Arc<RwLock<Instant>>,
}

impl SplitTunnelManager {
    pub fn new(config_dir: PathBuf) -> Result<Self, SplitTunnelError> {
        // Ensure config directory exists
        if !config_dir.exists() {
            std::fs::create_dir_all(&config_dir)
                .map_err(|e| SplitTunnelError::ConfigError(
                    format!("Failed to create config dir: {e}")
                ))?;
        }

        let config_path = config_dir.join("split_tunnel_v2.json");

        // WireGuard config path
        let wg_config_path = dirs::document_dir()
            .unwrap_or(PathBuf::from("."))
            .join("NeraVPN")
            .join("nera-token.conf");

        // Load persisted config or use defaults
        let config = if config_path.exists() {
            let data = std::fs::read_to_string(&config_path)
                .map_err(|e| SplitTunnelError::ConfigError(e.to_string()))?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            SplitTunnelConfig::default()
        };

        // DNS resolver is optional (may fail to initialize)
        let dns_resolver = DnsResolver::new().ok();

        info!("SplitTunnelManager initialized with config: {:?}", config.mode);

        Ok(Self {
            config: RwLock::new(config),
            route_mgr: RouteManager::new(),
            wfp_mgr: WfpManager::new(),
            dns_resolver,
            process_scanner: ProcessScanner::new(),
            is_active: RwLock::new(false),
            config_path,
            wg_config_path,
            flow_tracker_flag: RwLock::new(None),
            pid_watcher_flag: RwLock::new(None),
            active_pids: Arc::new(RwLock::new(HashSet::new())),
            excluded_networks: Arc::new(RwLock::new(HashSet::new())),
            pending_networks: Arc::new(RwLock::new(HashSet::new())),
            last_update: Arc::new(RwLock::new(Instant::now())),
        })
    }

    // ─── Activation ─────────────────────────────────────────

    /// Activate split tunneling. Call AFTER VPN connection is established.
    /// This modifies WG config (Table=off), restarts tunnel, sets up manual routes,
    /// and starts WinDivert FLOW-based PID tracking for app-based bypass.
    pub fn activate(&self) -> Result<SplitTunnelStatus, SplitTunnelError> {
        let config = self.config.read().unwrap().clone();

        if config.mode == SplitTunnelMode::Disabled {
            info!("Split tunnel is disabled — nothing to activate");
            return self.get_status();
        }

        info!("═══════════════════════════════════════════════════════");
        info!("Activating split tunnel in {:?} mode", config.mode);
        info!("═══════════════════════════════════════════════════════");

        // NOTE: Table=off is now injected into WG config at VPN connect time (vpn.rs)
        // No tunnel restart needed here — just add manual routes and start monitoring

        // 1. Add VPN default route manually (since Table=off prevents auto-routes)
        info!("Step 1: Adding VPN default route (metric 5)...");
        self.route_mgr.add_vpn_default_route(&self.wg_config_path)?;

        // 4. Collect app paths from config for PID detection
        let app_paths: Vec<String> = config.rules.iter().filter_map(|rule| {
            if let SplitRule::App(app) = rule {
                Some(app.exe_path.to_string_lossy().to_string())
            } else {
                None
            }
        }).collect();

        if !app_paths.is_empty() {
            info!("Step 4: Starting app monitoring for {} apps: {:?}", app_paths.len(), app_paths);

            // 5. Start PID watcher thread
            self.start_pid_watcher(app_paths.clone())?;

            // 6. Start WinDivert FLOW tracker for PID-based IP detection
            self.start_flow_tracker()?;
        } else {
            info!("No app rules configured, skipping PID/FLOW tracking");
        }

        *self.is_active.write().unwrap() = true;
        info!("Split tunnel activated successfully!");

        self.get_status()
    }

    /// Deactivate split tunneling and clean up everything
    pub fn deactivate(&self) -> Result<(), SplitTunnelError> {
        info!("Deactivating split tunnel...");

        // Stop background threads
        if let Some(flag) = self.flow_tracker_flag.write().unwrap().take() {
            flag.store(false, Ordering::Relaxed);
        }
        if let Some(flag) = self.pid_watcher_flag.write().unwrap().take() {
            flag.store(false, Ordering::Relaxed);
        }

        // Remove all WFP filters
        if let Err(e) = self.wfp_mgr.remove_all_filters() {
            warn!("WFP filter cleanup error: {e}");
        }
        if let Err(e) = self.wfp_mgr.shutdown() {
            warn!("WFP shutdown error: {e}");
        }

        // Remove all routes we added
        if let Err(e) = self.route_mgr.remove_all_routes() {
            warn!("Route cleanup error: {e}");
        }

        // Remove exclusion routes
        {
            let networks: Vec<_> = self.excluded_networks.write().unwrap().drain().collect();
            for network in &networks {
                let _ = self.route_mgr.remove_exclusion_route(network);
            }
            self.pending_networks.write().unwrap().clear();
        }

        // NOTE: Table=off cleanup happens naturally when VPN disconnects and reconnects
        // without split tunnel — vpn.rs generates fresh config each time

        // Clear state
        self.active_pids.write().unwrap().clear();

        *self.is_active.write().unwrap() = false;
        info!("Split tunnel deactivated");

        Ok(())
    }

    // ─── PID Watcher ────────────────────────────────────────

    /// Start a thread that continuously scans for PIDs of excluded apps
    fn start_pid_watcher(&self, app_paths: Vec<String>) -> Result<(), SplitTunnelError> {
        let flag = Arc::new(AtomicBool::new(true));
        *self.pid_watcher_flag.write().unwrap() = Some(flag.clone());

        let active_pids = self.active_pids.clone();

        thread::spawn(move || {
            info!("PID watcher thread started");
            let mut system = System::new();

            while flag.load(Ordering::Relaxed) {
                // Refresh process list with exe paths
                system.refresh_processes_specifics(
                    ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet)
                );

                let mut current_pids = HashSet::new();

                for (pid, process) in system.processes() {
                    if pid.as_u32() <= 4 { continue; }

                    if let Some(exe_path) = process.exe() {
                        let path_str = exe_path.to_string_lossy().to_lowercase();
                        if path_str.len() < 5 { continue; }

                        let is_excluded = app_paths.iter().any(|app_path| {
                            let app_lower = app_path.to_lowercase();
                            !app_lower.is_empty() && path_str.contains(&app_lower)
                        });

                        if is_excluded {
                            current_pids.insert(pid.as_u32());
                        }
                    }
                }

                // Update shared state
                {
                    let mut pids = active_pids.write().unwrap();
                    let old_count = pids.len();
                    *pids = current_pids;
                    if pids.len() != old_count {
                        info!("Active excluded PIDs: {} → {}", old_count, pids.len());
                    }
                }

                thread::sleep(Duration::from_secs(2));
            }
            info!("PID watcher thread stopped");
        });

        Ok(())
    }

    // ─── WinDivert FLOW Tracker ─────────────────────────────

    /// Start WinDivert FLOW layer to detect connections from excluded apps
    /// When a bypassed app connects to an IP, we add a /24 exclusion route
    /// via the physical gateway (metric 1 beats VPN's metric 5)
    fn start_flow_tracker(&self) -> Result<(), SplitTunnelError> {
        let flag = Arc::new(AtomicBool::new(true));
        *self.flow_tracker_flag.write().unwrap() = Some(flag.clone());

        let active_pids = self.active_pids.clone();
        let excluded_networks = self.excluded_networks.clone();
        let pending_networks = self.pending_networks.clone();
        let last_update = self.last_update.clone();
        let route_mgr_gateway = self.route_mgr.detect_physical_gateway();

        let gateway = match route_mgr_gateway {
            Some(gw) => gw,
            None => {
                return Err(SplitTunnelError::RouteError(
                    "Could not detect physical gateway for split tunnel".into()
                ));
            }
        };

        info!("Starting FLOW tracker with physical gateway: {gateway}");

        thread::spawn(move || {
            info!("WinDivert FLOW tracker thread started");

            // FLOW layer filter: capture all flow events
            let filter = "true";
            let flags = WinDivertFlags::new().set_sniff().set_recv_only();

            match WinDivert::flow(filter, 0, flags) {
                Ok(handle) => {
                    info!("WinDivert FLOW handle opened successfully");

                    while flag.load(Ordering::Relaxed) {
                        // Check debounce — apply pending exclusions
                        {
                            let can_commit = {
                                let lu = last_update.read().unwrap();
                                lu.elapsed() > Duration::from_millis(IP_COLLECTION_WINDOW_MS)
                            };

                            let has_pending = !pending_networks.read().unwrap().is_empty();

                            if has_pending && can_commit {
                                let networks_to_add: Vec<_> = pending_networks.write().unwrap().drain().collect();
                                let count = networks_to_add.len();

                                for network in networks_to_add {
                                    // Add exclusion route via physical gateway
                                    let net_str = network.to_string();
                                    #[cfg(windows)]
                                    {
                                        use std::os::windows::process::CommandExt;
                                        const CREATE_NO_WINDOW: u32 = 0x08000000;

                                        let _ = std::process::Command::new("route")
                                            .args(["add", &net_str, "mask", "255.255.255.0", &gateway, "metric", "1"])
                                            .creation_flags(CREATE_NO_WINDOW)
                                            .output();
                                    }

                                    excluded_networks.write().unwrap().insert(network);
                                    info!("Applied exclusion route: {net_str}/24 via {gateway}");
                                }

                                info!("Applied {count} new exclusion routes (Total: {} networks excluded)",
                                    excluded_networks.read().unwrap().len());
                            }
                        }

                        // Receive flow events
                        match handle.recv(None) {
                            Ok(packet) => {
                                let flow_addr = &packet.address;
                                let event = flow_addr.event();

                                match event {
                                    WinDivertEvent::FlowStablished => {
                                        let pid = flow_addr.process_id();
                                        let dst_ip = flow_addr.remote_address();

                                        // Check if this PID belongs to an excluded app
                                        let is_excluded = active_pids.read().unwrap().contains(&pid);

                                        if is_excluded {
                                            // Convert to /24 network and add to pending
                                            if let IpAddr::V4(ipv4) = dst_ip {
                                                if !ipv4.is_loopback() && !ipv4.is_private() && !ipv4.is_multicast() {
                                                    let octets = ipv4.octets();
                                                    let network = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 0);

                                                    let already_excluded = excluded_networks.read().unwrap().contains(&network);
                                                    let already_pending = pending_networks.read().unwrap().contains(&network);

                                                    if !already_excluded && !already_pending {
                                                        let total = excluded_networks.read().unwrap().len()
                                                            + pending_networks.read().unwrap().len();

                                                        if total < MAX_EXCLUDED_NETWORKS {
                                                            pending_networks.write().unwrap().insert(network);
                                                            *last_update.write().unwrap() = Instant::now();
                                                            info!("New /24 network detected: {}/24 (from IP: {}, PID: {})",
                                                                network, dst_ip, pid);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Err(e) => {
                                warn!("FLOW recv error: {:?}", e);
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to open WinDivert FLOW handle: {e}");
                    error!("App-based split tunnel will NOT work without WinDivert!");
                }
            }

            info!("WinDivert FLOW tracker thread stopped");
        });

        Ok(())
    }

    // ─── Configuration ──────────────────────────────────────

    pub fn get_config(&self) -> SplitTunnelConfig {
        self.config.read().unwrap().clone()
    }

    pub fn set_config(&self, config: SplitTunnelConfig) -> Result<(), SplitTunnelError> {
        let was_active = *self.is_active.read().unwrap();

        // If active, deactivate first
        if was_active {
            self.deactivate()?;
        }

        // Persist config
        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| SplitTunnelError::ConfigError(e.to_string()))?;
        std::fs::write(&self.config_path, json)
            .map_err(|e| SplitTunnelError::ConfigError(e.to_string()))?;

        *self.config.write().unwrap() = config;

        // Re-activate if it was active
        if was_active {
            self.activate()?;
        }

        Ok(())
    }

    pub fn set_mode(&self, mode: SplitTunnelMode) -> Result<(), SplitTunnelError> {
        let mut config = self.config.read().unwrap().clone();
        config.mode = mode;
        self.set_config(config)
    }

    pub fn add_rule(&self, rule: SplitRule) -> Result<(), SplitTunnelError> {
        let mut config = self.config.read().unwrap().clone();
        if !config.rules.contains(&rule) {
            config.rules.push(rule);
            self.set_config(config)?;
        }
        Ok(())
    }

    pub fn remove_rule(&self, rule: &SplitRule) -> Result<(), SplitTunnelError> {
        let mut config = self.config.read().unwrap().clone();
        config.rules.retain(|r| r != rule);
        self.set_config(config)
    }

    // ─── Status ─────────────────────────────────────────────

    pub fn get_status(&self) -> Result<SplitTunnelStatus, SplitTunnelError> {
        let config = self.config.read().unwrap();
        let is_active = *self.is_active.read().unwrap();

        let monitored_apps: Vec<MonitoredApp> = config
            .rules
            .iter()
            .filter_map(|rule| {
                if let SplitRule::App(app) = rule {
                    let pids = self.process_scanner.find_pids_for_app(&app.exe_path);
                    Some(MonitoredApp {
                        name: app.name.clone(),
                        exe_path: app.exe_path.to_string_lossy().to_string(),
                        active_pids: pids.clone(),
                        is_running: !pids.is_empty(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(SplitTunnelStatus {
            mode: config.mode.clone(),
            active_rules: config.rules.len(),
            resolved_ips: self.excluded_networks.read().unwrap().len(),
            monitored_apps,
            is_active,
        })
    }

    // ─── App Discovery ──────────────────────────────────────

    pub fn get_installed_apps(&self) -> Result<Vec<InstalledApp>, SplitTunnelError> {
        self.process_scanner.get_installed_apps()
    }
}
