//! Split Tunnel Types & Configuration
//!
//! Shared types for the WFP-based split tunneling system.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

// ─── Split Tunnel Mode ───────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelMode {
    /// All traffic through VPN (split tunnel disabled)
    #[default]
    Disabled,
    /// Everything through VPN EXCEPT listed rules (exclude mode)
    Bypass,
    /// ONLY listed rules through VPN (include / inverse mode)
    Proxy,
}

// ─── Rule Types ──────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "value")]
pub enum SplitRule {
    /// Single IP address
    Ip(IpAddr),
    /// CIDR range e.g. "192.168.1.0/24"
    Cidr(String),
    /// Domain name — resolved to IPs at connect time
    Domain(String),
    /// Application by executable path
    App(AppRule),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AppRule {
    pub name: String,
    pub exe_path: PathBuf,
}

// ─── Resolved state (what actually gets applied) ─────────────
#[derive(Debug, Clone, Default)]
pub struct ResolvedRules {
    /// IP/CIDR ranges to route outside the tunnel (Bypass) or inside (Proxy)
    pub ip_ranges: Vec<ipnet::IpNet>,
    /// App executable paths whose traffic gets special routing
    pub app_paths: Vec<PathBuf>,
    /// Domain → resolved IPs mapping
    pub domain_map: dashmap::DashMap<String, Vec<IpAddr>>,
}

// ─── Persisted Configuration ─────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SplitTunnelConfig {
    pub mode: SplitTunnelMode,
    pub rules: Vec<SplitRule>,
    /// Re-resolve domains every N seconds (default 300)
    #[serde(default = "default_dns_interval")]
    pub dns_refresh_interval_secs: u64,
    /// Allow LAN access when in full-tunnel mode
    #[serde(default = "default_true")]
    pub allow_lan: bool,
}

fn default_dns_interval() -> u64 { 300 }
fn default_true() -> bool { true }

// ─── Status reporting to frontend ────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitTunnelStatus {
    pub mode: SplitTunnelMode,
    pub active_rules: usize,
    pub resolved_ips: usize,
    pub monitored_apps: Vec<MonitoredApp>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredApp {
    pub name: String,
    pub exe_path: String,
    pub active_pids: Vec<u32>,
    pub is_running: bool,
}

// ─── App discovery for the picker ────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub exe_path: String,
    pub icon_path: Option<String>,
    pub publisher: Option<String>,
}

// ─── Errors ──────────────────────────────────────────────────
#[derive(Debug)]
pub enum SplitTunnelError {
    WfpError(String),
    RouteError(String),
    DnsError(String),
    InvalidCidr(String),
    ProcessError(String),
    ConfigError(String),
    OsError { code: u32, message: String },
    NotActive,
}

impl std::fmt::Display for SplitTunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WfpError(s) => write!(f, "WFP engine error: {}", s),
            Self::RouteError(s) => write!(f, "Route table error: {}", s),
            Self::DnsError(s) => write!(f, "DNS resolution error: {}", s),
            Self::InvalidCidr(s) => write!(f, "Invalid CIDR notation: {}", s),
            Self::ProcessError(s) => write!(f, "Process scan error: {}", s),
            Self::ConfigError(s) => write!(f, "Configuration error: {}", s),
            Self::OsError { code, message } => write!(f, "OS error: {} — {}", code, message),
            Self::NotActive => write!(f, "Split tunnel not active"),
        }
    }
}

impl std::error::Error for SplitTunnelError {}

impl Serialize for SplitTunnelError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
