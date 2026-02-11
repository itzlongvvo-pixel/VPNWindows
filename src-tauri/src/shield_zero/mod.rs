pub mod dga;
pub mod dns_proxy;
pub mod blocklist;

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use dga::{DgaDetector, DgaResult, DgaVerdict};

// ─── Serializable types for Tauri IPC ────────────────────────────────

/// JSON-serializable verdict for the frontend.
#[derive(serde::Serialize, Clone, Debug)]
pub struct DomainAnalysis {
    pub domain: String,
    pub score: f64,
    pub verdict: String,
    pub blocked: bool,
    pub whitelisted: bool,
    pub features: FeatureBreakdown,
}

/// JSON-serializable feature breakdown.
#[derive(serde::Serialize, Clone, Debug)]
pub struct FeatureBreakdown {
    pub entropy: f64,
    pub consonant_cluster: f64,
    pub vowel_ratio: f64,
    pub digit_ratio: f64,
    pub domain_length: f64,
    pub bigram_score: f64,
}

impl From<DgaResult> for DomainAnalysis {
    fn from(r: DgaResult) -> Self {
        let verdict_str = match &r.verdict {
            DgaVerdict::Clean => "clean",
            DgaVerdict::Suspicious => "suspicious",
            DgaVerdict::Malicious => "malicious",
        };
        Self {
            domain: r.domain.clone(),
            score: r.score,
            verdict: verdict_str.to_string(),
            blocked: r.verdict == DgaVerdict::Malicious,
            whitelisted: false,
            features: FeatureBreakdown {
                entropy: r.features.entropy,
                consonant_cluster: r.features.consonant_cluster,
                vowel_ratio: r.features.vowel_ratio,
                digit_ratio: r.features.digit_ratio,
                domain_length: r.features.domain_length,
                bigram_score: r.features.bigram_score,
            },
        }
    }
}

// ─── Persistent Telemetry ────────────────────────────────────────────

/// Telemetry data persisted to disk across sessions.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct TelemetryData {
    pub total_scanned: u64,
    pub total_blocked: u64,
    pub total_whitelisted_overrides: u64,
}

impl TelemetryData {
    fn load(config_dir: &PathBuf) -> Self {
        let path = config_dir.join("shield_zero_telemetry.json");
        if let Ok(data) = fs::read_to_string(&path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self, config_dir: &PathBuf) {
        let path = config_dir.join("shield_zero_telemetry.json");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::create_dir_all(config_dir);
            let _ = fs::write(path, json);
        }
    }
}

// ─── Whitelist ───────────────────────────────────────────────────────

/// Load whitelist from disk.
fn load_whitelist(config_dir: &PathBuf) -> HashSet<String> {
    let path = config_dir.join("whitelist.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashSet::new()
    }
}

/// Save whitelist to disk.
fn save_whitelist(config_dir: &PathBuf, whitelist: &HashSet<String>) {
    let path = config_dir.join("whitelist.json");
    if let Ok(json) = serde_json::to_string_pretty(&Vec::from_iter(whitelist.iter().cloned())) {
        let _ = fs::create_dir_all(config_dir);
        let _ = fs::write(path, json);
    }
}

// ─── Global State ────────────────────────────────────────────────────

/// Thread-safe state managed by Tauri.
/// Holds the DGA detector, blocklist engine, enabled flag, whitelist, and telemetry.
pub struct ShieldZeroState {
    pub enabled: Mutex<bool>,
    detector: DgaDetector,
    /// Blocklist engine (millions of domains, O(1) lookups)
    pub blocklist: blocklist::BlocklistEngine,
    /// Session counters
    pub session_scanned: Mutex<u64>,
    pub session_blocked: Mutex<u64>,
    /// Persistent telemetry (survives app restarts)
    pub telemetry: Mutex<TelemetryData>,
    /// User whitelist (false positive overrides)
    pub whitelist: Mutex<HashSet<String>>,
    /// Config directory for persistence
    config_dir: PathBuf,
    /// Recent threat log (last 50 entries)
    pub threat_log: Mutex<Vec<ThreatLogEntry>>,
}

/// A single entry in the threat log.
#[derive(serde::Serialize, Clone, Debug)]
pub struct ThreatLogEntry {
    pub domain: String,
    pub score: f64,
    pub verdict: String,
    pub action: String, // "blocked", "allowed", "whitelisted"
    pub timestamp: String,
}

impl ShieldZeroState {
    pub fn new() -> Self {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("NeraVPN");

        let telemetry = TelemetryData::load(&config_dir);
        let whitelist = load_whitelist(&config_dir);

        // Initialize blocklist engine and load from cache
        let blocklist_cache_dir = config_dir.join("blocklists");
        let blocklist_engine = blocklist::BlocklistEngine::new(blocklist_cache_dir);
        blocklist_engine.load_from_cache();

        Self {
            enabled: Mutex::new(false),
            detector: DgaDetector::new(),
            blocklist: blocklist_engine,
            session_scanned: Mutex::new(0),
            session_blocked: Mutex::new(0),
            telemetry: Mutex::new(telemetry),
            whitelist: Mutex::new(whitelist),
            config_dir,
            threat_log: Mutex::new(Vec::new()),
        }
    }

    /// Analyze a domain. Returns the analysis result.
    /// Checks whitelist first; if whitelisted, returns clean.
    /// If Shield Zero is disabled, returns a pass-through result.
    pub fn analyze(&self, domain: &str) -> DomainAnalysis {
        let enabled = *self.enabled.lock().unwrap();

        if !enabled {
            return DomainAnalysis {
                domain: domain.to_string(),
                score: 0.0,
                verdict: "disabled".to_string(),
                blocked: false,
                whitelisted: false,
                features: FeatureBreakdown {
                    entropy: 0.0,
                    consonant_cluster: 0.0,
                    vowel_ratio: 0.0,
                    digit_ratio: 0.0,
                    domain_length: 0.0,
                    bigram_score: 0.0,
                },
            };
        }

        // Check whitelist first
        let domain_lower = domain.to_lowercase();
        let is_whitelisted = {
            let wl = self.whitelist.lock().unwrap();
            wl.contains(&domain_lower) || wl.iter().any(|w| domain_lower.ends_with(w))
        };

        if is_whitelisted {
            *self.session_scanned.lock().unwrap() += 1;
            let mut telemetry = self.telemetry.lock().unwrap();
            telemetry.total_scanned += 1;
            telemetry.save(&self.config_dir);
            return DomainAnalysis {
                domain: domain.to_string(),
                score: 0.0,
                verdict: "whitelisted".to_string(),
                blocked: false,
                whitelisted: true,
                features: FeatureBreakdown {
                    entropy: 0.0,
                    consonant_cluster: 0.0,
                    vowel_ratio: 0.0,
                    digit_ratio: 0.0,
                    domain_length: 0.0,
                    bigram_score: 0.0,
                },
            };
        }

        // ─── Tier 1: Blocklist check (O(1), against millions of known-bad domains) ───
        if self.blocklist.is_blocked(&domain_lower) {
            *self.session_scanned.lock().unwrap() += 1;
            *self.session_blocked.lock().unwrap() += 1;
            let mut telemetry = self.telemetry.lock().unwrap();
            telemetry.total_scanned += 1;
            telemetry.total_blocked += 1;
            telemetry.save(&self.config_dir);

            // Add to threat log
            let entry = ThreatLogEntry {
                domain: domain.to_string(),
                score: 1.0,
                verdict: "blocklist".to_string(),
                action: "blocked".to_string(),
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            };
            let mut log = self.threat_log.lock().unwrap();
            log.push(entry);
            if log.len() > 50 {
                let excess = log.len() - 50;
                log.drain(0..excess);
            }

            return DomainAnalysis {
                domain: domain.to_string(),
                score: 1.0,
                verdict: "blocklist".to_string(),
                blocked: true,
                whitelisted: false,
                features: FeatureBreakdown {
                    entropy: 0.0,
                    consonant_cluster: 0.0,
                    vowel_ratio: 0.0,
                    digit_ratio: 0.0,
                    domain_length: 0.0,
                    bigram_score: 0.0,
                },
            };
        }

        // ─── Tier 2: DGA heuristic detection ───
        let result = self.detector.analyze(domain);
        let analysis: DomainAnalysis = result.into();

        // Update session counters
        *self.session_scanned.lock().unwrap() += 1;

        // Update persistent telemetry
        let mut telemetry = self.telemetry.lock().unwrap();
        telemetry.total_scanned += 1;

        if analysis.blocked {
            *self.session_blocked.lock().unwrap() += 1;
            telemetry.total_blocked += 1;
        }

        telemetry.save(&self.config_dir);

        // Add to threat log if suspicious or malicious
        if analysis.verdict == "suspicious" || analysis.verdict == "malicious" {
            let entry = ThreatLogEntry {
                domain: analysis.domain.clone(),
                score: analysis.score,
                verdict: analysis.verdict.clone(),
                action: if analysis.blocked { "blocked".to_string() } else { "flagged".to_string() },
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            };
            let mut log = self.threat_log.lock().unwrap();
            log.push(entry);
            // Keep only last 50 entries
            if log.len() > 50 {
                let excess = log.len() - 50;
                log.drain(0..excess);
            }
        }

        analysis
    }

    /// Toggle the Shield Zero engine on/off.
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock().unwrap() = enabled;
        if !enabled {
            // Reset session counters on disable (persistent telemetry stays)
            *self.session_blocked.lock().unwrap() = 0;
            *self.session_scanned.lock().unwrap() = 0;
        }
    }

    /// Add a domain to the whitelist.
    pub fn add_to_whitelist(&self, domain: &str) {
        let domain = domain.to_lowercase();
        let mut wl = self.whitelist.lock().unwrap();
        wl.insert(domain);
        save_whitelist(&self.config_dir, &wl);

        // Update telemetry
        let mut telemetry = self.telemetry.lock().unwrap();
        telemetry.total_whitelisted_overrides += 1;
        telemetry.save(&self.config_dir);
    }

    /// Remove a domain from the whitelist.
    pub fn remove_from_whitelist(&self, domain: &str) {
        let domain = domain.to_lowercase();
        let mut wl = self.whitelist.lock().unwrap();
        wl.remove(&domain);
        save_whitelist(&self.config_dir, &wl);
    }

    /// Get the current whitelist.
    pub fn get_whitelist(&self) -> Vec<String> {
        let wl = self.whitelist.lock().unwrap();
        let mut list: Vec<String> = wl.iter().cloned().collect();
        list.sort();
        list
    }

    /// Get the threat log.
    pub fn get_threat_log(&self) -> Vec<ThreatLogEntry> {
        self.threat_log.lock().unwrap().clone()
    }

    /// Get comprehensive stats for the frontend.
    pub fn get_stats(&self) -> serde_json::Value {
        let enabled = *self.enabled.lock().unwrap();
        let session_scanned = *self.session_scanned.lock().unwrap();
        let session_blocked = *self.session_blocked.lock().unwrap();
        let telemetry = self.telemetry.lock().unwrap();
        let whitelist_count = self.whitelist.lock().unwrap().len();
        let blocklist_stats = self.blocklist.get_stats();

        serde_json::json!({
            "enabled": enabled,
            "session_scanned": session_scanned,
            "session_blocked": session_blocked,
            "total_scanned": telemetry.total_scanned,
            "total_blocked": telemetry.total_blocked,
            "total_whitelisted_overrides": telemetry.total_whitelisted_overrides,
            "whitelist_count": whitelist_count,
            "blocklist": {
                "total_domains": blocklist_stats.total_domains,
                "sources_loaded": blocklist_stats.sources_loaded,
                "last_updated": blocklist_stats.last_updated,
                "source_counts": blocklist_stats.source_counts
            }
        })
    }
}
