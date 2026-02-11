//! Shield Zero Blocklist Engine
//!
//! Downloads, caches, and serves domain blocklists for DNS filtering.
//! Uses HashSet<String> for O(1) lookups against millions of domains.
//!
//! Supports multiple list formats:
//!   - Hosts file:  `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
//!   - Domain list: `domain.com` (one per line)
//!   - Comments:    lines starting with `#` or `!`

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// A single blocklist source.
#[derive(Clone, Debug)]
pub struct BlocklistSource {
    /// Human-readable name
    pub name: &'static str,
    /// Raw URL to download
    pub url: &'static str,
    /// Local cache filename
    pub cache_file: &'static str,
}

/// Default blocklist sources — curated for low false-positive rate.
pub const DEFAULT_SOURCES: &[BlocklistSource] = &[
    BlocklistSource {
        name: "OISD Big",
        url: "https://big.oisd.nl/domainswild",
        cache_file: "oisd_big.txt",
    },
    BlocklistSource {
        name: "Steven Black Unified",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        cache_file: "steven_black.txt",
    },
    BlocklistSource {
        name: "HaGeZi Multi PRO",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        cache_file: "hagezi_pro.txt",
    },
];

/// How long before cached lists are considered stale (24 hours).
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Telemetry for the blocklist engine.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct BlocklistStats {
    pub total_domains: usize,
    pub sources_loaded: usize,
    pub last_updated: Option<String>,
    pub source_counts: Vec<SourceCount>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SourceCount {
    pub name: String,
    pub count: usize,
}

/// The main blocklist engine.
/// Thread-safe: domains are behind a Mutex.
pub struct BlocklistEngine {
    /// All blocked domains — O(1) lookup.
    domains: Mutex<HashSet<String>>,
    /// Cache directory for downloaded lists.
    cache_dir: PathBuf,
    /// Whether the engine is loaded and ready.
    loaded: Mutex<bool>,
    /// Stats about loaded lists.
    stats: Mutex<BlocklistStats>,
}

impl BlocklistEngine {
    /// Create a new engine with the given cache directory.
    pub fn new(cache_dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&cache_dir);
        Self {
            domains: Mutex::new(HashSet::new()),
            cache_dir,
            loaded: Mutex::new(false),
            stats: Mutex::new(BlocklistStats::default()),
        }
    }

    /// Check if a domain is blocked.
    /// Also checks parent domains (e.g. "sub.evil.com" matches "evil.com").
    pub fn is_blocked(&self, domain: &str) -> bool {
        let loaded = *self.loaded.lock().unwrap();
        if !loaded {
            return false;
        }

        let domains = self.domains.lock().unwrap();
        let lower = domain.to_lowercase();

        // Exact match
        if domains.contains(&lower) {
            return true;
        }

        // Check parent domains: "a.b.evil.com" → "b.evil.com" → "evil.com"
        let mut parts: &str = &lower;
        while let Some(pos) = parts.find('.') {
            parts = &parts[pos + 1..];
            if domains.contains(parts) {
                return true;
            }
        }

        false
    }

    /// Get current stats.
    pub fn get_stats(&self) -> BlocklistStats {
        self.stats.lock().unwrap().clone()
    }

    /// Load blocklists from cache (synchronous, for startup).
    /// Falls back to empty set if cache doesn't exist.
    pub fn load_from_cache(&self) {
        let mut all_domains = HashSet::new();
        let mut source_counts = Vec::new();

        for source in DEFAULT_SOURCES {
            let cache_path = self.cache_dir.join(source.cache_file);
            if cache_path.exists() {
                let count_before = all_domains.len();
                if let Ok(content) = fs::read_to_string(&cache_path) {
                    parse_blocklist(&content, &mut all_domains);
                }
                let added = all_domains.len() - count_before;
                source_counts.push(SourceCount {
                    name: source.name.to_string(),
                    count: added,
                });
                log::info!(
                    "[Blocklist] Loaded {} domains from cache: {} ({})",
                    added,
                    source.name,
                    cache_path.display()
                );
            }
        }

        let total = all_domains.len();
        *self.domains.lock().unwrap() = all_domains;
        *self.loaded.lock().unwrap() = total > 0;

        let mut stats = self.stats.lock().unwrap();
        stats.total_domains = total;
        stats.sources_loaded = source_counts.len();
        stats.source_counts = source_counts;

        log::info!("[Blocklist] Cache loaded: {} total domains", total);
    }

    /// Download all blocklist sources and update the engine.
    /// This is async and should be called from a tokio task.
    pub async fn download_and_update(&self) -> Result<BlocklistStats, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("NeraVPN-ShieldZero/1.0")
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let mut all_domains = HashSet::new();
        let mut source_counts = Vec::new();
        let mut sources_loaded = 0;

        for source in DEFAULT_SOURCES {
            let cache_path = self.cache_dir.join(source.cache_file);

            // Check if cache is still fresh
            if is_cache_fresh(&cache_path) {
                // Load from cache instead of downloading
                if let Ok(content) = fs::read_to_string(&cache_path) {
                    let count_before = all_domains.len();
                    parse_blocklist(&content, &mut all_domains);
                    let added = all_domains.len() - count_before;
                    source_counts.push(SourceCount {
                        name: source.name.to_string(),
                        count: added,
                    });
                    sources_loaded += 1;
                    log::info!(
                        "[Blocklist] Using fresh cache for {}: {} domains",
                        source.name,
                        added
                    );
                }
                continue;
            }

            // Download the list
            log::info!("[Blocklist] Downloading: {} → {}", source.name, source.url);
            match client.get(source.url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.text().await {
                            Ok(content) => {
                                // Cache to disk
                                let _ = fs::write(&cache_path, &content);

                                let count_before = all_domains.len();
                                parse_blocklist(&content, &mut all_domains);
                                let added = all_domains.len() - count_before;
                                source_counts.push(SourceCount {
                                    name: source.name.to_string(),
                                    count: added,
                                });
                                sources_loaded += 1;

                                log::info!(
                                    "[Blocklist] Downloaded {}: {} new domains (total now: {})",
                                    source.name,
                                    added,
                                    all_domains.len()
                                );
                            }
                            Err(e) => {
                                log::warn!("[Blocklist] Failed to read body from {}: {}", source.name, e);
                                // Try to load from stale cache
                                load_stale_cache(&cache_path, &mut all_domains, &mut source_counts, source.name);
                            }
                        }
                    } else {
                        log::warn!(
                            "[Blocklist] HTTP {} for {}: {}",
                            response.status(),
                            source.name,
                            source.url
                        );
                        load_stale_cache(&cache_path, &mut all_domains, &mut source_counts, source.name);
                    }
                }
                Err(e) => {
                    log::warn!("[Blocklist] Download failed for {}: {}", source.name, e);
                    load_stale_cache(&cache_path, &mut all_domains, &mut source_counts, source.name);
                }
            }
        }

        let total = all_domains.len();
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();

        // Update the live domain set
        *self.domains.lock().unwrap() = all_domains;
        *self.loaded.lock().unwrap() = total > 0;

        let updated_stats = BlocklistStats {
            total_domains: total,
            sources_loaded,
            last_updated: Some(now),
            source_counts,
        };

        *self.stats.lock().unwrap() = updated_stats.clone();

        log::info!(
            "[Blocklist] Update complete: {} domains from {} sources",
            total,
            sources_loaded
        );

        Ok(updated_stats)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Parse a blocklist file into a HashSet of domains.
/// Supports:
///   - `0.0.0.0 domain.com` (hosts format)
///   - `127.0.0.1 domain.com` (hosts format)
///   - `domain.com` (domain list)
///   - `*.domain.com` (wildcard — stored as `domain.com`)
///   - Lines starting with `#`, `!`, or empty → skipped
fn parse_blocklist(content: &str, domains: &mut HashSet<String>) {
    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        // Hosts file format: "0.0.0.0 domain" or "127.0.0.1 domain"
        let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
            line.split_whitespace().nth(1)
        } else if line.contains(' ') || line.contains('\t') {
            // Unknown multi-column format → skip
            continue;
        } else {
            // Plain domain
            Some(line)
        };

        if let Some(d) = domain {
            let d = d.to_lowercase();
            // Strip wildcard prefix
            let d = d.strip_prefix("*.").unwrap_or(&d);
            // Skip localhost entries and IPs
            if d == "localhost"
                || d == "localhost.localdomain"
                || d == "broadcasthost"
                || d == "local"
                || d.is_empty()
                || d.parse::<std::net::Ipv4Addr>().is_ok()
            {
                continue;
            }
            domains.insert(d.to_string());
        }
    }
}

/// Check if a cache file is less than CACHE_TTL old.
fn is_cache_fresh(path: &Path) -> bool {
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                return elapsed < CACHE_TTL;
            }
        }
    }
    false
}

/// Try to load from a stale cache as a fallback.
fn load_stale_cache(
    path: &Path,
    domains: &mut HashSet<String>,
    source_counts: &mut Vec<SourceCount>,
    name: &str,
) {
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            let count_before = domains.len();
            parse_blocklist(&content, domains);
            let added = domains.len() - count_before;
            source_counts.push(SourceCount {
                name: format!("{} (stale)", name),
                count: added,
            });
            log::info!(
                "[Blocklist] Fallback to stale cache for {}: {} domains",
                name,
                added
            );
        }
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_format() {
        let content = "# Comment\n0.0.0.0 ads.example.com\n127.0.0.1 tracker.evil.net\n";
        let mut domains = HashSet::new();
        parse_blocklist(content, &mut domains);
        assert!(domains.contains("ads.example.com"));
        assert!(domains.contains("tracker.evil.net"));
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn test_parse_domain_list_format() {
        let content = "malware.com\nphishing.org\n# skip this\n\nevil.ru\n";
        let mut domains = HashSet::new();
        parse_blocklist(content, &mut domains);
        assert!(domains.contains("malware.com"));
        assert!(domains.contains("phishing.org"));
        assert!(domains.contains("evil.ru"));
        assert_eq!(domains.len(), 3);
    }

    #[test]
    fn test_parse_wildcard_format() {
        let content = "*.ads.example.com\n*.tracker.evil.net\n";
        let mut domains = HashSet::new();
        parse_blocklist(content, &mut domains);
        assert!(domains.contains("ads.example.com"));
        assert!(domains.contains("tracker.evil.net"));
    }

    #[test]
    fn test_skip_localhost_entries() {
        let content = "0.0.0.0 localhost\n0.0.0.0 localhost.localdomain\n0.0.0.0 broadcasthost\n0.0.0.0 real-malware.com\n";
        let mut domains = HashSet::new();
        parse_blocklist(content, &mut domains);
        assert!(!domains.contains("localhost"));
        assert!(!domains.contains("localhost.localdomain"));
        assert!(domains.contains("real-malware.com"));
        assert_eq!(domains.len(), 1);
    }

    #[test]
    fn test_skip_comments_and_empty() {
        let content = "# This is a comment\n! Also a comment\n\n   \nmalware.com\n";
        let mut domains = HashSet::new();
        parse_blocklist(content, &mut domains);
        assert_eq!(domains.len(), 1);
        assert!(domains.contains("malware.com"));
    }

    #[test]
    fn test_case_insensitive() {
        let content = "ADS.EXAMPLE.COM\nTracker.Evil.Net\n";
        let mut domains = HashSet::new();
        parse_blocklist(content, &mut domains);
        assert!(domains.contains("ads.example.com"));
        assert!(domains.contains("tracker.evil.net"));
    }

    #[test]
    fn test_is_blocked_exact() {
        let engine = BlocklistEngine::new(PathBuf::from("."));
        {
            let mut domains = engine.domains.lock().unwrap();
            domains.insert("evil.com".to_string());
            domains.insert("ads.tracker.net".to_string());
        }
        *engine.loaded.lock().unwrap() = true;

        assert!(engine.is_blocked("evil.com"));
        assert!(engine.is_blocked("EVIL.COM"));
        assert!(!engine.is_blocked("not-evil.com"));
    }

    #[test]
    fn test_is_blocked_subdomain() {
        let engine = BlocklistEngine::new(PathBuf::from("."));
        {
            let mut domains = engine.domains.lock().unwrap();
            domains.insert("evil.com".to_string());
        }
        *engine.loaded.lock().unwrap() = true;

        // Subdomains of a blocked domain should also be blocked
        assert!(engine.is_blocked("sub.evil.com"));
        assert!(engine.is_blocked("deep.sub.evil.com"));
        assert!(!engine.is_blocked("notevil.com"));
    }

    #[test]
    fn test_not_loaded_returns_false() {
        let engine = BlocklistEngine::new(PathBuf::from("."));
        {
            let mut domains = engine.domains.lock().unwrap();
            domains.insert("evil.com".to_string());
        }
        // loaded is false by default
        assert!(!engine.is_blocked("evil.com"));
    }
}
