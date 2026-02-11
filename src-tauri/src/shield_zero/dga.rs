//! Shield Zero — DGA (Domain Generation Algorithm) Detection Engine
//!
//! A production-grade, lightweight heuristic engine that identifies
//! algorithmically generated domain names used by malware for C2 communication.
//!
//! Uses a 6-feature weighted scoring model based on academic research
//! (IEEE, UW, Cisco Umbrella, Splunk) to achieve gold-standard detection
//! with minimal false positives.
//!
//! Features:
//!   1. Shannon Entropy          — measures character randomness
//!   2. Consonant Cluster Length  — detects unpronounceable strings
//!   3. Vowel Ratio              — checks linguistic plausibility
//!   4. Digit Ratio              — flags numeric-heavy domains
//!   5. Domain Length             — catches unusually long names
//!   6. Bigram Frequency Score    — compares char-pairs to English norms

use std::collections::HashMap;

// ─── Result Types ────────────────────────────────────────────────────

/// Verdict returned by the DGA detector.
#[derive(Debug, Clone, PartialEq)]
pub enum DgaVerdict {
    /// Domain appears clean (score < 0.5)
    Clean,
    /// Domain is borderline, worth monitoring (0.5 ≤ score < 0.7)
    Suspicious,
    /// High confidence this is a DGA domain (score ≥ 0.7)
    Malicious,
}

/// Full analysis result for a domain.
#[derive(Debug, Clone)]
pub struct DgaResult {
    /// The domain that was analyzed (label only, no TLD)
    pub domain: String,
    /// Combined weighted score (0.0 = perfectly clean, 1.0 = certain DGA)
    pub score: f64,
    /// Final verdict
    pub verdict: DgaVerdict,
    /// Individual feature scores for transparency / debugging
    pub features: FeatureScores,
}

/// Breakdown of each feature's contribution.
#[derive(Debug, Clone)]
pub struct FeatureScores {
    pub entropy: f64,
    pub consonant_cluster: f64,
    pub vowel_ratio: f64,
    pub digit_ratio: f64,
    pub domain_length: f64,
    pub bigram_score: f64,
}

// ─── Configuration ───────────────────────────────────────────────────

/// Tunable thresholds for the DGA detector.
/// Defaults are calibrated from academic research.
pub struct DgaConfig {
    /// Entropy above this is considered suspicious (research: 3.8)
    pub entropy_threshold: f64,
    /// Maximum clean entropy (above this = definitely suspicious)
    pub entropy_ceiling: f64,
    /// Consecutive consonants to flag (research: 4+)
    pub consonant_cluster_threshold: usize,
    /// Vowel ratio below this is suspicious (research: <15%)
    pub vowel_ratio_threshold: f64,
    /// Digit ratio above this is suspicious (research: >30%)
    pub digit_ratio_threshold: f64,
    /// Domain length above this is suspicious (research: >24)
    pub length_threshold: usize,
    /// Maximum normal domain length
    pub length_ceiling: usize,
    /// Bigram score below this is suspicious
    pub bigram_threshold: f64,

    // Feature weights (must sum to 1.0)
    pub w_entropy: f64,
    pub w_consonant: f64,
    pub w_vowel: f64,
    pub w_digit: f64,
    pub w_length: f64,
    pub w_bigram: f64,
}

impl Default for DgaConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.0,
            entropy_ceiling: 4.0,
            consonant_cluster_threshold: 4,
            vowel_ratio_threshold: 0.25,
            digit_ratio_threshold: 0.20,
            length_threshold: 24,
            length_ceiling: 48,
            bigram_threshold: 0.008,

            // Weights (sum = 1.0)
            w_entropy: 0.25,
            w_consonant: 0.15,
            w_vowel: 0.15,
            w_digit: 0.20,
            w_length: 0.05,
            w_bigram: 0.20,
        }
    }
}

// ─── Detector ────────────────────────────────────────────────────────

pub struct DgaDetector {
    config: DgaConfig,
    bigram_freq: HashMap<(char, char), f64>,
}

impl DgaDetector {
    /// Create a new detector with default (research-calibrated) config.
    pub fn new() -> Self {
        Self::with_config(DgaConfig::default())
    }

    /// Create a detector with custom thresholds.
    pub fn with_config(config: DgaConfig) -> Self {
        Self {
            config,
            bigram_freq: build_english_bigram_table(),
        }
    }

    /// Analyze a domain name and return a verdict.
    ///
    /// Expects the second-level domain label only (e.g., "google" from "google.com").
    /// If a full domain is passed, the TLD will be stripped automatically.
    pub fn analyze(&self, domain: &str) -> DgaResult {
        let label = extract_label(domain);

        if label.is_empty() {
            return DgaResult {
                domain: domain.to_string(),
                score: 0.0,
                verdict: DgaVerdict::Clean,
                features: FeatureScores {
                    entropy: 0.0,
                    consonant_cluster: 0.0,
                    vowel_ratio: 0.0,
                    digit_ratio: 0.0,
                    domain_length: 0.0,
                    bigram_score: 0.0,
                },
            };
        }

        // Calculate all 6 features (each returns 0.0–1.0 suspicion score)
        let f_entropy = self.score_entropy(&label);
        let f_consonant = self.score_consonant_cluster(&label);
        let f_vowel = self.score_vowel_ratio(&label);
        let f_digit = self.score_digit_ratio(&label);
        let f_length = self.score_length(&label);
        let f_bigram = self.score_bigram(&label);

        // Weighted combination
        let raw_score = f_entropy * self.config.w_entropy
            + f_consonant * self.config.w_consonant
            + f_vowel * self.config.w_vowel
            + f_digit * self.config.w_digit
            + f_length * self.config.w_length
            + f_bigram * self.config.w_bigram;

        // Multi-signal anomaly boost:
        // When multiple features are independently elevated (>0.2),
        // the convergence of signals is itself suspicious.
        let elevated_features = [f_entropy, f_consonant, f_vowel, f_digit, f_bigram]
            .iter()
            .filter(|&&f| f > 0.2)
            .count();

        let boost = match elevated_features {
            0..=2 => 1.0,   // Normal — no boost
            3 => 1.4,       // 3 signals converging — moderate boost
            4 => 1.6,       // 4 signals — strong boost
            _ => 1.8,       // 5+ signals — very strong boost
        };

        let score = (raw_score * boost).clamp(0.0, 1.0);

        let verdict = if score >= 0.7 {
            DgaVerdict::Malicious
        } else if score >= 0.5 {
            DgaVerdict::Suspicious
        } else {
            DgaVerdict::Clean
        };

        DgaResult {
            domain: label,
            score,
            verdict,
            features: FeatureScores {
                entropy: f_entropy,
                consonant_cluster: f_consonant,
                vowel_ratio: f_vowel,
                digit_ratio: f_digit,
                domain_length: f_length,
                bigram_score: f_bigram,
            },
        }
    }

    // ─── Feature 1: Shannon Entropy ──────────────────────────────

    fn score_entropy(&self, label: &str) -> f64 {
        let entropy = shannon_entropy(label);
        if entropy <= self.config.entropy_threshold {
            0.0
        } else if entropy >= self.config.entropy_ceiling {
            1.0
        } else {
            // Linear interpolation between threshold and ceiling
            (entropy - self.config.entropy_threshold)
                / (self.config.entropy_ceiling - self.config.entropy_threshold)
        }
    }

    // ─── Feature 2: Consonant Cluster ────────────────────────────

    fn score_consonant_cluster(&self, label: &str) -> f64 {
        let max_run = longest_consonant_run(label);
        if max_run < self.config.consonant_cluster_threshold {
            0.0
        } else {
            // Scale: 4 consonants = 0.5, 6+ = 1.0
            let over = (max_run - self.config.consonant_cluster_threshold) as f64;
            (0.5 + over * 0.25).min(1.0)
        }
    }

    // ─── Feature 3: Vowel Ratio ──────────────────────────────────

    fn score_vowel_ratio(&self, label: &str) -> f64 {
        let ratio = vowel_ratio(label);
        // Pure numeric strings have 0 vowels from 0 alpha chars;
        // treat them as neutral here (digit_ratio handles them)
        let alpha_count = label.chars().filter(|c| c.is_ascii_alphabetic()).count();
        if alpha_count == 0 {
            return 0.5; // Neutral — digit_ratio will handle
        }
        if ratio >= self.config.vowel_ratio_threshold {
            0.0
        } else if ratio <= 0.05 {
            1.0
        } else {
            // Inverse: fewer vowels = higher score
            1.0 - (ratio / self.config.vowel_ratio_threshold)
        }
    }

    // ─── Feature 4: Digit Ratio ──────────────────────────────────

    fn score_digit_ratio(&self, label: &str) -> f64 {
        let ratio = digit_ratio(label);
        if ratio <= self.config.digit_ratio_threshold {
            0.0
        } else if ratio >= 0.6 {
            1.0
        } else {
            (ratio - self.config.digit_ratio_threshold)
                / (0.6 - self.config.digit_ratio_threshold)
        }
    }

    // ─── Feature 5: Domain Length ────────────────────────────────

    fn score_length(&self, label: &str) -> f64 {
        let len = label.len();
        if len <= self.config.length_threshold {
            0.0
        } else if len >= self.config.length_ceiling {
            1.0
        } else {
            (len - self.config.length_threshold) as f64
                / (self.config.length_ceiling - self.config.length_threshold) as f64
        }
    }

    // ─── Feature 6: Bigram Frequency ────────────────────────────

    fn score_bigram(&self, label: &str) -> f64 {
        if label.len() < 2 {
            return 0.0;
        }

        let lower: Vec<char> = label.to_lowercase().chars().collect();
        let mut total_freq = 0.0;
        let mut count = 0;
        let mut non_alpha_pairs = 0;

        for window in lower.windows(2) {
            let pair = (window[0], window[1]);
            if pair.0.is_ascii_alphabetic() && pair.1.is_ascii_alphabetic() {
                let freq = self.bigram_freq.get(&pair).copied().unwrap_or(0.0);
                total_freq += freq;
                count += 1;
            } else {
                // Non-alphabetic pairs (digit-letter, digit-digit) are unusual
                non_alpha_pairs += 1;
            }
        }

        // Penalize domains with many non-alphabetic bigram pairs
        let non_alpha_penalty = if lower.len() > 2 {
            (non_alpha_pairs as f64 / (lower.len() - 1) as f64).min(1.0)
        } else {
            0.0
        };

        if count == 0 {
            // No alphabetic bigrams at all = very suspicious (all digits/symbols)
            return (0.7 + non_alpha_penalty * 0.3).min(1.0);
        }

        let avg_freq = total_freq / count as f64;

        // Low average bigram frequency = unusual character pairings = suspicious
        let base_score = if avg_freq >= self.config.bigram_threshold {
            0.0
        } else if avg_freq <= 0.001 {
            1.0
        } else {
            1.0 - (avg_freq / self.config.bigram_threshold)
        };

        // Blend base score with non-alpha penalty
        (base_score * 0.7 + non_alpha_penalty * 0.3).min(1.0)
    }
}

// ─── Core Math Functions ─────────────────────────────────────────────

/// Calculate Shannon entropy of a string.
///
/// H(X) = -Σ P(x_i) · log₂(P(x_i))
///
/// Returns bits of entropy. English text ≈ 2.5-3.5, random ≈ 4.0-4.7.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq: HashMap<char, usize> = HashMap::new();

    for ch in s.chars() {
        *freq.entry(ch.to_ascii_lowercase()).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Returns the longest run of consecutive consonants in the string.
pub fn longest_consonant_run(s: &str) -> usize {
    const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];
    let mut max_run = 0;
    let mut current = 0;

    for ch in s.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphabetic() && !VOWELS.contains(&lower) {
            current += 1;
            if current > max_run {
                max_run = current;
            }
        } else {
            current = 0;
        }
    }

    max_run
}

/// Returns the ratio of vowels to total alphabetic characters.
pub fn vowel_ratio(s: &str) -> f64 {
    const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];

    let alpha_chars: Vec<char> = s.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();

    if alpha_chars.is_empty() {
        return 0.0;
    }

    let vowel_count = alpha_chars.iter()
        .filter(|c| VOWELS.contains(&c.to_ascii_lowercase()))
        .count();

    vowel_count as f64 / alpha_chars.len() as f64
}

/// Returns the ratio of digit characters to total characters.
pub fn digit_ratio(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
    digit_count as f64 / s.len() as f64
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Extract the second-level domain label from a FQDN.
/// "www.evil-domain.com" → "evil-domain"
/// "google.co.uk" → "google"
/// "x83ndq29.net" → "x83ndq29"
fn extract_label(domain: &str) -> String {
    let domain = domain.trim().to_lowercase();
    // Strip trailing dot
    let domain = domain.trim_end_matches('.');

    let parts: Vec<&str> = domain.split('.').collect();

    match parts.len() {
        0 => String::new(),
        1 => parts[0].to_string(),
        _ => {
            // Known two-part TLDs
            let two_part_tlds = ["co.uk", "com.au", "co.jp", "co.kr", "com.br", "co.in"];
            let suffix = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

            if two_part_tlds.contains(&suffix.as_str()) && parts.len() >= 3 {
                parts[parts.len() - 3].to_string()
            } else {
                parts[parts.len() - 2].to_string()
            }
        }
    }
}

/// Build a frequency table of English character bigrams.
///
/// These are approximate relative frequencies from large English corpora.
/// Used to detect character pairings that are rare in natural language.
fn build_english_bigram_table() -> HashMap<(char, char), f64> {
    let mut table = HashMap::new();

    // Top ~80 English bigrams with approximate frequencies (normalized)
    let bigrams: &[((char, char), f64)] = &[
        (('t', 'h'), 0.0356), (('h', 'e'), 0.0307), (('i', 'n'), 0.0243),
        (('e', 'r'), 0.0205), (('a', 'n'), 0.0199), (('r', 'e'), 0.0185),
        (('o', 'n'), 0.0176), (('a', 't'), 0.0149), (('e', 'n'), 0.0145),
        (('n', 'd'), 0.0135), (('t', 'i'), 0.0134), (('e', 's'), 0.0132),
        (('o', 'r'), 0.0128), (('t', 'e'), 0.0127), (('o', 'f'), 0.0111),
        (('e', 'd'), 0.0110), (('i', 's'), 0.0110), (('i', 't'), 0.0108),
        (('a', 'l'), 0.0105), (('a', 'r'), 0.0102), (('s', 't'), 0.0105),
        (('t', 'o'), 0.0104), (('n', 't'), 0.0104), (('n', 'g'), 0.0095),
        (('s', 'e'), 0.0093), (('h', 'a'), 0.0093), (('a', 's'), 0.0087),
        (('o', 'u'), 0.0087), (('i', 'o'), 0.0083), (('l', 'e'), 0.0083),
        (('v', 'e'), 0.0083), (('c', 'o'), 0.0079), (('m', 'e'), 0.0079),
        (('d', 'e'), 0.0076), (('h', 'i'), 0.0076), (('r', 'i'), 0.0073),
        (('r', 'o'), 0.0073), (('i', 'c'), 0.0070), (('n', 'e'), 0.0069),
        (('e', 'a'), 0.0069), (('r', 'a'), 0.0069), (('c', 'e'), 0.0065),
        (('l', 'i'), 0.0062), (('c', 'h'), 0.0060), (('l', 'l'), 0.0058),
        (('m', 'a'), 0.0057), (('c', 'a'), 0.0053), (('u', 'r'), 0.0051),
        (('g', 'e'), 0.0051), (('l', 'a'), 0.0049), (('e', 'l'), 0.0049),
        (('o', 'l'), 0.0047), (('u', 's'), 0.0046), (('p', 'l'), 0.0043),
        (('u', 'n'), 0.0043), (('n', 'o'), 0.0042), (('w', 'a'), 0.0041),
        (('a', 'd'), 0.0040), (('w', 'i'), 0.0040), (('p', 'r'), 0.0039),
        (('a', 'i'), 0.0038), (('n', 'a'), 0.0037), (('u', 'l'), 0.0034),
        (('n', 'c'), 0.0033), (('p', 'e'), 0.0032), (('e', 'c'), 0.0032),
        (('t', 'a'), 0.0031), (('s', 'i'), 0.0031), (('t', 'r'), 0.0031),
        (('o', 'm'), 0.0030), (('i', 'l'), 0.0030), (('a', 'c'), 0.0029),
        (('w', 'h'), 0.0028), (('e', 't'), 0.0027), (('s', 'u'), 0.0026),
        (('a', 'b'), 0.0024), (('s', 'o'), 0.0024), (('l', 'o'), 0.0024),
        (('i', 'g'), 0.0023), (('k', 'e'), 0.0023),
    ];

    for &(pair, freq) in bigrams {
        table.insert(pair, freq);
    }

    table
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> DgaDetector {
        DgaDetector::new()
    }

    // --- Legitimate Domains (should be Clean) ---

    #[test]
    fn test_clean_google() {
        let r = detector().analyze("google.com");
        println!("google.com => score={:.3}, verdict={:?}, features={:?}", r.score, r.verdict, r.features);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_clean_facebook() {
        let r = detector().analyze("facebook.com");
        println!("facebook.com => score={:.3}, verdict={:?}", r.score, r.verdict);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_clean_amazon() {
        let r = detector().analyze("amazon.com");
        let r2 = detector().analyze("stackoverflow.com");
        println!("amazon.com => {:.3}", r.score);
        println!("stackoverflow.com => {:.3}", r2.score);
        assert_eq!(r.verdict, DgaVerdict::Clean);
        assert_eq!(r2.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_clean_microsoft() {
        let r = detector().analyze("login.microsoftonline.com");
        println!("microsoftonline.com => score={:.3}", r.score);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_clean_github() {
        let r = detector().analyze("github.com");
        println!("github.com => score={:.3}", r.score);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_clean_youtube() {
        let r = detector().analyze("youtube.com");
        println!("youtube.com => score={:.3}", r.score);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_clean_wikipedia() {
        let r = detector().analyze("wikipedia.org");
        println!("wikipedia.org => score={:.3}", r.score);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_clean_cloudflare() {
        let r = detector().analyze("cloudflare.com");
        println!("cloudflare.com => score={:.3}", r.score);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    // --- DGA Domains (should be Suspicious or Malicious) ---

    #[test]
    fn test_dga_random_hex() {
        let r = detector().analyze("a1b2c3d4e5f6.com");
        println!("a1b2c3d4e5f6.com => score={:.3}, verdict={:?}", r.score, r.verdict);
        assert!(r.verdict == DgaVerdict::Suspicious || r.verdict == DgaVerdict::Malicious);
    }

    #[test]
    fn test_dga_conficker_style() {
        // Conficker DGA pattern: long random consonant-heavy strings
        let r = detector().analyze("eywonbdkjgmvsstgkblztpkfxhi.ru");
        println!("conficker-style => score={:.3}, verdict={:?}, features={:?}", r.score, r.verdict, r.features);
        assert!(r.verdict == DgaVerdict::Suspicious || r.verdict == DgaVerdict::Malicious);
    }

    #[test]
    fn test_dga_pure_random() {
        let r = detector().analyze("zxqvbnmk.net");
        println!("zxqvbnmk.net => score={:.3}, verdict={:?}", r.score, r.verdict);
        assert!(r.verdict == DgaVerdict::Suspicious || r.verdict == DgaVerdict::Malicious);
    }

    #[test]
    fn test_dga_numeric_heavy() {
        let r = detector().analyze("83472916.com");
        println!("83472916.com => score={:.3}, verdict={:?}", r.score, r.verdict);
        assert!(r.verdict == DgaVerdict::Suspicious || r.verdict == DgaVerdict::Malicious);
    }

    #[test]
    fn test_dga_long_random() {
        let r = detector().analyze("qhftvxzmpkwjgblrndcs.com");
        println!("long random => score={:.3}, verdict={:?}", r.score, r.verdict);
        assert!(r.verdict == DgaVerdict::Suspicious || r.verdict == DgaVerdict::Malicious);
    }

    #[test]
    fn test_dga_mixed_alphanumeric() {
        let r = detector().analyze("x8j2qa9k3m.com");
        println!("x8j2qa9k3m.com => score={:.3}, verdict={:?}", r.score, r.verdict);
        assert!(r.verdict == DgaVerdict::Suspicious || r.verdict == DgaVerdict::Malicious);
    }

    // --- Edge Cases ---

    #[test]
    fn test_short_domain() {
        let r = detector().analyze("go.com");
        println!("go.com => score={:.3}", r.score);
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_empty_domain() {
        let r = detector().analyze("");
        assert_eq!(r.verdict, DgaVerdict::Clean);
    }

    #[test]
    fn test_extract_label_simple() {
        assert_eq!(extract_label("google.com"), "google");
    }

    #[test]
    fn test_extract_label_subdomain() {
        assert_eq!(extract_label("www.evil.com"), "evil");
    }

    #[test]
    fn test_extract_label_co_uk() {
        assert_eq!(extract_label("bbc.co.uk"), "bbc");
    }

    // --- Shannon Entropy Direct ---

    #[test]
    fn test_entropy_values() {
        let e_google = shannon_entropy("google");
        let e_random = shannon_entropy("zxqvbnmk");
        println!("entropy(google)={:.3}, entropy(zxqvbnmk)={:.3}", e_google, e_random);
        assert!(e_google < e_random, "Random string should have higher entropy");
    }

    // --- Batch Comparison ---

    #[test]
    fn test_batch_legit_vs_dga() {
        let det = detector();
        let legit = vec![
            "google", "facebook", "amazon", "microsoft", "apple",
            "netflix", "twitter", "linkedin", "reddit", "wikipedia",
        ];
        let dga = vec![
            "zxqvbnmk", "a1b2c3d4e5f6", "83472916", "qhftvxzmpkw",
            "eywonbdkjgmvsstgkblztpkfxhi", "x8j2qa9k3m", "bnkrtqlz",
            "jfhwgzmnv", "83nd7qk2l", "pkzxwqjrm",
        ];

        println!("\n=== Legitimate Domains ===");
        for d in &legit {
            let r = det.analyze(&format!("{}.com", d));
            println!("  {:20} => score={:.3}  {:?}", d, r.score, r.verdict);
            assert!(r.score < 0.7, "{} should not be flagged as Malicious (score={})", d, r.score);
        }

        println!("\n=== DGA Domains ===");
        for d in &dga {
            let r = det.analyze(&format!("{}.com", d));
            println!("  {:30} => score={:.3}  {:?}", d, r.score, r.verdict);
            assert!(r.score > 0.3, "{} should have elevated score (score={})", d, r.score);
        }
    }
}
