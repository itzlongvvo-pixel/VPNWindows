//! Transport abstraction layer for VPN connections.
//! 
//! This module defines the `Transport` trait that abstracts the underlying
//! network transport mechanism. Phase 2.5 implements `TlsBridgeTransport`,
//! while Phase 3.0 will add `RelayTransport`.

use std::net::SocketAddr;
use std::time::Duration;
use async_trait::async_trait;

/// Connection state for multi-stage transports (Phase 3.0 compatibility)
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum TransportState {
    /// Not connected
    Disconnected,
    /// Initiating transport layer (TLS handshake, relay negotiation, etc.)
    Initializing,
    /// Transport layer established, WireGuard handshake pending
    TransportReady,
    /// Fully connected through transport
    Connected,
    /// Transport failed with error
    Failed(String),
}

/// Transport configuration abstraction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransportConfig {
    /// Target endpoint (can be VPN server or relay)
    pub endpoint: SocketAddr,
    /// Local bind port for WireGuard
    pub local_port: u16,
    /// Transport-specific options
    pub options: TransportOptions,
}

/// Transport-specific configuration options
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum TransportOptions {
    /// Direct WireGuard (no wrapping)
    Direct,
    /// TLS-wrapped UDP tunnel
    TlsBridge {
        /// Server hostname for TLS SNI
        sni_hostname: String,
        /// Expected certificate fingerprint (SHA256)
        cert_fingerprint: Option<String>,
        /// Enable obfuscation padding
        obfuscate: bool,
    },
    /// Future: Relay transport for Phase 3.0
    #[serde(skip)]
    Relay {
        entry_relay: SocketAddr,
        exit_relay: SocketAddr,
    },
}

impl Default for TransportOptions {
    fn default() -> Self {
        TransportOptions::Direct
    }
}

/// Result type for transport operations
pub type TransportResult<T> = Result<T, TransportError>;

/// Transport layer errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("TLS handshake failed: {0}")]
    TlsError(String),
    
    #[error("Timeout after {0:?}")]
    Timeout(Duration),
    
    #[error("Transport closed unexpectedly")]
    Closed,
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// The core transport abstraction trait.
/// 
/// Implementations handle the underlying network transport mechanism,
/// whether that's direct UDP, TLS-wrapped TCP, or multi-hop relays.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Returns the current state of the transport
    fn state(&self) -> TransportState;
    
    /// Initiates the transport connection
    /// 
    /// For TLS bridge: Establishes TCP connection, performs TLS handshake
    /// For Relay: Connects to entry relay, negotiates session
    async fn connect(&mut self, config: &TransportConfig) -> TransportResult<()>;
    
    /// Gracefully closes the transport
    async fn disconnect(&mut self) -> TransportResult<()>;
    
    /// Returns the local address where WireGuard should connect
    /// 
    /// For TLS bridge: `127.0.0.1:51821`
    /// For Direct: The actual server endpoint
    fn wireguard_endpoint(&self) -> SocketAddr;
    
    /// Returns true if this transport is considered "stealth"
    fn is_stealth(&self) -> bool;
    
    /// Returns latency overhead estimation in milliseconds
    fn estimated_overhead_ms(&self) -> u32;
}

// Note: create_transport factory moved to main.rs or a separate factory module to avoid circular deps if needed, 
// or can remain here if implementations are available. 
// For now we'll implement the factory in main.rs or usage site to keep transport.rs clean of detailed implementations?
// Actually, blueprint had create_transport here. Let's include DirectTransport here and TlsBridge in stealth.rs.
// To avoid circular dependency (stealth depends on transport), we can't have create_transport here depend on stealth.
// So we'll skip create_transport here and implement it in main.rs later.

/// Direct transport (no wrapping) - current behavior
pub struct DirectTransport {
    state: TransportState,
    endpoint: Option<SocketAddr>,
}

impl DirectTransport {
    pub fn new() -> Self {
        Self {
            state: TransportState::Disconnected,
            endpoint: None,
        }
    }
}

#[async_trait]
impl Transport for DirectTransport {
    fn state(&self) -> TransportState {
        self.state.clone()
    }
    
    async fn connect(&mut self, config: &TransportConfig) -> TransportResult<()> {
        self.endpoint = Some(config.endpoint);
        self.state = TransportState::Connected;
        Ok(())
    }
    
    async fn disconnect(&mut self) -> TransportResult<()> {
        self.state = TransportState::Disconnected;
        self.endpoint = None;
        Ok(())
    }
    
    fn wireguard_endpoint(&self) -> SocketAddr {
        self.endpoint.expect("Not connected")
    }
    
    fn is_stealth(&self) -> bool {
        false
    }
    
    fn estimated_overhead_ms(&self) -> u32 {
        0
    }
}
