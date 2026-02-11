//! TLS Bridge Transport for DPI Stealth Mode (Enterprise Grade)
//! 
//! This module implements a TLS-wrapped UDP tunnel with enterprise-grade
//! obfuscation to defeat Deep Packet Inspection. Features:
//! 
//! 1. TLS 1.3 wrapping — traffic appears as standard HTTPS
//! 2. Packet padding — random sizes defeat traffic fingerprinting  
//! 3. Timing jitter — random delays defeat timing correlation
//! 4. Certificate pinning — prevents MITM attacks

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::{TlsConnector, rustls};
use async_trait::async_trait;
use rand::Rng;

use crate::transport::{
    Transport, TransportConfig, TransportOptions, TransportState,
    TransportResult, TransportError,
};

/// Default local port for WireGuard to connect to
const LOCAL_PROXY_PORT: u16 = 51821;

/// Maximum UDP packet size (WireGuard max is ~1420 with overhead)
const MAX_PACKET_SIZE: usize = 1500;

/// Heartbeat interval to keep connection alive
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Enterprise DPI Obfuscation Constants ────────────────────────

/// Minimum padding target size (bytes). Packets smaller than this
/// will be padded up to a random size between MIN and MAX.
/// These values mimic typical HTTPS response sizes.
const PAD_MIN_TARGET: usize = 256;
const PAD_MAX_TARGET: usize = 1400;

/// Timing jitter range (microseconds). Random delays between
/// outgoing packets to defeat timing correlation analysis.
const JITTER_MIN_US: u64 = 50;
const JITTER_MAX_US: u64 = 500;

/// Padding sentinel byte — filled with this value so server
/// can distinguish padding from payload (length-prefix handles framing)
const PAD_BYTE: u8 = 0x00;

/// Header obfuscation XOR key (16 bytes).
/// Must match server-side obfuscation-proxy.js.
/// This is NOT a security key (TLS provides encryption).
/// It only disguises WireGuard packet format inside the TLS tunnel
/// to defeat middleboxes that inspect TLS-decrypted content.
/// Derived from: HMAC-SHA256("nera-obf-v1", "nera-header-obfuscation")[0..16]
const OBF_KEY: [u8; 16] = [
    0xA3, 0x7B, 0xF2, 0x1E, 0x9C, 0x4D, 0x68, 0x05,
    0xE1, 0x3A, 0x87, 0xC6, 0x54, 0x0F, 0xD9, 0xB2,
];

/// TLS Bridge Transport implementation
pub struct TlsBridgeTransport {
    state: TransportState,
    config: Option<TransportConfig>,
    /// Handle to stop the bridge when disconnecting
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Local endpoint info
    local_addr: Option<SocketAddr>,
}

use sha2::{Digest, Sha256};
use rustls::client::{ServerCertVerifier, ServerCertVerified};
use rustls::{Certificate, ServerName};
use std::time::SystemTime;

/// Custom Certificate Verifier that enforces SHA256 pinning
struct PinningVerifier {
    fingerprint_bytes: Vec<u8>,
}

impl PinningVerifier {
    fn new(fingerprint: &str) -> Result<Self, String> {
        let clean = fingerprint.replace(':', "").replace('-', "");
        if clean.len() != 64 {
            return Err("Invalid SHA256 fingerprint length".to_string());
        }
        
        let mut bytes = Vec::with_capacity(32);
        for i in (0..clean.len()).step_by(2) {
            let byte = u8::from_str_radix(&clean[i..i+2], 16)
                .map_err(|e| format!("Invalid hex: {e}"))?;
            bytes.push(byte);
        }
        
        Ok(Self { fingerprint_bytes: bytes })
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(&end_entity.0);
        let hash = hasher.finalize();
        
        if hash.as_slice() == self.fingerprint_bytes {
            Ok(ServerCertVerified::assertion())
        } else {
             // Log the mismatch for debugging (optional, but helpful)
             // buffer formatting is hard without hex crate, minimal log:
             // eprintln!("[Pinning] Mismatch! Expected {:?}, got {:?}", self.fingerprint_bytes, hash.as_slice());
             Err(rustls::Error::General("Certificate pinning verification failed".into()))
        }
    }
}

impl TlsBridgeTransport {
    pub fn new() -> Self {
        Self {
            state: TransportState::Disconnected,
            config: None,
            shutdown_tx: None,
            local_addr: None,
        }
    }
    
    /// Builds TLS configuration with certificate pinning
    fn build_tls_config(fingerprint: Option<&str>) -> Result<rustls::ClientConfig, TransportError> {
        // If pinning is requested, we IGNORE system roots and only trust the specific cert
        if let Some(fp_str) = fingerprint {
            println!("[Stealth] Enabling certificate pinning. EXPECTED: {}", fp_str);
            let verifier = PinningVerifier::new(fp_str)
                .map_err(|e| TransportError::TlsError(e))?;
                
            let config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
                
            return Ok(config);
        }

        // Standard WebPKI path if no pinning
        let mut root_store = rustls::RootCertStore::empty();
        
        // Add system root certificates
        // rustls-native-certs returns a Result, map error
        for cert in rustls_native_certs::load_native_certs()
            .map_err(|e| TransportError::TlsError(format!("Failed to load certs: {e}")))?
        {
            root_store.add(&rustls::Certificate(cert.0))
                .map_err(|e| TransportError::TlsError(format!("Invalid cert: {e}")))?;
        }
        
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        Ok(config)
    }
    
    /// XOR the first 16 bytes of a WireGuard packet with the obfuscation key.
    /// This disguises the WG message type header (bytes 0-3) and the sender
    /// index (bytes 4-7), making it unrecognizable to DPI even if TLS is
    /// terminated by a middlebox.
    fn xor_header_obfuscate(packet: &[u8]) -> Vec<u8> {
        let mut obfuscated = packet.to_vec();
        let len = std::cmp::min(16, obfuscated.len());
        for i in 0..len {
            obfuscated[i] ^= OBF_KEY[i];
        }
        obfuscated
    }
    
    /// Encapsulates a UDP packet for TLS transport with header obfuscation
    /// and random padding.
    ///
    /// Processing pipeline:
    /// 1. XOR first 16 bytes (header obfuscation) 
    /// 2. Add length prefix (2 bytes)
    /// 3. Append random padding
    ///
    /// Frame format (enterprise obfuscation):
    /// ```
    /// +----------+-------------------+----------+
    /// | Length   | XOR'd Payload     | Padding  |
    /// | (2 bytes)| (N bytes)         | (random) |
    /// +----------+-------------------+----------+
    /// ```
    fn encapsulate_padded(packet: &[u8]) -> Vec<u8> {
        // Step 1: XOR header obfuscation (disguise WG packet type)
        let obfuscated = Self::xor_header_obfuscate(packet);
        let payload_len = obfuscated.len();
        let mut rng = rand::thread_rng();
        
        // Calculate padding: inflate to random target size
        let target_size = if payload_len < PAD_MIN_TARGET {
            // Small packets (handshakes, keepalives): pad to random HTTPS-like size
            rng.gen_range(PAD_MIN_TARGET..=PAD_MAX_TARGET)
        } else if payload_len < PAD_MAX_TARGET {
            // Medium packets: pad to random size between current and max
            rng.gen_range(payload_len..=PAD_MAX_TARGET)
        } else {
            // Large packets: minimal random padding (0-64 bytes)
            payload_len + rng.gen_range(0..=64)
        };
        
        let pad_len = target_size.saturating_sub(payload_len);
        let total_frame_size = 2 + payload_len + pad_len;
        
        let mut frame = Vec::with_capacity(total_frame_size);
        // Length field: ONLY the real payload size (server uses this to strip padding)
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        frame.extend_from_slice(&obfuscated);
        // Append random padding bytes
        frame.resize(total_frame_size, PAD_BYTE);
        // Randomize padding content to avoid zero-fill detection
        for byte in frame[2 + payload_len..].iter_mut() {
            *byte = rng.gen();
        }
        
        frame
    }
    
    /// Legacy encapsulate without padding (for compatibility/testing)
    #[allow(dead_code)]
    fn encapsulate(packet: &[u8]) -> Vec<u8> {
        let len = packet.len() as u16;
        let mut frame = Vec::with_capacity(2 + packet.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(packet);
        frame
    }
    
    /// Decapsulates a frame received from TLS transport.
    /// Uses the length prefix to extract only the real payload,
    /// automatically stripping any server-side padding.
    fn decapsulate(frame: &[u8]) -> Option<&[u8]> {
        if frame.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        if frame.len() < 2 + len {
            return None;
        }
        Some(&frame[2..2 + len])
    }
    
    /// Generates a random timing jitter duration to insert between packets.
    /// This defeats DPI timing correlation attacks that detect regular
    /// WireGuard keepalive intervals.
    fn random_jitter() -> Duration {
        let us = rand::thread_rng().gen_range(JITTER_MIN_US..=JITTER_MAX_US);
        Duration::from_micros(us)
    }
    
    /// Main bridge loop - runs in background
    async fn run_bridge(
        local_socket: UdpSocket,
        tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> TransportResult<()> {
        let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);
        let local_socket = Arc::new(local_socket);
        
        // Track WireGuard's address (set on first packet)
        let wg_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        
        // Channel for outbound packets
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        
        // Task 1: UDP -> TLS (WireGuard outbound) with padding + jitter
        let socket_clone = local_socket.clone();
        let tx_clone = tx.clone();
        let wg_addr_clone = wg_addr.clone();
        let udp_to_tls = tokio::spawn(async move {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            let mut pkt_count: u64 = 0;
            loop {
                match socket_clone.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        // Remember WireGuard's address for responses
                        let mut wg = wg_addr_clone.lock().await;
                        if wg.is_none() {
                            *wg = Some(addr);
                            println!("[Stealth] WireGuard connected from {}", addr);
                        }
                        drop(wg); // Release lock before async work
                        
                        // Enterprise obfuscation: pad packet to random size
                        let frame = Self::encapsulate_padded(&buf[..n]);
                        
                        // Enterprise obfuscation: add timing jitter every few packets
                        // (not every packet to avoid excessive latency)
                        pkt_count += 1;
                        if pkt_count % 3 == 0 {
                            tokio::time::sleep(Self::random_jitter()).await;
                        }
                        
                        if tx_clone.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[Stealth] UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });
        
        // Task 2: TLS Write (send queued frames)
        let tls_write_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if let Err(e) = tls_write.write_all(&frame).await {
                    eprintln!("[Stealth] TLS write error: {}", e);
                    break;
                }
                // Flush after each packet to minimize latency
                if let Err(e) = tls_write.flush().await {
                    eprintln!("[Stealth] TLS flush error: {}", e);
                    break;
                }
            }
        });
        
        // Task 3: TLS -> UDP (inbound traffic)
        let socket_clone = local_socket.clone();
        let wg_addr_clone = wg_addr.clone();
        let tls_to_udp = tokio::spawn(async move {
            let mut buf = [0u8; MAX_PACKET_SIZE + 2];
            let mut partial: Vec<u8> = Vec::new();
            
            loop {
                match tls_read.read(&mut buf).await {
                    Ok(0) => {
                        println!("[Stealth] TLS connection closed");
                        break;
                    }
                    Ok(n) => {
                        partial.extend_from_slice(&buf[..n]);
                        
                        // Process complete frames
                        loop {
                            if partial.len() < 2 {
                                break;
                            }
                            let len = u16::from_be_bytes([partial[0], partial[1]]) as usize;
                            if partial.len() < 2 + len {
                                break; // Wait for more data
                            }
                            
                            let payload = &partial[2..2 + len];
                            
                            // Send to WireGuard
                            if let Some(addr) = *wg_addr_clone.lock().await {
                                if let Err(e) = socket_clone.send_to(payload, addr).await {
                                    eprintln!("[Stealth] UDP send error: {}", e);
                                }
                            }
                            
                            // Remove processed frame from buffer
                            // Optimize: Use a circular buffer or similar to avoid O(N) drain
                            // For MVP Vec::drain is acceptable
                            let _ = partial.drain(..2 + len);
                        }
                    }
                    Err(e) => {
                        eprintln!("[Stealth] TLS read error: {}", e);
                        break;
                    }
                }
            }
        });
        
        // Wait for shutdown signal or task failure
        tokio::select! {
            _ = shutdown_rx.recv() => {
                println!("[Stealth] Shutdown signal received");
            }
            _ = udp_to_tls => {
                eprintln!("[Stealth] UDP task exited");
            }
            _ = tls_write_task => {
                eprintln!("[Stealth] TLS write task exited");
            }
            _ = tls_to_udp => {
                eprintln!("[Stealth] TLS read task exited");
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl Transport for TlsBridgeTransport {
    fn state(&self) -> TransportState {
        self.state.clone()
    }
    
    async fn connect(&mut self, config: &TransportConfig) -> TransportResult<()> {
        // Extract TLS-specific options
        let (sni_hostname, cert_fingerprint, _obfuscate) = match &config.options {
            TransportOptions::TlsBridge { sni_hostname, cert_fingerprint, obfuscate } => {
                (sni_hostname.clone(), cert_fingerprint.clone(), *obfuscate)
            }
            _ => return Err(TransportError::InvalidConfig("Expected TlsBridge options".into())),
        };
        
        self.state = TransportState::Initializing;
        self.config = Some(config.clone());
        
        println!("[Stealth] Connecting to {} via TLS...", config.endpoint);
        
        // 1. Build TLS configuration
        let tls_config = Self::build_tls_config(cert_fingerprint.as_deref())?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        
        // 2. Create TCP connection with timeout
        let tcp_stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(config.endpoint),
        )
        .await
        .map_err(|_| TransportError::Timeout(CONNECT_TIMEOUT))?
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        
        // Disable Nagle's algorithm for lower latency
        tcp_stream.set_nodelay(true)
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to set nodelay: {e}")))?;
        
        // 3. Perform TLS handshake
        let server_name = rustls::ServerName::try_from(sni_hostname.as_str())
            .map_err(|_| TransportError::InvalidConfig("Invalid SNI hostname".into()))?;
        
        let tls_stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| TransportError::Timeout(CONNECT_TIMEOUT))?
        .map_err(|e| TransportError::TlsError(e.to_string()))?;
        
        // println!("[Stealth] TLS handshake complete, cipher: {:?}",
        //     tls_stream.get_ref().1.negotiated_cipher_suite());
        // Note: In newer tokio-rustls/rustls, accessing negotiated cipher suite might differ.
        // Keeping it simple for now.
        println!("[Stealth] TLS handshake complete");
        
        self.state = TransportState::TransportReady;
        
        // 4. Bind local UDP socket for WireGuard
        let local_addr: SocketAddr = format!("127.0.0.1:{}", config.local_port).parse().unwrap();
        // Create UDP socket for local proxy with SO_REUSEADDR
        // This allows immediate port reuse after disconnect
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to create socket: {}", e)))?;
        
        socket.set_reuse_address(true)
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to set SO_REUSEADDR: {}", e)))?;
        
        socket.bind(&local_addr.into())
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to bind UDP: {}", e)))?;
        
        socket.set_nonblocking(true)
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to set non-blocking: {}", e)))?;
        
        // Convert: socket2::Socket -> std::net::UdpSocket -> tokio::net::UdpSocket
        let std_socket: std::net::UdpSocket = socket.into();
        let local_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to convert to tokio socket: {}", e)))?;
        
        self.local_addr = Some(local_socket.local_addr()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?);
        
        println!("[Stealth] Local UDP proxy listening on {}", self.local_addr.unwrap());
        
        // 5. Start bridge in background
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);
        
        tokio::spawn(async move {
            if let Err(e) = TlsBridgeTransport::run_bridge(local_socket, tls_stream, shutdown_rx).await {
                eprintln!("[Stealth] Bridge error: {}", e);
            }
        });
        
        self.state = TransportState::Connected;
        println!("[Stealth] Bridge active, WireGuard should connect to 127.0.0.1:{}", config.local_port);
        
        Ok(())
    }
    
    async fn disconnect(&mut self) -> TransportResult<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        self.state = TransportState::Disconnected;
        self.config = None;
        self.local_addr = None;
        println!("[Stealth] Disconnected");
        Ok(())
    }
    
    fn wireguard_endpoint(&self) -> SocketAddr {
        self.local_addr.expect("Not connected")
    }
    
    fn is_stealth(&self) -> bool {
        true
    }
    
    fn estimated_overhead_ms(&self) -> u32 {
        // TLS adds ~5-15ms typical overhead
        10
    }
}
