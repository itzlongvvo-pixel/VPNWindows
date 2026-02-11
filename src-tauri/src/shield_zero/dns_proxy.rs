//! Shield Zero DNS Proxy — Local UDP DNS filter proxy.
//!
//! Binds to 127.0.0.1:53 and intercepts DNS queries.
//! Malicious domains (detected by DGA engine) get an NXDOMAIN response.
//! Clean domains are forwarded to the upstream DNS resolver (e.g. 9.9.9.9).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use super::ShieldZeroState;

/// Maximum DNS UDP packet size.
/// Modern DNS uses EDNS0 which allows up to 4096 bytes.
/// Google/YouTube responses frequently exceed the legacy 512-byte limit.
const MAX_DNS_PACKET: usize = 4096;

/// Handle to a running DNS proxy (used to stop it).
pub struct DnsProxyHandle {
    shutdown_tx: watch::Sender<bool>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl DnsProxyHandle {
    /// Signal the proxy to stop and wait for it.
    pub async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join_handle.await;
    }
}

/// Start the DNS proxy on 127.0.0.1:53.
///
/// Returns a handle that can be used to stop the proxy later.
pub async fn start_proxy(
    state: Arc<ShieldZeroState>,
    upstream: Ipv4Addr,
) -> Result<DnsProxyHandle, String> {
    let bind_addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind DNS proxy to {}: {}", bind_addr, e))?;

    let socket = Arc::new(socket);
    let upstream_addr: SocketAddr = SocketAddr::new(upstream.into(), 53);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    log::info!("[Shield Zero DNS] Proxy started on {}, upstream={}", bind_addr, upstream);

    let join_handle = tokio::spawn(proxy_loop(socket, state, upstream_addr, shutdown_rx));

    Ok(DnsProxyHandle {
        shutdown_tx,
        join_handle,
    })
}

/// Main proxy event loop — receives DNS queries, filters, and forwards.
async fn proxy_loop(
    socket: Arc<UdpSocket>,
    state: Arc<ShieldZeroState>,
    upstream_addr: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut buf = [0u8; MAX_DNS_PACKET];

    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::info!("[Shield Zero DNS] Proxy shutting down");
                    break;
                }
            }
            // Receive a DNS query
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, client_addr)) => {
                        let query = buf[..len].to_vec();
                        let socket_clone = socket.clone();
                        let state_clone = state.clone();

                        // Handle each query in its own task for concurrency
                        tokio::spawn(handle_query(
                            socket_clone,
                            state_clone,
                            upstream_addr,
                            client_addr,
                            query,
                        ));
                    }
                    Err(e) => {
                        log::warn!("[Shield Zero DNS] recv_from error: {}", e);
                    }
                }
            }
        }
    }
}

/// Handle a single DNS query: analyze, block or forward.
async fn handle_query(
    socket: Arc<UdpSocket>,
    state: Arc<ShieldZeroState>,
    upstream_addr: SocketAddr,
    client_addr: SocketAddr,
    query: Vec<u8>,
) {
    // Extract domain name from the DNS query
    let domain = match parse_dns_qname(&query) {
        Some(d) => d,
        None => {
            // Can't parse → just forward it
            forward_and_relay(&socket, &query, upstream_addr, client_addr).await;
            return;
        }
    };

    // Run DGA + blocklist analysis
    let analysis = state.analyze(&domain);

    if analysis.blocked {
        // Respond with NXDOMAIN
        println!("[Shield Zero DNS] ❌ BLOCKED: {} (verdict={}, score={:.2})",
            domain, analysis.verdict, analysis.score);
        let nxdomain = craft_nxdomain(&query);
        let _ = socket.send_to(&nxdomain, client_addr).await;
    } else {
        // Forward to upstream and relay response
        println!("[Shield Zero DNS] ✅ FORWARD: {} → upstream", domain);
        forward_and_relay(&socket, &query, upstream_addr, client_addr).await;
    }
}

/// Forward a DNS query to the upstream server and relay the response back.
async fn forward_and_relay(
    socket: &UdpSocket,
    query: &[u8],
    upstream_addr: SocketAddr,
    client_addr: SocketAddr,
) {
    // Create a separate socket for the upstream query
    let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("[Shield Zero DNS] Failed to create upstream socket: {}", e);
            return;
        }
    };

    if let Err(e) = upstream_socket.send_to(query, upstream_addr).await {
        log::warn!("[Shield Zero DNS] Failed to send to upstream: {}", e);
        return;
    }

    // Wait for response with a timeout
    let mut response_buf = [0u8; MAX_DNS_PACKET];
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        upstream_socket.recv_from(&mut response_buf),
    )
    .await
    {
        Ok(Ok((len, _))) => {
            let _ = socket.send_to(&response_buf[..len], client_addr).await;
        }
        Ok(Err(e)) => {
            log::warn!("[Shield Zero DNS] Upstream recv error: {}", e);
        }
        Err(_) => {
            log::warn!("[Shield Zero DNS] Upstream timeout");
        }
    }
}

// ─── DNS Packet Parsing ──────────────────────────────────────────────

/// Parse the QNAME (domain name) from a raw DNS query packet.
///
/// DNS wire format:
///   Header: 12 bytes
///   Question section: QNAME + QTYPE(2) + QCLASS(2)
///   QNAME: sequence of length-prefixed labels, terminated by 0x00
///
/// Example: "google.com" → [6,g,o,o,g,l,e,3,c,o,m,0]
pub fn parse_dns_qname(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 + 1 {
        return None; // Too short for header + at least 1 byte of QNAME
    }

    let mut pos = 12; // Skip DNS header
    let mut labels: Vec<String> = Vec::new();

    loop {
        if pos >= packet.len() {
            return None; // Ran past end
        }

        let label_len = packet[pos] as usize;
        if label_len == 0 {
            break; // End of QNAME
        }

        // Compression pointer check (0xC0 prefix) — shouldn't appear in
        // queries but handle gracefully
        if label_len & 0xC0 == 0xC0 {
            return None; // We don't handle compression in queries
        }

        // Sanity check: labels are max 63 bytes
        if label_len > 63 {
            return None;
        }

        pos += 1;
        if pos + label_len > packet.len() {
            return None; // Label extends past packet
        }

        let label = String::from_utf8_lossy(&packet[pos..pos + label_len]).to_string();
        labels.push(label);
        pos += label_len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Craft an NXDOMAIN response for a given DNS query.
///
/// We copy the query's Transaction ID and Question section,
/// then set the response flags:
///   QR=1 (response), AA=1 (authoritative), RCODE=3 (NXDOMAIN)
pub fn craft_nxdomain(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new(); // Invalid query
    }

    let mut response = query.to_vec();

    // Byte 2: QR=1, Opcode=0000, AA=1, TC=0, RD=1
    //   = 1_0000_1_0_1 = 0x85
    response[2] = 0x85;

    // Byte 3: RA=1, Z=000, RCODE=0011 (NXDOMAIN)
    //   = 1_000_0011 = 0x83
    response[3] = 0x83;

    // ANCOUNT = 0 (no answers)
    response[6] = 0;
    response[7] = 0;

    // NSCOUNT = 0
    response[8] = 0;
    response[9] = 0;

    // ARCOUNT = 0
    response[10] = 0;
    response[11] = 0;

    // Truncate to just header + question section (no answer/authority/additional)
    // Find end of question section: skip QNAME then skip QTYPE(2) + QCLASS(2)
    let mut pos = 12;
    while pos < response.len() {
        let label_len = response[pos] as usize;
        if label_len == 0 {
            pos += 1; // Skip the null terminator
            break;
        }
        pos += 1 + label_len;
    }
    pos += 4; // QTYPE + QCLASS

    if pos <= response.len() {
        response.truncate(pos);
    }

    response
}

// ─── Unit Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for a given domain.
    fn build_dns_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // Header (12 bytes)
        packet.extend_from_slice(&[
            0xAB, 0xCD, // Transaction ID
            0x01, 0x00, // Flags: QR=0, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ]);

        // QNAME
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // Null terminator

        // QTYPE = A (1) and QCLASS = IN (1)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        packet
    }

    #[test]
    fn test_parse_qname_simple() {
        let query = build_dns_query("google.com");
        assert_eq!(parse_dns_qname(&query), Some("google.com".to_string()));
    }

    #[test]
    fn test_parse_qname_subdomain() {
        let query = build_dns_query("www.example.co.uk");
        assert_eq!(parse_dns_qname(&query), Some("www.example.co.uk".to_string()));
    }

    #[test]
    fn test_parse_qname_single_label() {
        let query = build_dns_query("localhost");
        assert_eq!(parse_dns_qname(&query), Some("localhost".to_string()));
    }

    #[test]
    fn test_parse_qname_too_short() {
        let short = vec![0u8; 10];
        assert_eq!(parse_dns_qname(&short), None);
    }

    #[test]
    fn test_nxdomain_response() {
        let query = build_dns_query("malware.xyz");
        let response = craft_nxdomain(&query);

        // Transaction ID preserved
        assert_eq!(response[0], 0xAB);
        assert_eq!(response[1], 0xCD);

        // QR=1 (response)
        assert_ne!(response[2] & 0x80, 0);

        // RCODE=3 (NXDOMAIN)
        assert_eq!(response[3] & 0x0F, 3);

        // ANCOUNT = 0
        assert_eq!(response[6], 0);
        assert_eq!(response[7], 0);

        // Can still parse the domain out of the response
        assert_eq!(parse_dns_qname(&response), Some("malware.xyz".to_string()));
    }

    #[test]
    fn test_nxdomain_preserves_question() {
        let query = build_dns_query("test.example.org");
        let response = craft_nxdomain(&query);

        // QDCOUNT = 1 (question preserved)
        assert_eq!(response[4], 0x00);
        assert_eq!(response[5], 0x01);
    }

    #[test]
    fn test_parse_dga_domain() {
        let query = build_dns_query("eywonbdkjgmvsstgkblztpkfxhi.ru");
        assert_eq!(
            parse_dns_qname(&query),
            Some("eywonbdkjgmvsstgkblztpkfxhi.ru".to_string())
        );
    }
}
