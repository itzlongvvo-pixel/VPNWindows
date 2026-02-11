/**
 * Nera VPN — WireGuard Header Obfuscation Proxy (Server-Side)
 * 
 * Sits between stunnel (TLS termination) and WireGuard:
 *   Client → stunnel:8443 (TLS) → this proxy:51822 (UDP) → WireGuard:51821 (UDP)
 * 
 * Each incoming UDP packet has its first 16 bytes XOR'd with a static key.
 * This proxy reverses the XOR to reconstruct the original WireGuard packet,
 * then forwards it to the WireGuard server.
 * 
 * Usage:
 *   node obfuscation-proxy.js
 * 
 * Environment:
 *   OBF_LISTEN_PORT  - Port to listen on (default: 51822)
 *   OBF_WG_HOST      - WireGuard host (default: 127.0.0.1)
 *   OBF_WG_PORT      - WireGuard port (default: 51821)
 */

const dgram = require('dgram');

// Configuration
const LISTEN_PORT = parseInt(process.env.OBF_LISTEN_PORT || '51822');
const WG_HOST = process.env.OBF_WG_HOST || '127.0.0.1';
const WG_PORT = parseInt(process.env.OBF_WG_PORT || '51821');

// Static 16-byte XOR key — MUST match client-side OBF_KEY in stealth.rs
// This is NOT a security key (TLS provides encryption).
// It only disguises WireGuard packet format to defeat DPI.
const OBF_KEY = Buffer.from([
    0xA3, 0x7B, 0xF2, 0x1E, 0x9C, 0x4D, 0x68, 0x05,
    0xE1, 0x3A, 0x87, 0xC6, 0x54, 0x0F, 0xD9, 0xB2,
]);

console.log(`[Obfuscation Proxy] Starting...`);
console.log(`[Obfuscation Proxy] Listen: UDP :${LISTEN_PORT}`);
console.log(`[Obfuscation Proxy] Forward: ${WG_HOST}:${WG_PORT}`);
console.log(`[Obfuscation Proxy] Key (first 4): ${OBF_KEY.slice(0, 4).toString('hex')}...`);

// XOR the first 16 bytes of a buffer with the obfuscation key
function xorHeader(buf) {
    const result = Buffer.from(buf);
    const len = Math.min(16, result.length);
    for (let i = 0; i < len; i++) {
        result[i] ^= OBF_KEY[i];
    }
    return result;
}

// Create the proxy socket
const proxy = dgram.createSocket('udp4');

// Track client addresses for responses
const clientMap = new Map();

proxy.on('message', (msg, rinfo) => {
    // De-obfuscate: XOR first 16 bytes to recover original WG packet
    const deobfuscated = xorHeader(msg);

    // Remember this client for return traffic
    const clientKey = `${rinfo.address}:${rinfo.port}`;
    clientMap.set(clientKey, { address: rinfo.address, port: rinfo.port, lastSeen: Date.now() });

    // Forward to WireGuard
    proxy.send(deobfuscated, WG_PORT, WG_HOST, (err) => {
        if (err) console.error(`[Obfuscation Proxy] Forward error: ${err.message}`);
    });
});

proxy.on('error', (err) => {
    console.error(`[Obfuscation Proxy] Error: ${err.message}`);
    proxy.close();
});

proxy.bind(LISTEN_PORT, () => {
    console.log(`[Obfuscation Proxy] Listening on UDP :${LISTEN_PORT}`);
    console.log(`[Obfuscation Proxy] Forwarding deobfuscated packets to ${WG_HOST}:${WG_PORT}`);
});

// Cleanup stale client entries every 60s
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of clientMap) {
        if (now - value.lastSeen > 120000) {
            clientMap.delete(key);
        }
    }
}, 60000);

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('[Obfuscation Proxy] Shutting down...');
    proxy.close();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('[Obfuscation Proxy] Shutting down...');
    proxy.close();
    process.exit(0);
});
