/**
 * Nera VPN™ - Ephemeral Port Forwarding (Beta)
 * Copyright © 2025 Vio Holdings LLC. All rights reserved.
 * 
 * Proton-style ephemeral port allocation via iptables DNAT.
 * Ports are randomly assigned, session-bound, and auto-expire.
 * 
 * Beta Mitigations:
 *  - 1 port per user (access_token)
 *  - Max 10 concurrent ports globally
 *  - 120s TTL with 60s heartbeat renewal
 *  - High ports only (30000-60000)
 */

const express = require('express');
const { execSync } = require('child_process');
const crypto = require('crypto');
const router = express.Router();

// ============================================================
// In-Memory Port State
// ============================================================
const activePorts = new Map(); // tokenHash -> { port, clientIP, expiresAt }
const MAX_PORTS = 10;
const PORT_MIN = 30000;
const PORT_MAX = 60000;
const TTL_MS = 120 * 1000; // 120 seconds
const CLEANUP_INTERVAL = 30 * 1000; // 30 seconds

// ============================================================
// Helpers
// ============================================================

/**
 * Hash the access token to use as a map key (privacy: never store raw tokens)
 */
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
}

/**
 * Pick a random port in [PORT_MIN, PORT_MAX] that isn't already in use
 */
function pickRandomPort() {
    const usedPorts = new Set([...activePorts.values()].map(e => e.port));
    let attempts = 0;
    while (attempts < 100) {
        const port = PORT_MIN + Math.floor(Math.random() * (PORT_MAX - PORT_MIN));
        if (!usedPorts.has(port)) return port;
        attempts++;
    }
    return null; // couldn't find a free port
}

/**
 * Add iptables DNAT + FORWARD rules for a port → client VPN IP
 */
function addIptablesRules(port, clientIP) {
    const isProduction = process.env.NODE_ENV === 'production';
    if (!isProduction) {
        console.log(`[PortFwd] DEV MODE: Would add iptables rules for port ${port} → ${clientIP}`);
        return true;
    }

    try {
        // DNAT: Redirect incoming traffic on this port to the client's VPN IP
        execSync(`iptables -t nat -A PREROUTING -i eth0 -p tcp --dport ${port} -j DNAT --to-destination ${clientIP}`);
        execSync(`iptables -t nat -A PREROUTING -i eth0 -p udp --dport ${port} -j DNAT --to-destination ${clientIP}`);
        // FORWARD: Allow the forwarded traffic through
        execSync(`iptables -A FORWARD -p tcp --dport ${port} -d ${clientIP} -j ACCEPT`);
        execSync(`iptables -A FORWARD -p udp --dport ${port} -d ${clientIP} -j ACCEPT`);
        console.log(`[PortFwd] ✅ iptables rules added: port ${port} → ${clientIP}`);
        return true;
    } catch (e) {
        console.error(`[PortFwd] ❌ iptables add failed:`, e.message);
        return false;
    }
}

/**
 * Remove iptables DNAT + FORWARD rules for a port → client VPN IP
 */
function removeIptablesRules(port, clientIP) {
    const isProduction = process.env.NODE_ENV === 'production';
    if (!isProduction) {
        console.log(`[PortFwd] DEV MODE: Would remove iptables rules for port ${port} → ${clientIP}`);
        return;
    }

    try {
        execSync(`iptables -t nat -D PREROUTING -i eth0 -p tcp --dport ${port} -j DNAT --to-destination ${clientIP}`);
        execSync(`iptables -t nat -D PREROUTING -i eth0 -p udp --dport ${port} -j DNAT --to-destination ${clientIP}`);
        execSync(`iptables -D FORWARD -p tcp --dport ${port} -d ${clientIP} -j ACCEPT`);
        execSync(`iptables -D FORWARD -p udp --dport ${port} -d ${clientIP} -j ACCEPT`);
        console.log(`[PortFwd] ✅ iptables rules removed: port ${port}`);
    } catch (e) {
        console.error(`[PortFwd] ⚠️ iptables remove failed (may already be gone):`, e.message);
    }
}

/**
 * Validate access token format (same logic as /api/connect)
 */
function validateToken(accessToken) {
    try {
        const tokenBuffer = Buffer.from(accessToken, 'base64');
        if (tokenBuffer.length < 64) return false;
        return true;
    } catch {
        return false;
    }
}

// ============================================================
// POST /api/port-forward
// Request a new ephemeral port
// ============================================================
router.post('/api/port-forward', (req, res) => {
    try {
        const { access_token, client_ip } = req.body;

        if (!access_token || !client_ip) {
            return res.status(400).json({ error: 'Missing access_token or client_ip' });
        }

        if (!validateToken(access_token)) {
            return res.status(403).json({ error: 'Invalid access token' });
        }

        // Validate client_ip looks like a VPN IP (10.66.66.x)
        if (!/^10\.66\.66\.\d{1,3}$/.test(client_ip)) {
            return res.status(400).json({ error: 'Invalid client IP format' });
        }

        const tokenKey = hashToken(access_token);

        // Check 1-port-per-user limit
        if (activePorts.has(tokenKey)) {
            const existing = activePorts.get(tokenKey);
            return res.json({
                port: existing.port,
                expires_in: Math.max(0, Math.floor((existing.expiresAt - Date.now()) / 1000)),
                message: 'Port already assigned'
            });
        }

        // Check global limit
        if (activePorts.size >= MAX_PORTS) {
            return res.status(503).json({ error: 'Port forwarding capacity reached. Try again later.' });
        }

        // Pick a random port
        const port = pickRandomPort();
        if (!port) {
            return res.status(503).json({ error: 'No available ports. Try again later.' });
        }

        // Add iptables rules
        if (!addIptablesRules(port, client_ip)) {
            return res.status(500).json({ error: 'Failed to configure port forwarding on server' });
        }

        // Store allocation
        const expiresAt = Date.now() + TTL_MS;
        activePorts.set(tokenKey, { port, clientIP: client_ip, expiresAt });

        console.log(`[PortFwd] 🔌 Allocated port ${port} → ${client_ip} (${activePorts.size}/${MAX_PORTS} active)`);

        res.json({
            port,
            expires_in: Math.floor(TTL_MS / 1000),
            message: 'Port forwarding enabled'
        });

    } catch (error) {
        console.error('[PortFwd] ❌ Request error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// POST /api/port-forward/renew
// Heartbeat to keep the port alive
// ============================================================
router.post('/api/port-forward/renew', (req, res) => {
    try {
        const { access_token } = req.body;

        if (!access_token) {
            return res.status(400).json({ error: 'Missing access_token' });
        }

        const tokenKey = hashToken(access_token);
        const entry = activePorts.get(tokenKey);

        if (!entry) {
            return res.status(404).json({ error: 'No active port forwarding found' });
        }

        // Reset TTL
        entry.expiresAt = Date.now() + TTL_MS;
        activePorts.set(tokenKey, entry);

        console.log(`[PortFwd] 💓 Renewed port ${entry.port} (${Math.floor(TTL_MS / 1000)}s TTL)`);

        res.json({
            port: entry.port,
            renewed: true,
            expires_in: Math.floor(TTL_MS / 1000)
        });

    } catch (error) {
        console.error('[PortFwd] ❌ Renew error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// DELETE /api/port-forward
// Release a port explicitly
// ============================================================
router.delete('/api/port-forward', (req, res) => {
    try {
        const { access_token } = req.body;

        if (!access_token) {
            return res.status(400).json({ error: 'Missing access_token' });
        }

        const tokenKey = hashToken(access_token);
        const entry = activePorts.get(tokenKey);

        if (!entry) {
            return res.json({ released: true, message: 'No active port to release' });
        }

        // Remove iptables rules
        removeIptablesRules(entry.port, entry.clientIP);
        activePorts.delete(tokenKey);

        console.log(`[PortFwd] 🔓 Released port ${entry.port} (${activePorts.size}/${MAX_PORTS} active)`);

        res.json({ released: true, message: `Port ${entry.port} released` });

    } catch (error) {
        console.error('[PortFwd] ❌ Release error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// Cleanup Timer: Expire stale ports every 30s
// ============================================================
setInterval(() => {
    const now = Date.now();
    let expired = 0;

    for (const [tokenKey, entry] of activePorts.entries()) {
        if (now > entry.expiresAt) {
            removeIptablesRules(entry.port, entry.clientIP);
            activePorts.delete(tokenKey);
            expired++;
            console.log(`[PortFwd] ⏰ Expired port ${entry.port} (TTL exceeded)`);
        }
    }

    if (expired > 0) {
        console.log(`[PortFwd] Cleanup: ${expired} expired, ${activePorts.size} remaining`);
    }
}, CLEANUP_INTERVAL);

// ============================================================
// GET /api/port-forward/status (debug/admin endpoint)
// ============================================================
router.get('/api/port-forward/status', (req, res) => {
    res.json({
        active: activePorts.size,
        max: MAX_PORTS,
        ports: [...activePorts.values()].map(e => ({
            port: e.port,
            expires_in: Math.max(0, Math.floor((e.expiresAt - Date.now()) / 1000))
        }))
    });
});

module.exports = router;
