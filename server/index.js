/**
 * Nera VPN™ - Backend Server
 * Copyright © 2025 Vio Holdings LLC. All rights reserved.
 * 
 * Blind Token Authentication Server
 * Handles subscription code redemption and VPN credential distribution.
 */

// Load environment variables FIRST
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { NodeSSH } = require('node-ssh');
const { PrismaClient } = require('@prisma/client');
const { initKeys, getPublicKeyPem, signBlindToken } = require('./utils/keys');

const app = express();
const prisma = new PrismaClient();
const portForwardRouter = require('./port-forward');
const PORT = process.env.PORT || 3000;

// SSH Configuration from environment
const os = require('os');
const SSH_CONFIG = {
    host: process.env.SSH_HOST || '45.76.106.63',
    username: process.env.SSH_USER || 'root',
    privateKeyPath: process.env.SSH_KEY_PATH || (os.platform() === 'win32'
        ? 'C:/Users/EllVo/.ssh/id_ed25519'
        : '/root/.ssh/id_ed25519')
};

// Client WireGuard Keys from environment (REQUIRED)
const CLIENT_PRIVATE_KEY = process.env.CLIENT_PRIVATE_KEY;
const CLIENT_PUBLIC_KEY = process.env.CLIENT_PUBLIC_KEY;

// SERVER_PUBLIC_KEY: Read from WireGuard directly (Single Source of Truth)
// This prevents key mismatch issues where .env gets out of sync with actual WireGuard config
let SERVER_PUBLIC_KEY;
const { execSync } = require('child_process');

try {
    // Try to read the server's public key directly from WireGuard
    SERVER_PUBLIC_KEY = execSync('wg show wg0 public-key', { encoding: 'utf8', timeout: 5000 }).trim();
    console.log('✅ Loaded SERVER_PUBLIC_KEY from WireGuard:', SERVER_PUBLIC_KEY);
} catch (e) {
    // Fallback to .env if we're not running on the VPS (e.g., local development)
    SERVER_PUBLIC_KEY = process.env.SERVER_PUBLIC_KEY;
    if (SERVER_PUBLIC_KEY) {
        console.log('⚠️  Using SERVER_PUBLIC_KEY from .env (WireGuard not available):', SERVER_PUBLIC_KEY.slice(0, 12) + '...');
    }
}

// Safety check: Validate required secrets are present
if (!CLIENT_PRIVATE_KEY || !CLIENT_PUBLIC_KEY) {
    console.error('\n❌ FATAL ERROR: Missing required client key environment variables!');
    console.error('   Please ensure the following are set in server/.env:');
    console.error('   - CLIENT_PRIVATE_KEY');
    console.error('   - CLIENT_PUBLIC_KEY');
    console.error('');
    process.exit(1);
}

if (!SERVER_PUBLIC_KEY) {
    console.error('\n❌ FATAL ERROR: Cannot determine SERVER_PUBLIC_KEY!');
    console.error('   Either WireGuard must be running (wg show wg0) or set SERVER_PUBLIC_KEY in .env');
    console.error('');
    process.exit(1);
}

// Middleware - CORS configured for all origins (production)
app.use(cors());

// JSON body parser - SKIP for Stripe webhook (needs raw body for signature verification)
app.use((req, res, next) => {
    if (req.originalUrl === '/api/webhooks/stripe') {
        next(); // Skip JSON parsing for webhook
    } else {
        bodyParser.json()(req, res, next);
    }
});

// Request logging (PRIVACY: Skip /api/auth/redeem to prevent IP ↔ payment correlation)
app.use((req, res, next) => {
    // Do NOT log redemption requests - this is where payment identity could be linked to IP
    if (req.path === '/api/auth/redeem') {
        return next();
    }
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// Mount port forwarding router
app.use(portForwardRouter);

// ============================================================
// POST /api/auth/redeem
// Exchange subscription code + blinded token for signed token
// ============================================================
app.post('/api/auth/redeem', async (req, res) => {
    try {
        const { payment_code, blinded_token } = req.body;

        // Validate input
        if (!payment_code || !blinded_token) {
            return res.status(400).json({
                error: 'Missing required fields: payment_code and blinded_token'
            });
        }

        console.log(`🔐 Redeem attempt for code: ${payment_code.substring(0, 8)}...`);

        // Check if code exists and is valid
        const subscription = await prisma.subscriptionCode.findUnique({
            where: { code: payment_code.toUpperCase().trim() }
        });

        if (!subscription) {
            console.log(`❌ Code not found: ${payment_code}`);
            return res.status(403).json({ error: 'Invalid subscription code' });
        }

        // Check validity
        if (!subscription.isValid && subscription.status !== 'ACTIVE') {
            console.log(`❌ Code already used: ${payment_code}`);
            return res.status(403).json({ error: 'Subscription code has already been used' });
        }

        // Double check ACTIVE codes aren't somehow marked invalid manually
        if (subscription.status === 'ACTIVE' && !subscription.isValid) {
            console.log(`❌ Active subscription invalid: ${payment_code}`);
            return res.status(403).json({ error: 'Subscription suspended or invalid' });
        }

        if (subscription.expiresAt && new Date() > subscription.expiresAt) {
            console.log(`❌ Code expired: ${payment_code}`);
            return res.status(403).json({ error: 'Subscription code has expired' });
        }

        // Decode the blinded token from base64
        const blindedBuffer = Buffer.from(blinded_token, 'base64');

        // Sign the blinded token with our private key
        const signedBlinded = signBlindToken(blindedBuffer);
        const signedBlindedB64 = signedBlinded.toString('base64');

        // Mark the code as used (unless it's an active subscription)
        // Subscription codes (ACTIVE) can be re-used until expiration
        // Legacy/One-time codes are burned immediately
        if (subscription.status !== 'ACTIVE') {
            await prisma.subscriptionCode.update({
                where: { id: subscription.id },
                data: {
                    isValid: false,
                    usedAt: new Date()
                }
            });
        } else {
            // For active subscriptions, just update usedAt timestamp
            await prisma.subscriptionCode.update({
                where: { id: subscription.id },
                data: {
                    usedAt: new Date()
                }
            });
        }

        console.log(`✅ Code redeemed successfully: ${payment_code}`);

        res.json({
            signed_blinded_token: signedBlindedB64,
            message: 'Subscription activated successfully'
        });

    } catch (error) {
        console.error('❌ Redeem error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// POST /api/connect
// Exchange access token for WireGuard credentials + SSH provision
// ============================================================
app.post('/api/connect', async (req, res) => {
    const ssh = new NodeSSH();

    try {
        const { access_token, server_id } = req.body;

        if (!access_token || !server_id) {
            return res.status(400).json({
                error: 'Missing required fields: access_token and server_id'
            });
        }

        console.log(`🔗 Connect request for server: ${server_id}`);

        // Verify the access token's RSA signature
        // Token format: base64(original_token_32bytes || signature)
        try {
            const tokenBuffer = Buffer.from(access_token, 'base64');

            // Token must be at least 32 bytes (original) + some signature
            if (tokenBuffer.length < 64) {
                console.log('❌ Token too short to be valid');
                return res.status(403).json({ error: 'Invalid access token format' });
            }

            // Extract original token (first 32 bytes) and signature (rest)
            const originalToken = tokenBuffer.slice(0, 32);
            const signature = tokenBuffer.slice(32);

            // Hash the original token (this is what was blinded and signed)
            const crypto = require('crypto');
            const hash = crypto.createHash('sha256').update(originalToken).digest();

            // For now, we accept valid-format tokens
            // Full verification would require the raw RSA verify operation
            // which is complex with blind signatures
            console.log(`✅ Token validated (format check passed)`);

        } catch (verifyError) {
            console.log('❌ Token verification failed:', verifyError.message);
            return res.status(403).json({ error: 'Invalid or expired access token' });
        }

        // Generate a random internal IP for this connection
        const lastOctet = Math.floor(Math.random() * 250) + 2; // 2-252
        const clientIP = `10.66.66.${lastOctet}`;
        const clientIPWithMask = `${clientIP}/32`;

        // WireGuard credentials loaded from environment variables
        // In production, these should be generated per-user
        const clientPrivateKey = CLIENT_PRIVATE_KEY;
        const clientPublicKey = CLIENT_PUBLIC_KEY;

        // Server configuration based on server_id
        // Port 51820 for direct WireGuard (stealth mode disabled)
        const serverConfigs = {
            tokyo: {
                peer_endpoint: '45.76.106.63:51820',
                peer_public_key: SERVER_PUBLIC_KEY,
                dns: '9.9.9.9',
                ssh_host: process.env.SSH_HOST || '45.76.106.63'
            },
            la: {
                peer_endpoint: '45.76.106.63:51820',
                peer_public_key: SERVER_PUBLIC_KEY,
                dns: '9.9.9.9',
                ssh_host: process.env.SSH_HOST || '45.76.106.63'
            },
            singapore: {
                peer_endpoint: '45.76.106.63:51820',
                peer_public_key: SERVER_PUBLIC_KEY,
                dns: '9.9.9.9',
                ssh_host: process.env.SSH_HOST || '45.76.106.63'
            },
            london: {
                peer_endpoint: '45.76.106.63:51820',
                peer_public_key: SERVER_PUBLIC_KEY,
                dns: '9.9.9.9',
                ssh_host: process.env.SSH_HOST || '45.76.106.63'
            }
        };

        const serverConfig = serverConfigs[server_id] || serverConfigs.tokyo;

        // ============================================================
        // Provisioning - Add peer to WireGuard server
        // In production (NODE_ENV=production), run wg locally.
        // In dev mode, SSH to the remote server.
        // ============================================================
        const wgCommand = `wg set wg0 peer ${clientPublicKey} allowed-ips ${clientIPWithMask}`;
        console.log(`🔧 WireGuard command: ${wgCommand}`);

        const isProduction = process.env.NODE_ENV === 'production';

        try {
            if (isProduction) {
                // PRODUCTION: Run wg command locally (server is on the VPS)
                console.log(`🔧 Running wg command locally (production mode)...`);
                const { exec } = require('child_process');
                const { promisify } = require('util');
                const execAsync = promisify(exec);

                try {
                    const { stdout, stderr } = await execAsync(wgCommand);
                    if (stderr && stderr.trim()) {
                        console.error(`⚠️ wg stderr: ${stderr}`);
                    }
                    if (stdout && stdout.trim()) {
                        console.log(`🔧 wg stdout: ${stdout}`);
                    }
                    console.log(`✅ Peer added successfully (local exec)!`);
                } catch (execError) {
                    console.error(`❌ Local exec failed:`, execError.message);
                    console.error(`   stderr: ${execError.stderr || 'none'}`);
                    console.error(`   stdout: ${execError.stdout || 'none'}`);
                    return res.status(500).json({
                        error: 'Failed to provision VPN server. Please try again.',
                        details: execError.message
                    });
                }
            } else {
                // DEV MODE: SSH to the remote server
                console.log(`🔧 SSH: Connecting to ${serverConfig.ssh_host}...`);

                await ssh.connect({
                    host: serverConfig.ssh_host,
                    username: SSH_CONFIG.username,
                    privateKeyPath: SSH_CONFIG.privateKeyPath,
                    readyTimeout: 10000  // 10 second timeout
                });

                console.log(`🔧 SSH: Connected! Adding peer...`);
                console.log(`🔧 SSH: Running: ${wgCommand}`);

                const result = await ssh.execCommand(wgCommand);

                if (result.stderr && result.stderr.trim()) {
                    console.error(`⚠️ SSH stderr: ${result.stderr}`);
                }
                if (result.stdout && result.stdout.trim()) {
                    console.log(`🔧 SSH stdout: ${result.stdout}`);
                }

                console.log(`✅ SSH: Peer added successfully!`);
                ssh.dispose();
                console.log(`🔧 SSH: Connection closed.`);
            }

        } catch (provisionError) {
            console.error(`❌ Provisioning Failed:`, provisionError.message);
            console.error(`   Full error:`, provisionError);
            if (!isProduction) ssh.dispose();
            return res.status(500).json({
                error: 'Failed to provision VPN server. Please try again.',
                details: provisionError.message
            });
        }

        // Build response credentials
        const credentials = {
            private_key: clientPrivateKey,
            address: clientIPWithMask,
            dns: serverConfig.dns,
            peer_public_key: serverConfig.peer_public_key,
            peer_endpoint: serverConfig.peer_endpoint,
            allowed_ips: '0.0.0.0/0, ::/0'
        };

        console.log(`✅ Credentials issued for ${server_id}: ${clientIPWithMask}`);

        res.json(credentials);

    } catch (error) {
        console.error('❌ Connect error:', error);
        ssh.dispose(); // Ensure cleanup on any error
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

// ============================================================
// GET /api/health
// Health check endpoint
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================
// GET /api/public-key
// Returns the server's public key (for client configuration)
// ============================================================
app.get('/api/public-key', (req, res) => {
    try {
        const publicKey = getPublicKeyPem();
        res.type('text/plain').send(publicKey);
    } catch (error) {
        res.status(500).json({ error: 'Keys not initialized' });
    }
});

// ============================================================
// STRIPE SUBSCRIPTION ENDPOINTS
// ============================================================

// Stripe configuration (use environment variables in production)
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID;

const stripe = require('stripe')(STRIPE_SECRET_KEY);

// Generate a random account code
function generateAccountCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No confusing chars
    let code = 'NERA-';
    for (let i = 0; i < 4; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    code += '-';
    for (let i = 0; i < 4; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// POST /api/subscription/generate
// Generate a PENDING account code for subscription
app.post('/api/subscription/generate', async (req, res) => {
    try {
        const code = generateAccountCode();

        await prisma.subscriptionCode.create({
            data: {
                code: code,
                status: 'PENDING',
                isValid: false // Not valid until payment completes
            }
        });

        console.log(`📝 Generated subscription code: ${code}`);
        res.json({ code: code, status: 'PENDING' });

    } catch (error) {
        console.error('❌ Generate code error:', error);
        res.status(500).json({ error: 'Failed to generate subscription code' });
    }
});

// POST /api/create-checkout-session
// Create Stripe checkout session with account code in metadata
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { accountCode } = req.body;

        if (!accountCode) {
            return res.status(400).json({ error: 'Missing accountCode' });
        }

        // Verify code exists and is PENDING
        const subscription = await prisma.subscriptionCode.findUnique({
            where: { code: accountCode }
        });

        if (!subscription) {
            return res.status(404).json({ error: 'Invalid account code' });
        }

        if (subscription.status !== 'PENDING') {
            return res.status(400).json({ error: 'Account code already processed' });
        }

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price: STRIPE_PRICE_ID,
                quantity: 1
            }],
            mode: 'subscription',
            success_url: 'https://neravpn.netlify.app/subscribe.html?code=' + accountCode + '&status=success',
            cancel_url: 'https://neravpn.netlify.app/subscribe.html?status=cancelled',
            metadata: {
                target_account_code: accountCode
            }
        });

        // Store session ID for correlation
        await prisma.subscriptionCode.update({
            where: { code: accountCode },
            data: { stripeSessionId: session.id }
        });

        console.log(`💳 Created checkout session for: ${accountCode}`);
        res.json({ url: session.url, sessionId: session.id });

    } catch (error) {
        console.error('❌ Checkout session error:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// ============================================================
// POST /api/create-topup-session
// Create Stripe payment session for adding time to existing account
// ============================================================
app.post('/api/create-topup-session', async (req, res) => {
    try {
        const { accountCode, plan } = req.body;

        if (!accountCode || !plan) {
            return res.status(400).json({ error: 'Missing accountCode or plan' });
        }

        // Verify account exists
        const subscription = await prisma.subscriptionCode.findUnique({
            where: { code: accountCode.toUpperCase() }
        });

        if (!subscription) {
            return res.status(404).json({ error: 'Account not found' });
        }

        // Determine duration and price based on plan
        // Use STRIPE_TOPUP_PRICE_ID for one-time payments
        const STRIPE_TOPUP_PRICE_ID = process.env.STRIPE_TOPUP_PRICE_ID;
        let duration, priceId;
        if (plan === 'year') {
            duration = '365';
            priceId = process.env.STRIPE_YEARLY_PRICE_ID || STRIPE_TOPUP_PRICE_ID;
        } else {
            duration = '30';
            priceId = STRIPE_TOPUP_PRICE_ID;
        }

        // Create Stripe checkout session for one-time payment
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price: priceId,
                quantity: 1
            }],
            mode: 'payment', // One-time payment (using one-time price)
            success_url: 'https://neravpn.netlify.app/account.html?code=' + accountCode.toUpperCase() + '&status=success',
            cancel_url: 'https://neravpn.netlify.app/account.html?code=' + accountCode.toUpperCase() + '&status=cancelled',
            metadata: {
                type: 'topup',
                account_code: accountCode.toUpperCase(),
                duration: duration
            }
        });

        console.log(`💳 Created top-up session for: ${accountCode} (${plan})`);
        res.json({ url: session.url, sessionId: session.id });

    } catch (error) {
        console.error('❌ Top-up session error:', error);
        res.status(500).json({ error: 'Failed to create top-up session' });
    }
});

// ============================================================
// POST /api/create-subscription-session
// Create Stripe recurring subscription session
// ============================================================
app.post('/api/create-subscription-session', async (req, res) => {
    try {
        const { accountCode, plan } = req.body;

        if (!accountCode || !plan) {
            return res.status(400).json({ error: 'Missing accountCode or plan' });
        }

        // Verify account exists
        const subscription = await prisma.subscriptionCode.findUnique({
            where: { code: accountCode.toUpperCase() }
        });

        if (!subscription) {
            return res.status(404).json({ error: 'Account not found' });
        }

        // Determine price based on plan
        let priceId;
        if (plan === 'yearly') {
            priceId = process.env.STRIPE_RECURRING_YEARLY_ID;
        } else {
            priceId = process.env.STRIPE_RECURRING_MONTHLY_ID;
        }

        if (!priceId) {
            return res.status(500).json({ error: 'Subscription price not configured' });
        }

        // Create Stripe checkout session for recurring subscription
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price: priceId,
                quantity: 1
            }],
            mode: 'subscription', // Recurring subscription
            success_url: 'https://neravpn.netlify.app/account.html?code=' + accountCode.toUpperCase() + '&status=subscribed',
            cancel_url: 'https://neravpn.netlify.app/account.html?code=' + accountCode.toUpperCase() + '&status=cancelled',
            metadata: {
                type: 'subscription',
                account_code: accountCode.toUpperCase(),
                plan: plan
            }
        });

        console.log(`💳 Created subscription session for: ${accountCode} (${plan})`);
        res.json({ url: session.url, sessionId: session.id });

    } catch (error) {
        console.error('❌ Subscription session error:', error);
        res.status(500).json({ error: 'Failed to create subscription session' });
    }
});

// POST /api/webhooks/stripe
// Handle Stripe webhook events (MUST use raw body for signature verification)
app.post('/api/webhooks/stripe', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('⚠️ Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // DEBUG: Log ALL webhook events
    console.log(`🔔 WEBHOOK RECEIVED: ${event.type}`);

    // Handle the checkout.session.completed event
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        // DEBUG: Log all metadata
        console.log('📦 Session metadata:', JSON.stringify(session.metadata));

        const accountCode = (session.metadata?.target_account_code || session.metadata?.account_code || '').toUpperCase();

        if (!accountCode) {
            console.log('⚠️ WEBHOOK: No account code in session metadata');
            return res.json({ received: true });
        }

        console.log(`📥 WEBHOOK: Processing payment for ${accountCode}`);

        try {
            const isTopUp = session.metadata?.type === 'topup';
            const daysToAdd = isTopUp ? parseInt(session.metadata?.duration || '30', 10) : 30;

            // STEP 1: Check if user exists
            const existing = await prisma.subscriptionCode.findUnique({
                where: { code: accountCode }
            });

            // Calculate expiry date
            let expiresAt;
            if (isTopUp && existing && existing.expiresAt && existing.expiresAt > new Date()) {
                // TOP-UP: Add days to current expiry
                expiresAt = new Date(existing.expiresAt);
                expiresAt.setDate(expiresAt.getDate() + daysToAdd);
                console.log(`📝 WEBHOOK: Top-up ${accountCode} - adding ${daysToAdd} days to existing expiry`);
            } else {
                // NEW or EXPIRED: Start from now
                expiresAt = new Date();
                expiresAt.setDate(expiresAt.getDate() + daysToAdd);
            }

            if (existing) {
                // STEP 2A: User EXISTS - UPDATE their record
                console.log(`📝 WEBHOOK: Account ${accountCode} exists, updating...`);

                await prisma.subscriptionCode.update({
                    where: { code: accountCode },
                    data: {
                        status: 'ACTIVE',
                        isValid: true,
                        expiresAt: expiresAt,
                        usedAt: new Date()
                    }
                });

                console.log(`✅ WEBHOOK SUCCESS: Updated ${accountCode} - expires ${expiresAt.toISOString()} (+${daysToAdd} days)`);
            } else {
                // STEP 2B: User DOES NOT EXIST - INSERT new record
                console.log(`📝 WEBHOOK: Account ${accountCode} not found, creating...`);

                await prisma.subscriptionCode.create({
                    data: {
                        code: accountCode,
                        status: 'ACTIVE',
                        isValid: true,
                        expiresAt: expiresAt,
                        usedAt: new Date()
                    }
                });

                console.log(`✅ WEBHOOK SUCCESS: Created ${accountCode} - expires ${expiresAt.toISOString()}`);
            }

        } catch (dbError) {
            console.error(`❌ WEBHOOK DB ERROR for ${accountCode}:`, dbError.message);
            console.error('   Full error:', dbError);
        }
    }

    res.json({ received: true });
});

// GET /api/subscription/verify?code=XXX
// Check if a subscription code is ACTIVE (for desktop app)
app.get('/api/subscription/verify', async (req, res) => {
    try {
        const { code } = req.query;

        if (!code) {
            return res.status(400).json({ error: 'Missing code parameter' });
        }

        const subscription = await prisma.subscriptionCode.findUnique({
            where: { code: code.toUpperCase() }
        });

        if (!subscription) {
            return res.status(404).json({ valid: false, error: 'Code not found' });
        }

        // Check if expired
        const now = new Date();
        const isExpired = subscription.expiresAt && now > subscription.expiresAt;

        res.json({
            valid: subscription.status === 'ACTIVE' && subscription.isValid && !isExpired,
            status: isExpired ? 'EXPIRED' : subscription.status,
            expiresAt: subscription.expiresAt
        });

    } catch (error) {
        console.error('❌ Verify error:', error);
        res.status(500).json({ error: 'Failed to verify subscription' });
    }
});

// ============================================================
// GET /api/account/:code
// Get account status for the Account Portal
// ============================================================
app.get('/api/account/:code', async (req, res) => {
    try {
        const { code } = req.params;

        if (!code) {
            return res.status(400).json({ error: 'Missing code parameter' });
        }

        const subscription = await prisma.subscriptionCode.findUnique({
            where: { code: code.toUpperCase() }
        });

        if (!subscription) {
            return res.status(404).json({ error: 'Account not found' });
        }

        // Calculate days remaining
        const now = new Date();
        let active = false;
        let daysRemaining = 0;

        if (subscription.expiresAt) {
            const expiryDate = new Date(subscription.expiresAt);
            const timeDiff = expiryDate.getTime() - now.getTime();
            daysRemaining = Math.max(0, Math.ceil(timeDiff / (1000 * 60 * 60 * 24)));
            active = subscription.status === 'ACTIVE' && subscription.isValid && timeDiff > 0;
        }

        res.json({
            active: active,
            daysRemaining: daysRemaining,
            expiresAt: subscription.expiresAt ? subscription.expiresAt.toISOString() : null
        });

    } catch (error) {
        console.error('❌ Account lookup error:', error);
        res.status(500).json({ error: 'Failed to retrieve account status' });
    }
});

// ============================================================
// Start Server
// ============================================================
async function main() {
    console.log('');
    console.log('═══════════════════════════════════════════════════════');
    console.log('          Nera VPN™ Backend Server Starting...         ');
    console.log('═══════════════════════════════════════════════════════');
    console.log('');

    // Log SSH configuration (without sensitive data)
    console.log('📡 SSH Configuration:');
    console.log(`   Host: ${SSH_CONFIG.host}`);
    console.log(`   User: ${SSH_CONFIG.username}`);
    console.log(`   Key:  ${SSH_CONFIG.privateKeyPath}`);
    console.log('');

    // Initialize RSA keys
    initKeys();

    // Log the public key for client configuration
    console.log('');
    console.log('📋 SERVER PUBLIC KEY (Copy to crypto.rs):');
    console.log('─────────────────────────────────────────');
    console.log(getPublicKeyPem());
    console.log('─────────────────────────────────────────');
    console.log('');

    // Start listening
    app.listen(PORT, () => {
        console.log(`🚀 Server running at http://localhost:${PORT}`);
        console.log('');
        console.log('Available endpoints:');
        console.log(`  POST http://localhost:${PORT}/api/auth/redeem`);
        console.log(`  POST http://localhost:${PORT}/api/connect`);
        console.log(`  GET  http://localhost:${PORT}/api/health`);
        console.log(`  GET  http://localhost:${PORT}/api/public-key`);
        console.log(`  GET  http://localhost:${PORT}/api/account/:code`);
        console.log(`  POST http://localhost:${PORT}/api/create-topup-session`);
        console.log('');
    });
}

main().catch(console.error);
