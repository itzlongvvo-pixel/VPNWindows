/**
 * Nera VPN™ - Deep Debug Script
 * 
 * Thoroughly checks WireGuard server configuration and keys.
 * Run with: node maintenance/debug-vpn.js
 * 
 * REQUIRED ENV VARS:
 *   CLIENT_PRIVATE_KEY - WireGuard client private key
 *   CLIENT_PUBLIC_KEY  - WireGuard client public key
 *   SERVER_PUBLIC_KEY  - WireGuard server public key
 */

require('dotenv').config({ path: '../.env' });
const { NodeSSH } = require('node-ssh');

const SSH_CONFIG = {
    host: process.env.SSH_HOST || '45.76.106.63',
    username: process.env.SSH_USER || 'root',
    privateKeyPath: process.env.SSH_KEY_PATH || 'C:/Users/EllVo/.ssh/id_ed25519'
};

// Keys loaded from environment variables (no hardcoded secrets!)
const CLIENT_PRIVATE_KEY = process.env.CLIENT_PRIVATE_KEY;
const CLIENT_PUBLIC_KEY = process.env.CLIENT_PUBLIC_KEY;
const SERVER_PUBLIC_KEY = process.env.SERVER_PUBLIC_KEY;

async function main() {
    // Validate required env vars
    if (!CLIENT_PRIVATE_KEY || !CLIENT_PUBLIC_KEY || !SERVER_PUBLIC_KEY) {
        console.error('❌ Missing required environment variables!');
        console.error('   Please set in server/.env:');
        console.error('   - CLIENT_PRIVATE_KEY');
        console.error('   - CLIENT_PUBLIC_KEY');
        console.error('   - SERVER_PUBLIC_KEY');
        process.exit(1);
    }

    const ssh = new NodeSSH();

    console.log('');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('       Nera VPN™ - Deep Debug Script                           ');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('');

    console.log('📋 Keys loaded from environment:');
    console.log(`   Client Private Key: ${CLIENT_PRIVATE_KEY.substring(0, 8)}...`);
    console.log(`   Client Public Key:  ${CLIENT_PUBLIC_KEY.substring(0, 8)}...`);
    console.log(`   Server Public Key:  ${SERVER_PUBLIC_KEY.substring(0, 8)}...`);
    console.log('');

    console.log(`🔧 Connecting to ${SSH_CONFIG.host}...`);

    try {
        await ssh.connect({
            host: SSH_CONFIG.host,
            username: SSH_CONFIG.username,
            privateKeyPath: SSH_CONFIG.privateKeyPath,
            readyTimeout: 15000
        });

        console.log('✅ Connected!\n');

        // 1. Check WireGuard config file
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('📌 WireGuard Server Config (/etc/wireguard/wg0.conf)');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const wgConf = await ssh.execCommand('cat /etc/wireguard/wg0.conf');
        if (wgConf.stdout) {
            wgConf.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        } else {
            console.log('   ⚠️ Config file not found or empty!');
        }

        // 2. Check what port WireGuard is listening on
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('📌 WireGuard Listening Port');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const listenPort = await ssh.execCommand('wg show wg0 listen-port');
        console.log(`   Listening Port: ${listenPort.stdout.trim() || 'NOT RUNNING'}`);

        if (listenPort.stdout.trim() !== '443') {
            console.log(`   ⚠️ Client expects port 443, but server uses ${listenPort.stdout.trim()}`);
            console.log(`   This could be the problem!`);
        }

        // 3. Check server's public key
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('📌 Server Public Key Verification');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const serverKey = await ssh.execCommand('wg show wg0 public-key');
        console.log(`   Server's Actual Public Key: ${serverKey.stdout.trim()}`);
        console.log(`   Expected (in our code):     ${SERVER_PUBLIC_KEY}`);

        if (serverKey.stdout.trim() !== SERVER_PUBLIC_KEY) {
            console.log(`   ❌ MISMATCH! The client has the wrong server public key!`);
        } else {
            console.log(`   ✅ Keys match!`);
        }

        // 4. Verify client public key derivation
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('📌 Client Key Verification (derive public from private)');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const derivedKey = await ssh.execCommand(`echo "${CLIENT_PRIVATE_KEY}" | wg pubkey`);
        console.log(`   Derived Public Key: ${derivedKey.stdout.trim()}`);
        console.log(`   Expected:           ${CLIENT_PUBLIC_KEY}`);

        if (derivedKey.stdout.trim() !== CLIENT_PUBLIC_KEY) {
            console.log(`   ❌ MISMATCH! The public key in .env is WRONG!`);
            console.log(`   Fix: Update CLIENT_PUBLIC_KEY to: ${derivedKey.stdout.trim()}`);
        } else {
            console.log(`   ✅ Keys match!`);
        }

        // 5. Show current peers
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('📌 Current WireGuard Peers');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const peers = await ssh.execCommand('wg show wg0');
        if (peers.stdout) {
            peers.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        }

        // 6. Check firewall
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('📌 Firewall Status');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const ufw = await ssh.execCommand('ufw status');
        console.log(`   UFW: ${ufw.stdout.trim()}`);

        const iptables = await ssh.execCommand('iptables -L INPUT -n | head -10');
        console.log('\n   iptables INPUT:');
        iptables.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));

        // 7. Test connectivity from server
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('📌 Server Internet Connectivity');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const ping = await ssh.execCommand('ping -c 2 1.1.1.1');
        if (ping.stdout.includes('2 received')) {
            console.log('   ✅ Server can reach internet');
        } else {
            console.log('   ❌ Server cannot reach internet!');
        }

        // 8. IP forwarding
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('📌 IP Forwarding');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const forward = await ssh.execCommand('cat /proc/sys/net/ipv4/ip_forward');
        console.log(`   ip_forward: ${forward.stdout.trim()}`);
        if (forward.stdout.trim() !== '1') {
            console.log('   ❌ IP forwarding is DISABLED!');
        } else {
            console.log('   ✅ IP forwarding enabled');
        }

        // Summary
        console.log('\n');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('📋 SUMMARY - Check these items:');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('');
        console.log('1. Is the server listening on port 443? (client expects 443)');
        console.log('2. Does the server public key match what client has?');
        console.log('3. Is the client public key correctly derived?');
        console.log('4. Is IP forwarding enabled?');
        console.log('5. Is the peer registered on the server?');
        console.log('');

    } catch (error) {
        console.error('❌ SSH Connection Failed:', error.message);
        process.exit(1);
    } finally {
        ssh.dispose();
        console.log('🔧 SSH connection closed.');
    }
}

main();
