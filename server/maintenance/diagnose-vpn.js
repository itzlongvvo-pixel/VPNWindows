/**
 * Nera VPN™ - Comprehensive VPN Diagnostic Script
 * 
 * Diagnoses why VPN is connected but has no internet.
 * Run with: node maintenance/diagnose-vpn.js
 */

require('dotenv').config({ path: '../.env' });
const { NodeSSH } = require('node-ssh');

const SSH_CONFIG = {
    host: process.env.SSH_HOST || '45.76.106.63',
    username: process.env.SSH_USER || 'root',
    privateKeyPath: process.env.SSH_KEY_PATH || 'C:/Users/EllVo/.ssh/id_ed25519'
};

// Diagnostic commands to run
const DIAGNOSTICS = [
    { name: 'Network Interfaces', cmd: 'ip -br addr' },
    { name: 'Default Route (find main interface)', cmd: 'ip route | grep default' },
    { name: 'IP Forwarding Status', cmd: 'cat /proc/sys/net/ipv4/ip_forward' },
    { name: 'WireGuard Interface', cmd: 'ip addr show wg0' },
    { name: 'WireGuard Peers', cmd: 'wg show' },
    { name: 'NAT/Masquerade Rules', cmd: 'iptables -t nat -L POSTROUTING -v -n' },
    { name: 'All iptables Rules (filter)', cmd: 'iptables -L -v -n | head -30' },
    { name: 'UFW Status (Firewall)', cmd: 'ufw status verbose' },
    { name: 'UFW Forward Policy', cmd: 'grep "DEFAULT_FORWARD_POLICY" /etc/default/ufw' },
    { name: 'WireGuard Config File', cmd: 'cat /etc/wireguard/wg0.conf 2>/dev/null || echo "Config file not found"' },
];

// Fix commands based on common issues
const FIXES = [
    { name: 'Enable IP Forwarding', cmd: 'echo 1 > /proc/sys/net/ipv4/ip_forward' },
    { name: 'Persist IP Forwarding', cmd: 'echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && sysctl -p' },
    { name: 'Allow UFW Forwarding', cmd: "sed -i 's/DEFAULT_FORWARD_POLICY=\"DROP\"/DEFAULT_FORWARD_POLICY=\"ACCEPT\"/' /etc/default/ufw && ufw reload" },
    { name: 'Allow WireGuard Port', cmd: 'ufw allow 51820/udp' },
    { name: 'Lower MTU (Fix packet loss)', cmd: 'ip link set dev wg0 mtu 1360' },
];

async function main() {
    const ssh = new NodeSSH();

    console.log('');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('       Nera VPN™ - Comprehensive VPN Diagnostic                ');
    console.log('═══════════════════════════════════════════════════════════════');
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

        // Run diagnostics
        let mainInterface = 'eth0'; // default guess

        for (const { name, cmd } of DIAGNOSTICS) {
            console.log(`─────────────────────────────────────────────────────────────`);
            console.log(`📌 ${name}`);
            console.log(`   $ ${cmd}`);
            console.log('');

            const result = await ssh.execCommand(cmd);
            const output = (result.stdout || result.stderr || '').trim();

            if (output) {
                output.split('\n').forEach(line => {
                    console.log(`   │ ${line}`);
                });
            } else {
                console.log('   │ (no output)');
            }

            // Detect main interface from default route
            if (name.includes('Default Route') && result.stdout) {
                const match = result.stdout.match(/dev\s+(\S+)/);
                if (match) {
                    mainInterface = match[1];
                    console.log(`\n   🎯 Detected main interface: ${mainInterface}`);
                }
            }

            // Check IP forwarding
            if (name.includes('IP Forwarding')) {
                if (result.stdout && result.stdout.trim() === '0') {
                    console.log(`\n   ⚠️  IP FORWARDING IS DISABLED! This is the problem.`);
                }
            }

            console.log('');
        }

        // Apply fixes
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('🔧 APPLYING FIXES...');
        console.log('═══════════════════════════════════════════════════════════════\n');

        // Fix 1: Enable IP forwarding
        console.log('📌 Enabling IP Forwarding...');
        await ssh.execCommand('echo 1 > /proc/sys/net/ipv4/ip_forward');
        const forwardCheck = await ssh.execCommand('cat /proc/sys/net/ipv4/ip_forward');
        console.log(`   Result: ip_forward = ${forwardCheck.stdout.trim()}`);
        console.log('');

        // Fix 2: Flush existing NAT rules and add correct one
        console.log(`📌 Setting up NAT on interface: ${mainInterface}...`);

        // First, check if rule already exists
        const natCheck = await ssh.execCommand(`iptables -t nat -C POSTROUTING -o ${mainInterface} -j MASQUERADE 2>&1`);

        if (natCheck.code !== 0) {
            // Rule doesn't exist, add it
            await ssh.execCommand(`iptables -t nat -A POSTROUTING -o ${mainInterface} -j MASQUERADE`);
            console.log(`   Added: iptables -t nat -A POSTROUTING -o ${mainInterface} -j MASQUERADE`);
        } else {
            console.log(`   Rule already exists for ${mainInterface}`);
        }
        console.log('');

        // Fix 3: Ensure WireGuard is running
        console.log('📌 Restarting WireGuard interface...');
        await ssh.execCommand('wg-quick down wg0 2>/dev/null; wg-quick up wg0');
        console.log('   WireGuard restarted');
        console.log('');

        // Final check
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('📋 FINAL STATUS');
        console.log('═══════════════════════════════════════════════════════════════\n');

        const finalWg = await ssh.execCommand('wg show');
        console.log('WireGuard Status:');
        if (finalWg.stdout) {
            finalWg.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        }

        console.log('\n');
        console.log('✅ Diagnostic and fixes complete!');
        console.log('');
        console.log('🔄 Now try reconnecting your VPN client and test:');
        console.log('   ping 1.1.1.1');
        console.log('   ping 8.8.8.8');
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
