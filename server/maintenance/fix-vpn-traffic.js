/**
 * Nera VPN™ - Fix VPN Traffic Flow
 * 
 * This script fixes the common issue where VPN connects but traffic doesn't flow.
 * It sets up proper iptables rules for forwarding and NAT.
 * 
 * Run with: node maintenance/fix-vpn-traffic.js
 */

require('dotenv').config({ path: '../.env' });
const { NodeSSH } = require('node-ssh');

const SSH_CONFIG = {
    host: process.env.SSH_HOST || '45.76.106.63',
    username: process.env.SSH_USER || 'root',
    privateKeyPath: process.env.SSH_KEY_PATH || 'C:/Users/EllVo/.ssh/id_ed25519'
};

async function main() {
    const ssh = new NodeSSH();

    console.log('');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('       Nera VPN™ - Fix Traffic Flow Script                     ');
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

        // Step 1: Get the main interface
        console.log('📌 Detecting main network interface...');
        const routeResult = await ssh.execCommand('ip route | grep default');
        const match = routeResult.stdout.match(/dev\s+(\S+)/);
        const mainInterface = match ? match[1] : 'enp1s0';
        console.log(`   Main interface: ${mainInterface}\n`);

        // Step 2: Enable IP forwarding
        console.log('📌 Enabling IP forwarding...');
        await ssh.execCommand('echo 1 > /proc/sys/net/ipv4/ip_forward');
        await ssh.execCommand('sysctl -w net.ipv4.ip_forward=1');
        console.log('   ✅ IP forwarding enabled\n');

        // Step 3: Set UFW default forward policy to ACCEPT
        console.log('📌 Setting UFW forward policy to ACCEPT...');
        await ssh.execCommand("sed -i 's/DEFAULT_FORWARD_POLICY=\"DROP\"/DEFAULT_FORWARD_POLICY=\"ACCEPT\"/' /etc/default/ufw");
        console.log('   ✅ UFW forward policy set\n');

        // Step 4: Clear old iptables rules that might conflict
        console.log('📌 Clearing old conflicting rules...');
        // Don't flush everything, just remove duplicate MASQUERADE rules
        await ssh.execCommand('iptables -t nat -F POSTROUTING');
        console.log('   ✅ NAT rules cleared\n');

        // Step 5: Add proper FORWARD rules (BOTH directions)
        console.log('📌 Adding FORWARD rules for bidirectional traffic...');

        // Allow traffic FROM wg0 TO internet
        await ssh.execCommand(`iptables -A FORWARD -i wg0 -o ${mainInterface} -j ACCEPT`);
        console.log(`   ✅ Added: FORWARD wg0 → ${mainInterface}`);

        // Allow return traffic FROM internet TO wg0
        await ssh.execCommand(`iptables -A FORWARD -i ${mainInterface} -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT`);
        console.log(`   ✅ Added: FORWARD ${mainInterface} → wg0 (ESTABLISHED)`);

        // Also allow new connections TO wg0 (for responses)
        await ssh.execCommand(`iptables -A FORWARD -i ${mainInterface} -o wg0 -j ACCEPT`);
        console.log(`   ✅ Added: FORWARD ${mainInterface} → wg0 (ALL)\n`);

        // Step 6: Add NAT MASQUERADE rule
        console.log('📌 Adding NAT MASQUERADE rule...');
        await ssh.execCommand(`iptables -t nat -A POSTROUTING -o ${mainInterface} -j MASQUERADE`);
        console.log(`   ✅ Added: MASQUERADE on ${mainInterface}\n`);

        // Step 7: Lower MTU on wg0 interface
        console.log('📌 Lowering MTU on wg0 to prevent fragmentation...');
        await ssh.execCommand('ip link set dev wg0 mtu 1280');
        console.log('   ✅ MTU set to 1280\n');

        // Step 8: Show current WireGuard peers
        console.log('📌 Current WireGuard peers:');
        const wgResult = await ssh.execCommand('wg show');
        console.log(wgResult.stdout || '   (none)');
        console.log('');

        // Step 9: Show iptables rules
        console.log('📌 Current iptables FORWARD chain:');
        const fwdResult = await ssh.execCommand('iptables -L FORWARD -v -n');
        fwdResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        console.log('📌 Current NAT POSTROUTING chain:');
        const natResult = await ssh.execCommand('iptables -t nat -L POSTROUTING -v -n');
        natResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        // Step 10: Save iptables rules
        console.log('📌 Saving iptables rules...');
        await ssh.execCommand('iptables-save > /etc/iptables.rules');
        console.log('   ✅ Rules saved\n');

        console.log('═══════════════════════════════════════════════════════════════');
        console.log('✅ FIX COMPLETE!');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('');
        console.log('🔄 Now DISCONNECT and RECONNECT your VPN client, then test:');
        console.log('   1. ping 8.8.8.8');
        console.log('   2. Open google.com in your browser');
        console.log('');

    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    } finally {
        ssh.dispose();
        console.log('🔧 SSH connection closed.');
    }
}

main();
