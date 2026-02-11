/**
 * Nera VPN™ - Restore and Fix WireGuard
 * 
 * Restores from backup and properly reconfigures WireGuard with correct subnet.
 * 
 * Run with: node maintenance/restore-and-fix-wg.js
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
    console.log('       Nera VPN™ - Restore and Fix WireGuard                   ');
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

        // Step 1: Restore from backup
        console.log('📌 Restoring WireGuard from backup...');
        await ssh.execCommand('cp /etc/wireguard/wg0.conf.backup /etc/wireguard/wg0.conf');
        console.log('   ✅ Config restored\n');

        // Step 2: Show current config
        console.log('📌 Current config:');
        const configResult = await ssh.execCommand('cat /etc/wireguard/wg0.conf');
        configResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        // Step 3: Change the Address line from 10.0.0.1/24 to 10.66.66.1/24
        console.log('📌 Updating Address to 10.66.66.1/24...');
        await ssh.execCommand("sed -i 's|Address = 10.0.0.1/24|Address = 10.66.66.1/24|' /etc/wireguard/wg0.conf");
        console.log('   ✅ Address updated\n');

        // Step 4: Show updated config
        console.log('📌 Updated config:');
        const newConfigResult = await ssh.execCommand('cat /etc/wireguard/wg0.conf');
        newConfigResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        // Step 5: Start WireGuard
        console.log('📌 Starting WireGuard...');
        await ssh.execCommand('wg-quick down wg0 2>/dev/null || true');
        const startResult = await ssh.execCommand('wg-quick up wg0');
        if (startResult.stderr) {
            startResult.stderr.split('\n').forEach(line => {
                if (line.trim()) console.log(`   │ ${line}`);
            });
        }
        console.log('   ✅ WireGuard started\n');

        // Step 6: Verify interface
        console.log('📌 Verifying WireGuard interface:');
        const ifResult = await ssh.execCommand('ip addr show wg0');
        ifResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        // Step 7: Show status
        console.log('📌 WireGuard status:');
        const wgResult = await ssh.execCommand('wg show');
        wgResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        // Step 8: Ensure iptables rules
        console.log('📌 Setting up iptables...');
        await ssh.execCommand('echo 1 > /proc/sys/net/ipv4/ip_forward');
        await ssh.execCommand('iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true');
        await ssh.execCommand('iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE 2>/dev/null || true');
        console.log('   ✅ iptables configured\n');

        console.log('═══════════════════════════════════════════════════════════════');
        console.log('✅ FIX COMPLETE!');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('');
        console.log('🔄 Now DISCONNECT and RECONNECT your VPN client!');
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
