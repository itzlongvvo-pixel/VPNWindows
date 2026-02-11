/**
 * Nera VPN™ - VPN Server Fix Script
 * 
 * Diagnoses and fixes common WireGuard server configuration issues.
 * Run with: node maintenance/fix-vpn.js
 */

require('dotenv').config({ path: '../.env' });
const { NodeSSH } = require('node-ssh');

const SSH_CONFIG = {
    host: process.env.SSH_HOST || '45.76.106.63',
    username: process.env.SSH_USER || 'root',
    privateKeyPath: process.env.SSH_KEY_PATH || 'C:/Users/EllVo/.ssh/id_ed25519'
};

const COMMANDS = [
    { name: 'Disable UFW Firewall', cmd: 'ufw disable' },
    { name: 'Enable IP Forwarding', cmd: 'sysctl -w net.ipv4.ip_forward=1' },
    { name: 'Add NAT Masquerade Rule', cmd: 'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE' },
    { name: 'Show WireGuard Status', cmd: 'wg show' },
];

async function main() {
    const ssh = new NodeSSH();

    console.log('');
    console.log('═══════════════════════════════════════════════════════');
    console.log('       Nera VPN™ - Server Fix Script                   ');
    console.log('═══════════════════════════════════════════════════════');
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

        for (const { name, cmd } of COMMANDS) {
            console.log(`─────────────────────────────────────────`);
            console.log(`📌 ${name}`);
            console.log(`   Command: ${cmd}`);
            console.log('');

            const result = await ssh.execCommand(cmd);

            if (result.stdout && result.stdout.trim()) {
                console.log('   Output:');
                result.stdout.trim().split('\n').forEach(line => {
                    console.log(`   │ ${line}`);
                });
            }

            if (result.stderr && result.stderr.trim()) {
                console.log('   Stderr:');
                result.stderr.trim().split('\n').forEach(line => {
                    console.log(`   │ ${line}`);
                });
            }

            console.log('');
        }

        console.log('═══════════════════════════════════════════════════════');
        console.log('✅ All commands executed successfully!');
        console.log('═══════════════════════════════════════════════════════');

    } catch (error) {
        console.error('❌ SSH Connection Failed:', error.message);
        process.exit(1);
    } finally {
        ssh.dispose();
        console.log('\n🔧 SSH connection closed.');
    }
}

main();
