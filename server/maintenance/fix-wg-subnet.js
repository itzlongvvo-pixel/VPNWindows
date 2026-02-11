/**
 * Nera VPN™ - Fix WireGuard Subnet Mismatch
 * 
 * The server was using 10.0.0.1/24 but clients are assigned 10.66.66.x/32
 * This script fixes the subnet to match.
 * 
 * Run with: node maintenance/fix-wg-subnet.js
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
    console.log('       Nera VPN™ - Fix WireGuard Subnet Mismatch               ');
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

        // Step 1: Stop WireGuard
        console.log('📌 Stopping WireGuard...');
        await ssh.execCommand('wg-quick down wg0 2>/dev/null || true');
        await ssh.execCommand('systemctl stop wg-quick@wg0 2>/dev/null || true');
        console.log('   ✅ WireGuard stopped\n');

        // Step 2: Backup old config
        console.log('📌 Backing up old config...');
        await ssh.execCommand('cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.backup');
        console.log('   ✅ Backup created\n');

        // Step 3: Get the current private key
        console.log('📌 Reading current private key...');
        const keyResult = await ssh.execCommand('grep PrivateKey /etc/wireguard/wg0.conf | cut -d= -f2 | tr -d " "');
        const privateKey = keyResult.stdout.trim();
        console.log(`   ✅ Private key retrieved\n`);

        // Step 4: Create new config with correct subnet
        console.log('📌 Creating new WireGuard config with correct subnet (10.66.66.1/24)...');

        const newConfig = `[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${privateKey}
SaveConfig = true

# PostUp/PostDown for NAT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o enp1s0 -j MASQUERADE
`;

        await ssh.execCommand(`cat > /etc/wireguard/wg0.conf << 'EOF'
${newConfig}
EOF`);
        console.log('   ✅ New config written\n');

        // Step 5: Start WireGuard
        console.log('📌 Starting WireGuard with new config...');
        const startResult = await ssh.execCommand('wg-quick up wg0');
        if (startResult.stderr && !startResult.stderr.includes('already')) {
            console.log(`   ⚠️ stderr: ${startResult.stderr}`);
        }
        console.log('   ✅ WireGuard started\n');

        // Step 6: Verify the new address
        console.log('📌 Verifying new WireGuard interface...');
        const ifResult = await ssh.execCommand('ip addr show wg0');
        ifResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        // Step 7: Show WireGuard status
        console.log('📌 WireGuard status:');
        const wgResult = await ssh.execCommand('wg show');
        wgResult.stdout.split('\n').forEach(line => console.log(`   │ ${line}`));
        console.log('');

        console.log('═══════════════════════════════════════════════════════════════');
        console.log('✅ SUBNET FIX COMPLETE!');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('');
        console.log('Server WireGuard is now on: 10.66.66.1/24');
        console.log('Clients will be assigned:   10.66.66.x/32');
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
