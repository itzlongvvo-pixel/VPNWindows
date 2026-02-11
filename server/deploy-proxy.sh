#!/bin/bash
# Deploy obfuscation proxy on VPN server
# Updates stunnel config to route through the XOR proxy

# 1. Update stunnel config: change connect port from 51821 to 51822
sed -i 's/connect = 127.0.0.1:51821/connect = 127.0.0.1:51822/' /etc/stunnel/nera-stealth.conf
echo "stunnel config updated:"
cat /etc/stunnel/nera-stealth.conf

# 2. Kill any existing obfuscation proxy
pkill -f "node.*obfuscation-proxy" 2>/dev/null
echo "killed old proxy if running"

# 3. Start the obfuscation proxy in background
nohup node /root/obfuscation-proxy.js > /var/log/obfuscation-proxy.log 2>&1 &
echo "proxy started with PID: $!"

# 4. Restart stunnel
systemctl restart stunnel4
echo "stunnel4 restarted"

# 5. Verify
sleep 1
echo "--- Verification ---"
ss -tulnp | grep -E "51822|8443"
echo "done"
