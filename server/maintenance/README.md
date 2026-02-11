# Nera VPN™ Maintenance Tools

This folder contains diagnostic and repair scripts for the WireGuard VPN server.

## Scripts

| Script | Purpose |
|--------|---------|
| `debug-vpn.js` | Deep diagnostic - checks keys, ports, peers, firewall |
| `diagnose-vpn.js` | Comprehensive check with auto-fix for common issues |
| `fix-vpn.js` | Quick fix - disables UFW, enables IP forwarding, adds NAT |

## Usage

Run from the `server/` directory:

```bash
# Deep diagnostics (requires key env vars)
node maintenance/debug-vpn.js

# Auto-diagnose and fix
node maintenance/diagnose-vpn.js

# Quick server fix
node maintenance/fix-vpn.js
```

## Required Environment Variables

For `debug-vpn.js`, you must set these in `server/.env`:

```env
CLIENT_PRIVATE_KEY=your_wireguard_private_key
CLIENT_PUBLIC_KEY=your_wireguard_public_key
SERVER_PUBLIC_KEY=server_wireguard_public_key
```

## Security Notes

- All SSH credentials are loaded from `../. env`
- **Never commit `.env` to version control** (it's in `.gitignore`)
- These scripts have SSH access to the VPN server - handle with care
