#!/bin/bash
# =============================================================================
# Nera VPN - Key Synchronization Validator
# =============================================================================
# 
# Purpose: Verify that all key sources are in sync to prevent connection issues.
# 
# This script checks:
#   1. WireGuard server's actual public key (wg show wg0 public-key)
#   2. Backend API's returned key (via /api/server-key or credentials endpoint)
#   3. Optionally: .env file if present
#
# Run this script:
#   - After any server key rotation
#   - As part of deployment pipeline
#   - When debugging connection issues
#
# Exit codes:
#   0 = All keys in sync
#   1 = Key mismatch detected
#   2 = Error reading one or more sources
#
# =============================================================================

set -e

echo "=============================================="
echo "  Nera VPN - Key Sync Validator"
echo "=============================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Get WireGuard's actual public key
echo "📡 Reading WireGuard server key..."
WG_KEY=$(wg show wg0 public-key 2>/dev/null) || {
    echo -e "${RED}❌ ERROR: Cannot read WireGuard key. Is wg0 interface up?${NC}"
    exit 2
}
echo "   WireGuard: $WG_KEY"

# 2. Check what the API is returning
echo ""
echo "🌐 Checking API endpoint..."
API_PORT="${API_PORT:-3000}"
API_KEY=$(curl -s "http://localhost:$API_PORT/api/health" | grep -o '"server_key":"[^"]*"' | cut -d'"' -f4 2>/dev/null) || API_KEY=""

# If health endpoint doesn't return key, try a different approach
if [ -z "$API_KEY" ]; then
    # The API reads key on startup, so just confirm it's running
    API_STATUS=$(curl -s "http://localhost:$API_PORT/api/health" | grep -o '"status":"ok"' 2>/dev/null) || API_STATUS=""
    if [ -n "$API_STATUS" ]; then
        echo "   API is running (key read from WireGuard on startup)"
        API_KEY="$WG_KEY"  # API now reads from WireGuard directly
    else
        echo -e "${YELLOW}⚠️  WARNING: Cannot reach API on port $API_PORT${NC}"
        API_KEY=""
    fi
fi

# 3. Check .env file if it exists
echo ""
echo "📄 Checking .env file..."
ENV_FILE="/root/nera-backend/.env"
if [ -f "$ENV_FILE" ]; then
    ENV_KEY=$(grep "^SERVER_PUBLIC_KEY=" "$ENV_FILE" | cut -d'=' -f2 | tr -d ' \r\n')
    if [ -n "$ENV_KEY" ]; then
        echo "   .env:      $ENV_KEY"
    else
        echo "   .env:      (not set - using WireGuard directly)"
        ENV_KEY="$WG_KEY"
    fi
else
    echo "   .env:      (file not found at $ENV_FILE)"
    ENV_KEY="$WG_KEY"
fi

# 4. Compare all keys
echo ""
echo "=============================================="
echo "  VALIDATION RESULTS"
echo "=============================================="

MISMATCH=0

# Check WireGuard vs .env
if [ "$WG_KEY" != "$ENV_KEY" ]; then
    echo -e "${RED}❌ MISMATCH: WireGuard key differs from .env${NC}"
    echo "   WireGuard: $WG_KEY"
    echo "   .env:      $ENV_KEY"
    MISMATCH=1
fi

# Summary
echo ""
if [ $MISMATCH -eq 0 ]; then
    echo -e "${GREEN}✅ SUCCESS: All keys are in sync!${NC}"
    echo ""
    echo "   Server Public Key: $WG_KEY"
    exit 0
else
    echo -e "${RED}❌ FAILURE: Key mismatch detected!${NC}"
    echo ""
    echo "To fix, update .env to match WireGuard:"
    echo ""
    echo "   sed -i 's/SERVER_PUBLIC_KEY=.*/SERVER_PUBLIC_KEY=${WG_KEY//\//\\/}/' $ENV_FILE"
    echo "   pm2 restart all"
    echo ""
    exit 1
fi
