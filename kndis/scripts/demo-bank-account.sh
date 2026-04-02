#!/bin/bash
# Demo: Bank Account Opening Flow
# This script demonstrates the complete bank account opening flow using KNDIS

set -e

KONOHA_BASE_URL="${KONOHA_BASE_URL:-http://localhost:8080}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8083}"
CLIENT_ID="${CLIENT_ID:-kcb-bank-client}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8081/callback}"

echo "=========================================="
echo "KNDIS Bank Account Opening Demo"
echo "=========================================="
echo ""
echo "This demo shows how a citizen can open a bank account"
echo "in under 2 minutes using KNDIS digital identity."
echo ""

# Generate PKCE parameters
echo "[Step 1] Citizen opens bank app and initiates account opening..."
echo ""
echo "  Citizen: Naruto Uzumaki"
echo "  Bank: KCB Bank"
echo "  Action: Open new account"
echo ""

CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=+/' | tr '/+' '_-')
STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)

echo "  ⏱️  T+0:05 - Bank app generates PKCE challenge"
echo ""

# Step 1: Authorization Request
echo "[Step 2] Bank redirects to K-IdP for authentication..."
echo ""

AUTH_URL="$KONOHA_BASE_URL/oauth/v1/authorize?client_id=$CLIENT_ID&redirect_uri=$(echo -n "$REDIRECT_URI" | jq -sRr @uri)&response_type=code&scope=$(echo -n "openid profile konoha:bank:kyc" | jq -sRr @uri)&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&nonce=$NONCE"

echo "  GET $KONOHA_BASE_URL/oauth/v1/authorize"
echo "  Parameters:"
echo "    - client_id: $CLIENT_ID"
echo "    - scope: openid profile konoha:bank:kyc"
echo "    - response_type: code"
echo "    - PKCE: S256"
echo ""
echo "  ⏱️  T+0:08 - K-IdP sends auth request to Hokage Wallet"
echo ""

# For demo, simulate the authorization
AUTH_CODE="demo-auth-code-$(date +%s)"

# Step 2: Token Exchange
echo "[Step 3] Bank exchanges authorization code for tokens..."
echo ""

TOKEN_RESPONSE=$(curl -s -X POST "$KONOHA_BASE_URL/oauth/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "code_verifier=$CODE_VERIFIER" \
  -d "client_id=$CLIENT_ID" 2>/dev/null || echo '{"error": "connection_failed"}')

if echo "$TOKEN_RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
    ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token // "N/A"')
    
    echo "  POST $KONOHA_BASE_URL/oauth/v1/token"
    echo ""
    echo "  ✓ Access Token received (5 min TTL)"
    echo "  ✓ ID Token received"
    echo "  ✓ Token Type: DPoP"
    echo ""
    echo "  ⏱️  T+0:28 - Token + VC sent to KCB Bank"
    echo ""
else
    echo "  (Demo mode - using mock tokens)"
    ACCESS_TOKEN="demo-access-token"
    echo ""
fi

# Step 3: Gateway Request for KYC
echo "[Step 4] Bank requests KYC data via KonohaX Gateway..."
echo ""

REQUEST_BODY='{
  "target_service": "konoha.bank.kyc.v1",
  "operation": "verify_identity",
  "parameters": {
    "required_attributes": ["name", "nationality", "date_of_birth", "income_range"]
  },
  "purpose": "bank_account_kyc",
  "citizen_spid": "B-RTYU7CXMN4QPWJK8ALVFB5ZGH"
}'

echo "  POST $GATEWAY_URL/konohax/v1/request"
echo "  Headers:"
echo "    Authorization: DPoP $ACCESS_TOKEN"
echo "    DPoP: <DPoP-proof-JWT>"
echo ""
echo "  Body:"
echo "$REQUEST_BODY" | jq '.' 2>/dev/null || echo "$REQUEST_BODY"
echo ""

# For demo, simulate the gateway response
GATEWAY_RESPONSE='{
  "request_id": "req-abc123",
  "status": "success",
  "data": {
    "name": "Naruto Uzumaki",
    "nationality": "Konoha",
    "date_of_birth": "1990-07-15",
    "income_range": "50000-75000",
    "kyc_verified": true
  },
  "audit_log_id": "audit-abc123"
}'

echo "  Response:"
echo "$GATEWAY_RESPONSE" | jq '.' 2>/dev/null || echo "$GATEWAY_RESPONSE"
echo ""
echo "  ⏱️  T+0:32 - KCB Bank verifies credentials"
echo ""

# Step 4: Account Creation
echo "[Step 5] Bank creates account with pre-filled KYC data..."
echo ""
echo "  ✓ Name verified: Naruto Uzumaki"
echo "  ✓ Nationality: Konoha"
echo "  ✓ Date of Birth: 1990-07-15"
echo "  ✓ Income range sufficient for account type"
echo "  ✓ No forms to fill!"
echo ""
echo "  ⏱️  T+0:45 - Account created"
echo ""

# Step 5: Result
echo "[Step 6] Account opening complete!"
echo ""
echo "=========================================="
echo "RESULT"
echo "=========================================="
echo ""
echo "  ⏱️  Total Time: ~45 seconds"
echo "  📝 Forms Filled: 0"
echo "  📄 Documents Scanned: 0"
echo "  🔐 Data Shared: Minimal (only KYC required)"
echo "  💳 Virtual Card: Issued"
echo ""
echo "  Account Details:"
echo "    - Account Number: 1234567890"
echo "    - Account Type: Savings"
echo "    - Status: Active"
echo ""
echo "=========================================="
echo ""
echo "Citizen's data rights preserved:"
echo "  ✓ Only necessary data shared"
echo "  ✓ Consent recorded and auditable"
echo "  ✓ Can revoke access anytime"
echo "  ✓ Full transparency in Hokage Wallet"
echo ""
echo "=========================================="