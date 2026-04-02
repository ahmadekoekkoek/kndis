#!/bin/bash
# Demo: Complete OAuth2 + PKCE Flow
# This script demonstrates the full OAuth2 authorization code flow with PKCE

set -e

KONOHA_BASE_URL="${KONOHA_BASE_URL:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:-kcb-bank-client}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8081/callback}"

echo "=========================================="
echo "KNDIS OAuth2 + PKCE Demo"
echo "=========================================="
echo ""

# Generate PKCE parameters
echo "[1/5] Generating PKCE parameters..."
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=+/' | tr '/+' '_-')
STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)

echo "  Code Verifier: ${CODE_VERIFIER:0:20}..."
echo "  Code Challenge: ${CODE_CHALLENGE:0:20}..."
echo "  State: $STATE"
echo "  Nonce: $NONCE"
echo ""

# Step 1: Authorization Request
echo "[2/5] Authorization Request..."
echo "  GET $KONOHA_BASE_URL/oauth/v1/authorize"
echo ""

AUTH_URL="$KONOHA_BASE_URL/oauth/v1/authorize?client_id=$CLIENT_ID&redirect_uri=$(echo -n "$REDIRECT_URI" | jq -sRr @uri)&response_type=code&scope=$(echo -n "openid profile konoha:bank:kyc" | jq -sRr @uri)&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&nonce=$NONCE"

echo "  Full URL: $AUTH_URL"
echo ""

# For demo, we'll simulate the authorization by calling the endpoint directly
echo "  Calling authorization endpoint..."
AUTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$AUTH_URL" 2>/dev/null || echo "302")
HTTP_CODE=$(echo "$AUTH_RESPONSE" | tail -n1)

echo "  HTTP Status: $HTTP_CODE"
echo ""

# In a real flow, the user would authenticate and be redirected
# For demo, we'll use a test authorization code
AUTH_CODE="test-auth-code-$(date +%s)"
echo "  (Demo: Simulating authorization code: $AUTH_CODE)"
echo ""

# Step 2: Token Exchange
echo "[3/5] Token Exchange..."
echo "  POST $KONOHA_BASE_URL/oauth/v1/token"
echo ""

TOKEN_RESPONSE=$(curl -s -X POST "$KONOHA_BASE_URL/oauth/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "code_verifier=$CODE_VERIFIER" \
  -d "client_id=$CLIENT_ID" 2>/dev/null || echo '{"error": "connection_failed"}')

echo "  Response:"
echo "$TOKEN_RESPONSE" | jq '.' 2>/dev/null || echo "$TOKEN_RESPONSE"
echo ""

# Extract tokens if successful
if echo "$TOKEN_RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
    REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token // "N/A"')
    ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token // "N/A"')
    
    echo "  ✓ Access Token received"
    echo "  ✓ Refresh Token received"
    echo "  ✓ ID Token received"
    echo ""
    
    # Step 3: Token Introspection
    echo "[4/5] Token Introspection..."
    echo "  POST $KONOHA_BASE_URL/oauth/v1/introspect"
    echo ""
    
    INTROSPECT_RESPONSE=$(curl -s -X POST "$KONOHA_BASE_URL/oauth/v1/introspect" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "token=$ACCESS_TOKEN" 2>/dev/null || echo '{"active": false}')
    
    echo "  Response:"
    echo "$INTROSPECT_RESPONSE" | jq '.' 2>/dev/null || echo "$INTROSPECT_RESPONSE"
    echo ""
    
    # Step 4: UserInfo
    echo "[5/5] UserInfo Request..."
    echo "  GET $KONOHA_BASE_URL/oauth/v1/userinfo"
    echo ""
    
    USERINFO_RESPONSE=$(curl -s -X GET "$KONOHA_BASE_URL/oauth/v1/userinfo" \
      -H "Authorization: Bearer $ACCESS_TOKEN" 2>/dev/null || echo '{"error": "unauthorized"}')
    
    echo "  Response:"
    echo "$USERINFO_RESPONSE" | jq '.' 2>/dev/null || echo "$USERINFO_RESPONSE"
    echo ""
    
    echo "=========================================="
    echo "OAuth2 Flow Complete!"
    echo "=========================================="
    echo ""
    echo "Access Token: ${ACCESS_TOKEN:0:50}..."
    echo ""
else
    echo "  ✗ Token exchange failed"
    echo ""
    echo "Note: This demo requires the K-IdP service to be running."
    echo "Start it with: make dev"
fi