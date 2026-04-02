# 🏛️ KNDIS - Konoha National Digital Identity System

A production-grade implementation of the Konoha National Digital Identity System (KNDIS) - a secure, scalable, privacy-preserving national identity platform.

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Services](#services)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Deployment](#deployment)
- [Security](#security)
- [End-to-End Flows](#end-to-end-flows)

## 🏗️ Architecture Overview

KNDIS implements a layered identity architecture based on the [KNDIS Blueprint v2.0](../KNDIS-Production-Blueprint.md):

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         KNDIS SERVICE ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   K-IdP     │  │   SPID      │  │   Consent   │  │   Token     │    │
│  │  (OAuth2.1) │  │  Service    │  │  Service    │  │  Service    │    │
│  │   :8080     │  │   :8081     │  │   :8082     │  │   :8088     │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │   Gateway   │  │  Audit Log  │  │ Credential  │                     │
│  │  (KonohaX)  │  │  Service    │  │   Issuer    │                     │
│  │   :8083     │  │   :8084     │  │   :8089     │                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Core Components

| Service | Port | Description |
|---------|------|-------------|
| K-IdP | 8080 | OAuth 2.1 + OpenID Connect Identity Provider |
| SPID Service | 8081 | Sector Pseudonymous ID (HMAC) Generator |
| Consent Service | 8082 | Consent Management & ABAC |
| Gateway | 8083 | KonohaX API Gateway |
| Audit Log | 8084 | Immutable Audit Logging |
| Token Service | 8088 | JWT Token Management & DPoP |
| Credential Issuer | 8089 | Verifiable Credentials (W3C VC) |

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Go 1.21+ (for local development)
- kubectl (for Kubernetes deployment)
- curl (for API testing)

### Start All Services

```bash
# Clone the repository
git clone https://github.com/konoha/kndis.git
cd kndis

# Start all services with Docker Compose
make dev

# Or manually:
docker-compose up --build -d
```

### Verify Services

```bash
# Check all services are healthy
curl http://localhost:8080/health  # K-IdP
curl http://localhost:8081/health  # SPID Service
curl http://localhost:8082/health  # Consent Service
curl http://localhost:8083/health  # Gateway
curl http://localhost:8084/health  # Audit Log
curl http://localhost:8088/health  # Token Service
curl http://localhost:8089/health  # Credential Issuer
```

## 🔧 Services

### K-IdP (Identity Provider)

OAuth 2.1 + OpenID Connect implementation with PKCE support.

**Endpoints:**
- `GET /.well-known/openid-configuration` - OIDC Discovery
- `GET /.well-known/jwks.json` - JWKS endpoint
- `GET /oauth/v1/authorize` - Authorization endpoint
- `POST /oauth/v1/token` - Token endpoint
- `POST /oauth/v1/revoke` - Token revocation
- `POST /oauth/v1/introspect` - Token introspection
- `GET /oauth/v1/userinfo` - UserInfo endpoint (protected)

### SPID Service

Generates sector-specific pseudonymous identifiers using HMAC-SHA256.

**Endpoints:**
- `POST /v1/spid/generate` - Generate SPID
- `POST /v1/spid/batch` - Batch SPID generation
- `POST /v1/spid/validate` - Validate SPID format
- `POST /v1/spid/rotate` - Rotate SPID
- `POST /v1/spid/resolve` - Resolve SPID to NIN (privileged)
- `GET /v1/sectors` - List sectors

### Consent Service

Manages citizen consent grants with signed receipts.

**Endpoints:**
- `POST /v1/consent/grant` - Grant consent (protected)
- `POST /v1/consent/revoke/:id` - Revoke consent (protected)
- `GET /v1/consent/activity` - Get activity log (protected)
- `GET /v1/consent/active` - List active consents (protected)
- `POST /internal/v1/consent/check` - Internal consent check

### Gateway (KonohaX)

API Gateway with circuit breakers and service routing.

**Endpoints:**
- `GET /konohax/v1/services` - List services
- `GET /konohax/v1/services/:id` - Get service info
- `POST /konohax/v1/request` - Cross-agency request (protected)
- `POST /konohax/v1/services/register` - Register service (protected)

### Audit Log Service

Immutable audit logging with Merkle tree verification.

**Endpoints:**
- `POST /v1/events` - Log event (protected)
- `GET /v1/events` - Query events (protected)
- `GET /transparency/daily-root` - Daily Merkle root
- `GET /transparency/report` - Transparency report

### Token Service

JWT token management and DPoP validation.

**Endpoints:**
- `POST /v1/introspect` - Introspect token
- `POST /v1/revoke` - Revoke token
- `POST /v1/dpop/validate` - Validate DPoP proof
- `POST /v1/info` - Get token info
- `GET /.well-known/jwks.json` - JWKS endpoint

### Credential Issuer

Issues and verifies W3C Verifiable Credentials.

**Endpoints:**
- `POST /v1/credentials/issue` - Issue credential (protected)
- `POST /v1/credentials/verify` - Verify credential
- `POST /v1/credentials/present` - Create presentation (protected)
- `GET /v1/schemas/:type` - Get credential schema

## 📚 API Documentation

### OAuth2 Authorization Flow

#### 1. Authorization Request

```bash
curl -X GET "http://localhost:8080/oauth/v1/authorize? \
  client_id=kcb-bank-client& \
  redirect_uri=http://localhost:8081/callback& \
  response_type=code& \
  scope=openid%20profile%20konoha:bank:kyc& \
  state=random-state-123& \
  code_challenge=BASE64URL(SHA256(code_verifier))& \
  code_challenge_method=S256& \
  nonce=random-nonce-456"
```

#### 2. Token Exchange

```bash
curl -X POST http://localhost:8080/oauth/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_FROM_STEP_1" \
  -d "redirect_uri=http://localhost:8081/callback" \
  -d "code_verifier=CODE_VERIFIER" \
  -d "client_id=kcb-bank-client"
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 300,
  "refresh_token": "opaque-refresh-token",
  "id_token": "eyJ...",
  "scope": "openid profile konoha:bank:kyc"
}
```

### SPID Generation

```bash
curl -X POST http://localhost:8081/v1/spid/generate \
  -H "Content-Type: application/json" \
  -d '{
    "nin_hash": "sha256-hash-of-nin",
    "sector": "KONOHA_BANK_V1",
    "request_id": "req-123",
    "requesting_service": "k-idp"
  }'
```

**Response:**
```json
{
  "spid": "B-RTYU7CXMN4QPWJK8ALVFB5ZGH",
  "sector": "KONOHA_BANK_V1",
  "generated_at": 1712345678
}
```

### Grant Consent

```bash
curl -X POST http://localhost:8082/v1/consent/grant \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "granted_to": "did:konoha:org:kcb-bank",
    "granted_to_name": "KCB Bank",
    "attributes": [
      {
        "attribute": "identity:name",
        "purpose": "account_opening",
        "legal_basis": "legitimate_interest",
        "sensitivity": "low"
      }
    ],
    "purpose": "bank_account_kyc",
    "valid_until": "2025-12-31T23:59:59Z",
    "storage_allowed": false,
    "downstream_sharing_allowed": false
  }'
```

### Gateway Request

```bash
curl -X POST http://localhost:8083/konohax/v1/request \
  -H "Authorization: DPoP ACCESS_TOKEN" \
  -H "DPoP: DPoP_PROOF_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "target_service": "konoha.health.citizen-records.v2",
    "operation": "read_medical_history",
    "parameters": {
      "date_range": {"from": "2024-01-01", "to": "2024-12-31"}
    },
    "purpose": "emergency_treatment",
    "citizen_spid": "H-KQNM4VWPX2JRYTF8BGZDA3E7U"
  }'
```

## 💻 Development

### Build from Source

```bash
# Download dependencies
make deps

# Build all services
make build

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Run linter
make lint
```

### Run Individual Services

```bash
# K-IdP
go run services/k-idp/main.go

# SPID Service
go run services/spid-service/main.go

# Consent Service
go run services/consent-service/main.go

# Gateway
go run services/gateway/main.go
```

## 🚢 Deployment

### Docker Compose

```bash
# Start all services
make dev

# View logs
make logs

# Stop services
make dev-stop
```

### Kubernetes

```bash
# Build and push images
make docker-build
make docker-push

# Deploy to Kubernetes
make k8s-deploy

# Check status
make k8s-status

# View logs
make k8s-logs

# Port forward for testing
make k8s-port-forward
```

### Production Checklist

- [ ] Use production HSM for key storage
- [ ] Configure TLS certificates
- [ ] Set up Redis cluster for token caching
- [ ] Configure PostgreSQL for consent storage
- [ ] Set up Kafka for event streaming
- [ ] Configure monitoring (Prometheus/Grafana)
- [ ] Set up log aggregation (ELK/Loki)
- [ ] Configure rate limiting
- [ ] Set up DDoS protection
- [ ] Enable audit logging
- [ ] Configure backup/restore
- [ ] Set up alerting (PagerDuty)

## 🔐 Security

### Cryptographic Specifications

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Token Signing | RS256 (RSA-2048) | JWT signatures |
| SPID Derivation | HMAC-SHA256 | Sector pseudonyms |
| Consent Receipts | Ed25519 | Receipt signatures |
| VCs | ECDSA (P-256) | Credential signatures |
| DPoP | Ed25519 | Token binding |

### Security Headers

All services implement:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Content-Security-Policy: default-src 'self'`

### Authentication

- OAuth 2.1 with PKCE (mandatory)
- FIDO2/WebAuthn (for citizen auth)
- DPoP token binding (mandatory)
- mTLS for service-to-service

## 🔄 End-to-End Flows

### Bank Account Opening Flow

```bash
# 1. Start authorization flow
curl "http://localhost:8080/oauth/v1/authorize?client_id=kcb-bank-client&..."

# 2. Exchange code for tokens
curl -X POST http://localhost:8080/oauth/v1/token \
  -d "grant_type=authorization_code&code=..."

# 3. Use token to access bank service via gateway
curl -X POST http://localhost:8083/konohax/v1/request \
  -H "Authorization: DPoP ACCESS_TOKEN" \
  -d '{"target_service": "konoha.bank.kyc.v1", ...}'
```

See [scripts/demo-bank-account.sh](scripts/demo-bank-account.sh) for complete flow.

### OAuth2 Complete Flow

See [scripts/demo-oauth2.sh](scripts/demo-oauth2.sh) for a complete OAuth2 + PKCE demonstration.

## 📊 Monitoring

### Health Endpoints

All services expose:
- `/health` - Overall health status
- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe
- `/metrics` - Basic metrics

### Logs

Structured JSON logging with:
- Request ID correlation
- Citizen SPID (when authenticated)
- Latency tracking
- Error details

## 📄 License

Copyright © 2024 Konoha Government. All rights reserved.

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## 📞 Support

For support, email support@konoha.gov or open an issue on GitHub.

---

**KNDIS** - Built for Konoha. Designed for Humanity.