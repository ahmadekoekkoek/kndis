# 🏛️ KONOHA NATIONAL DIGITAL IDENTITY SYSTEM (KNDIS)
## Production-Ready Execution Blueprint v2.0
### Multi-Agent Architecture Review & Hardened Implementation Plan

---

**Document Classification:** INTERNAL — Engineering Blueprint  
**Review Date:** 2026-04-02  
**Agents Participated:** CTO, Security Lead, SRE, Orchestrator  
**Status:** ✅ APPROVED FOR IMPLEMENTATION

---

# EXECUTIVE SUMMARY

This document represents the output of a **4-agent architecture war game** conducted on the Konoha National Digital Identity System (KNDIS). The original v1.0 architecture was subjected to:

1. **CTO technical design** with 35+ engineering tasks
2. **Security audit** with 14 critical findings and hardened mitigations
3. **SRE stress-testing** for 50M citizen scale with failure mode analysis
4. **Iterative refinement** resolving all conflicts

**Outcome:** A production-ready blueprint that engineers can execute immediately.

---

# PART 1: CTO DRAFT — INITIAL TECHNICAL DESIGN

## 1.1 Service Architecture

### Core Service Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KNDIS SERVICE ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    SOVEREIGN SECURITY ZONE                           │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │    │
│  │  │   CIV-1     │  │   CIV-2     │  │   CIV-3     │  HSM Clusters    │    │
│  │  │ (Primary)   │  │ (Secondary) │  │ (Tertiary)  │  FIPS 140-3 L3   │    │
│  │  │  Konoha City│  │North Hills  │  │Coastal Zone │                  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │    │
│  │         │                │                │                         │    │
│  │         └────────────────┴────────────────┘                         │    │
│  │                      Raft Consensus (2-of-3)                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼ gRPC/mTLS                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    GOVERNMENT CLOUD ZONE                             │    │
│  │                                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │    │
│  │  │   K-IdP      │  │  KonohaX     │  │   Consent    │               │    │
│  │  │  (OAuth2.1/  │  │   Gateway    │  │   Engine     │               │    │
│  │  │   OIDC Core) │  │  (API GW)    │  │  (ABAC)      │               │    │
│  │  │  3x nodes    │  │  3x nodes    │  │  3x nodes    │               │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │    │
│  │         │                │                │                         │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │    │
│  │  │ Token Cache  │  │   Kafka      │  │  Audit Log   │               │    │
│  │  │ (Redis 6x)   │  │  (Event Bus) │  │ (Merkle)     │               │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │    │
│  │                                                                      │    │
│  │  Region 1: Konoha City (Primary)    Region 2: Northern (Standby)    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼ mTLS                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      AGENCY NETWORK ZONE                             │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │    │
│  │  │  Health  │  │   Tax    │  │  Banking │  │  Elect.  │            │    │
│  │  │  Ministry│  │  Auth    │  │  Reg     │  │  Comm.   │            │    │
│  │  │ Security │  │ Security │  │ Security │  │ Security │            │    │
│  │  │  Server  │  │  Server  │  │  Server  │  │  Server  │            │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼ HTTPS/WSS                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      CITIZEN INTERFACE ZONE                          │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │    │
│  │  │ Hokage Wallet│  │  Smart Card  │  │  Edge Nodes  │               │    │
│  │  │ (iOS/Android)│  │  (NFC/Chip)  │  │  (Rural/50x) │               │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Service Specifications

| Service | Technology | Instances | SLA | Scaling Trigger |
|---------|------------|-----------|-----|-----------------|
| K-IdP | Go + Gin | 3 per region | 99.99% | CPU > 70% |
| KonohaX Gateway | Envoy + Lua | 3 per region | 99.99% | Latency p99 > 100ms |
| Consent Engine | Rust + Actix | 3 per region | 99.95% | Queue depth > 1000 |
| Token Cache | Redis Cluster | 6 nodes | 99.99% | Memory > 80% |
| CIV | Custom C + HSM | 3 clusters | 99.999% | N/A (fixed) |
| Kafka | Strimzi/KRaft | 5 brokers | 99.95% | Disk > 70% |
| Audit Log | ImmuDB | 3 nodes | 99.99% | N/A (append-only) |

---

## 1.2 API Contracts

### K-IdP OAuth 2.1 + OIDC Endpoints

```yaml
# Authorization Endpoint
GET /oauth/v1/authorize
  Parameters:
    - client_id: string (required, UUID format)
    - redirect_uri: string (required, HTTPS only, pre-registered)
    - response_type: string (required, "code" only)
    - scope: string (required, space-delimited)
    - state: string (required, min 32 bytes entropy)
    - code_challenge: string (required, PKCE S256)
    - code_challenge_method: string (required, "S256")
    - nonce: string (required for OIDC, min 16 bytes)
    - prompt: enum [none, login, consent, select_account]
  Response: 302 Redirect with authorization code
  Rate Limit: 10 req/min per IP

# Token Endpoint
POST /oauth/v1/token
  Content-Type: application/x-www-form-urlencoded
  Headers:
    - DPoP: string (required, DPoP proof JWT)
  Parameters:
    - grant_type: string (required, "authorization_code" | "refresh_token")
    - code: string (required for auth_code grant)
    - redirect_uri: string (required, must match authorize)
    - code_verifier: string (required, PKCE verifier)
    - refresh_token: string (required for refresh grant)
  Response: TokenResponse JSON
  Rate Limit: 30 req/min per client

# Token Response Schema
TokenResponse:
  type: object
  properties:
    access_token:
      type: string
      format: JWT
      description: DPoP-bound access token
    token_type:
      type: string
      enum: ["DPoP"]
    expires_in:
      type: integer
      default: 900
    refresh_token:
      type: string
      format: opaque
      description: Rotates on each use
    id_token:
      type: string
      format: JWT
      description: OIDC ID token with sector SPID
    scope:
      type: string
      description: Granted scopes (may be subset of requested)
```

### KonohaX Gateway API

```yaml
# Service Discovery
GET /konohax/v1/services
  Headers:
    - Authorization: Bearer {access_token}
    - X-KonohaX-Signature: Ed25519 signature
  Response: ServiceCatalog

# Cross-Agency Data Request
POST /konohax/v1/request
  Headers:
    - Authorization: DPoP {access_token}
    - X-KonohaX-Signature: string (required)
    - X-KonohaX-Timestamp: Unix timestamp (max drift 300s)
    - X-KonohaX-Request-ID: UUID
  Body:
    target_service: string (service ID from registry)
    operation: string (operation name)
    parameters: object
    purpose: string (must match consent)
    citizen_spid: string (sector-specific)
  Response: EncryptedResponse
  Rate Limit: 1000 req/min per agency

# Event Publish
POST /konohax/v1/events
  Body: CloudEvent 1.0 format
  Response: 202 Accepted with event_id
```

### Consent Engine API

```yaml
# Grant Consent
POST /consent/v1/grant
  Headers:
    - Authorization: DPoP {access_token}
  Body:
    granted_to: DID
    attributes: string[]
    purpose: string
    validity_from: ISO8601
    validity_until: ISO8601
    max_access_count: integer (optional)
    storage_allowed: boolean
    downstream_sharing_allowed: boolean
  Response: ConsentReceipt

# Check Consent
POST /consent/v1/check
  Body:
    citizen_spid: string
    requester_did: string
    attribute: string
    purpose: string
  Response:
    granted: boolean
    receipt_id: string (if granted)
    remaining_accesses: integer (if limited)

# Revoke Consent
POST /consent/v1/revoke/{receipt_id}
  Headers:
    - Authorization: DPoP {access_token}
  Response: 204 No Content
  Effect: Immediate, propagated < 1 second

# Citizen Activity Log
GET /consent/v1/activity
  Headers:
    - Authorization: DPoP {access_token}
  Query:
    - from: ISO8601
    - to: ISO8601
    - limit: integer (max 1000)
  Response: ActivityLog[]
```

### Core Identity Vault (Internal gRPC)

```protobuf
syntax = "proto3";
package civ;

service CoreIdentityVault {
  // SPID generation - most frequent operation
  rpc GenerateSPID(SPIDRequest) returns (SPIDResponse) {
    option (google.api.http) = {
      post: "/v1/spid/generate"
      body: "*"
    };
  }
  
  // SPID to NIN resolution (rare, audited)
  rpc ResolveSPID(ResolveRequest) returns (ResolveResponse) {
    option (google.api.http) = {
      post: "/v1/spid/resolve"
      body: "*"
    };
  }
  
  // Batch SPID generation for bulk operations
  rpc BatchGenerateSPID(BatchSPIDRequest) returns (BatchSPIDResponse);
  
  // SPID rotation
  rpc RotateSPID(RotateRequest) returns (RotateResponse);
  
  // Emergency NIN freeze
  rpc FreezeNIN(FreezeRequest) returns (FreezeResponse);
}

message SPIDRequest {
  bytes nin_hash = 1;  // SHA-256 of NIN, HSM never sees plaintext NIN
  string sector = 2;   // e.g., "KONOHA_HEALTH_V1"
  string request_id = 3;
  string requesting_service = 4;
}

message SPIDResponse {
  string spid = 1;     // Base32 encoded, 26 chars
  string sector = 2;
  int64 generated_at = 3;
}

message ResolveRequest {
  string spid = 1;
  string sector = 2;
  string justification = 3;  // Required, audited
  string court_order_id = 4; // If applicable
  string request_id = 5;
  string requesting_service = 6;
}

message ResolveResponse {
  bytes nin_hash = 1;
  bool found = 2;
  string resolution_id = 3;  // For audit trail
}
```

---

## 1.3 Data Models

### Core Entity Schema

```sql
-- CIV: NIN to SPID mapping (HSM-resident, never leaves)
-- This schema exists only for documentation; actual storage is HSM-proprietary

-- Token Cache (Redis)
-- Key: token:{token_id}
-- Value: JSON
{
  "token_id": "uuid",
  "token_type": "access|refresh",
  "sub": "SPID",  -- Sector pseudonym
  "sector": "health|tax|bank|...",
  "scope": ["read:records", "write:prescriptions"],
  "exp": 1720000000,
  "iat": 1720000000,
  "jti": "uuid",
  "consent_refs": ["consent-uuid-1", "consent-uuid-2"],
  "device_binding": "device-did",
  "revoked": false
}

-- Consent Store (PostgreSQL + encryption)
CREATE TABLE consent_receipts (
    receipt_id UUID PRIMARY KEY,
    citizen_spid VARCHAR(32) NOT NULL,
    sector VARCHAR(32) NOT NULL,
    granted_to_did VARCHAR(255) NOT NULL,
    attributes JSONB NOT NULL,
    purpose VARCHAR(255) NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    max_access_count INTEGER,
    access_count INTEGER DEFAULT 0,
    storage_allowed BOOLEAN DEFAULT FALSE,
    downstream_sharing_allowed BOOLEAN DEFAULT FALSE,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    receipt_signature BYTEA NOT NULL,
    
    INDEX idx_citizen (citizen_spid),
    INDEX idx_granted_to (granted_to_did),
    INDEX idx_validity (valid_from, valid_until),
    INDEX idx_revoked (revoked)
);

-- Audit Log (ImmuDB - append-only, Merkle-tree)
-- Each entry is cryptographically linked to previous
CREATE TABLE audit_events (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    actor_type VARCHAR(32) NOT NULL, -- 'citizen' | 'agency' | 'system'
    actor_id VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    purpose VARCHAR(255),
    outcome VARCHAR(32) NOT NULL, -- 'permitted' | 'denied' | 'error'
    consent_receipt_id UUID,
    evidence_hash BYTEA, -- Hash of supporting documents
    prev_hash BYTEA NOT NULL, -- Merkle chain link
    merkle_root BYTEA NOT NULL,
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_actor (actor_id),
    INDEX idx_resource (resource_id)
);

-- Service Registry (PostgreSQL)
CREATE TABLE registered_services (
    service_id VARCHAR(128) PRIMARY KEY,
    owner_agency VARCHAR(128) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    base_url VARCHAR(512) NOT NULL,
    auth_scopes VARCHAR(64)[],
    allowed_consumers VARCHAR(128)[],
    requires_consent BOOLEAN DEFAULT TRUE,
    data_classification VARCHAR(32), -- 'PUBLIC' | 'INTERNAL' | 'SENSITIVE' | 'CRITICAL'
    sla_availability VARCHAR(16),
    sla_latency_p95_ms INTEGER,
    schema_url VARCHAR(512),
    status VARCHAR(32) DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### JWT Token Schemas

```json
// Access Token (DPoP-bound)
{
  "header": {
    "alg": "EdDSA",
    "typ": "at+JWT",
    "kid": "k-idp-key-2026-04"
  },
  "payload": {
    "iss": "https://idp.konoha.gov",
    "sub": "H-KQNM4VWPX2JRYTF8BGZDA3E7U",
    "aud": "service:konoha.health.api.v2",
    "exp": 1720000900,
    "iat": 1720000000,
    "jti": "token-uuid-unique",
    "scope": "health:read health:write:prescriptions",
    "cnf": {
      "jkt": "base64url-encoded-JWK-thumbprint"  // DPoP binding
    },
    "sector": "health",
    "auth_time": 1720000000,
    "acr": "urn:mace:incommon:iap:silver",  // Authentication context
    "amr": ["pwd", "hwk"]  // FIDO2 used
  }
}

// ID Token (OIDC)
{
  "header": {
    "alg": "EdDSA",
    "typ": "ID Token"
  },
  "payload": {
    "iss": "https://idp.konoha.gov",
    "sub": "H-KQNM4VWPX2JRYTF8BGZDA3E7U",
    "aud": "client-app-uuid",
    "exp": 1720000900,
    "iat": 1720000000,
    "auth_time": 1720000000,
    "nonce": "client-provided-nonce",
    "name": "Naruto Uzumaki",
    "given_name": "Naruto",
    "family_name": "Uzumaki",
    "birthdate": "1990-07-15",
    "nationality": "Konoha",
    "sector_spid": "H-KQNM4VWPX2JRYTF8BGZDA3E7U"
  }
}

// DPoP Proof
{
  "header": {
    "alg": "EdDSA",
    "typ": "dpop+jwt",
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url-encoded-public-key"
    }
  },
  "payload": {
    "jti": "unique-proof-id",
    "htm": "POST",
    "htu": "https://api.health.gov.kn/v2/records",
    "iat": 1720000000,
    "ath": "base64url(SHA256(access_token))"  // Token binding
  }
}
```

---

## 1.4 Implementation Phases

### Phase 1: Foundation (Months 1-12)
**Goal:** Core identity infrastructure operational

| Month | Deliverable | Success Criteria |
|-------|-------------|------------------|
| 1-2 | CIV HSM procurement & setup | 3 clusters operational, FIPS 140-3 L3 certified |
| 2-3 | K-IdP development | OAuth 2.1 + OIDC compliant, pass conformance tests |
| 3-4 | KonohaX Gateway | mTLS, request signing, rate limiting operational |
| 4-5 | Token Cache layer | Redis cluster, < 5ms latency for token validation |
| 5-6 | FIDO2 integration | WebAuthn server, passkey support |
| 6-7 | Hokage Wallet MVP | iOS/Android, basic auth + CitizenshipVC |
| 7-8 | Consent Engine v1 | ABAC policies, consent receipts |
| 8-9 | Audit Log system | ImmuDB deployed, Merkle-tree verification |
| 9-10 | Developer Portal | Sandbox environment, SDKs |
| 10-11 | Integration testing | 3 agencies: Civil Registry, Tax, Health |
| 11-12 | Security audit | External penetration test, bug bounty launch |

### Phase 2: Expansion (Months 13-30)
**Goal:** Full government integration + advanced features

| Quarter | Deliverable |
|---------|-------------|
| Q1 Y2 | All 7 sector SPIDs live |
| Q2 Y2 | ZKP age verification (Groth16) |
| Q3 Y2 | Full VC catalog (12 credential types) |
| Q4 Y2 | All government agencies on KonohaX |
| Q1 Y3 | Pre-filled tax returns operational |
| Q2 Y3 | Delegation/guardian flows |

### Phase 3: Private Sector + International (Months 31-60)
**Goal:** Banking, telecom integration + EU eIDAS compatibility

| Quarter | Deliverable |
|---------|-------------|
| Q3 Y3 | Licensed private sector onboarding (Tier 2-3) |
| Q4 Y3 | EU eIDAS 2.0 wallet compatibility |
| Q1 Y4 | Rural edge nodes (50 locations) |
| Q2 Y4 | Blind-signature voting system |
| Q3 Y4 | Post-quantum crypto migration begins |

---

## 1.5 Engineering Tasks (35 Tasks)

### Infrastructure Tasks

```
INF-001: Provision HSM clusters (3 regions)
  Owner: Platform Team
  Effort: 4 weeks
  Dependencies: None
  Acceptance: FIPS 140-3 Level 3 certification complete

INF-002: Deploy Kubernetes clusters (2 regions)
  Owner: Platform Team
  Effort: 2 weeks
  Dependencies: INF-001
  Acceptance: 99.99% uptime, auto-scaling configured

INF-003: Set up Redis Cluster for token cache
  Owner: Data Team
  Effort: 1 week
  Dependencies: INF-002
  Acceptance: < 5ms p99 latency, 3-way replication

INF-004: Deploy Kafka event bus
  Owner: Platform Team
  Effort: 2 weeks
  Dependencies: INF-002
  Acceptance: 100k msg/sec throughput, 3x replication

INF-005: Deploy ImmuDB audit log
  Owner: Security Team
  Effort: 2 weeks
  Dependencies: INF-002
  Acceptance: Merkle root verifiable, tamper-evident

INF-006: Configure mTLS mesh (Istio/Linkerd)
  Owner: Platform Team
  Effort: 2 weeks
  Dependencies: INF-002
  Acceptance: All inter-service traffic encrypted + authenticated

INF-007: Set up edge nodes (50 rural locations)
  Owner: Infrastructure Team
  Effort: 8 weeks
  Dependencies: INF-002
  Acceptance: Offline credential verification, 6-hour sync
```

### Core Services Tasks

```
SRV-001: Implement CIV gRPC service
  Owner: Identity Team
  Effort: 6 weeks
  Dependencies: INF-001
  Acceptance: < 5ms SPID generation, HSM integration tests pass

SRV-002: Build K-IdP OAuth 2.1 server
  Owner: Auth Team
  Effort: 8 weeks
  Dependencies: INF-002, SRV-001
  Acceptance: Pass OIDC conformance suite, < 500ms auth latency

SRV-003: Implement FIDO2/WebAuthn server
  Owner: Auth Team
  Effort: 4 weeks
  Dependencies: SRV-002
  Acceptance: Pass FIDO2 server conformance tests

SRV-004: Build KonohaX Gateway
  Owner: Integration Team
  Effort: 6 weeks
  Dependencies: INF-002, INF-006
  Acceptance: mTLS handshake, request signing, rate limiting

SRV-005: Implement Consent Engine
  Owner: Privacy Team
  Effort: 6 weeks
  Dependencies: INF-005
  Acceptance: ABAC policies enforced, < 10ms consent check

SRV-006: Build Service Registry
  Owner: Integration Team
  Effort: 3 weeks
  Dependencies: SRV-004
  Acceptance: Schema validation, service discovery

SRV-007: Implement token rotation service
  Owner: Auth Team
  Effort: 2 weeks
  Dependencies: SRV-002
  Acceptance: Refresh tokens rotate on use, old invalidated
```

### Cryptography Tasks

```
CRY-001: Implement Ed25519 signing (HSM-resident keys)
  Owner: Crypto Team
  Effort: 3 weeks
  Dependencies: INF-001
  Acceptance: 10k sigs/sec, keys never leave HSM

CRY-002: Implement BBS+ signature scheme
  Owner: Crypto Team
  Effort: 4 weeks
  Dependencies: CRY-001
  Acceptance: Selective disclosure works, verify with 3+ libs

CRY-003: Build ZKP age verification circuit
  Owner: Crypto Team
  Effort: 6 weeks
  Dependencies: CRY-002
  Acceptance: < 200ms proof generation on mid-range phone

CRY-004: Implement SPID derivation (HMAC-SHA256)
  Owner: Crypto Team
  Effort: 2 weeks
  Dependencies: SRV-001
  Acceptance: Deterministic, unique per sector

CRY-005: Build DPoP token binding
  Owner: Auth Team
  Effort: 2 weeks
  Dependencies: SRV-002
  Acceptance: Tokens bound to device key, theft = useless
```

### Mobile/Client Tasks

```
MOB-001: Hokage Wallet iOS app
  Owner: Mobile Team
  Effort: 10 weeks
  Dependencies: SRV-002, CRY-002
  Acceptance: App Store approval, < 2min key flows

MOB-002: Hokage Wallet Android app
  Owner: Mobile Team
  Effort: 10 weeks
  Dependencies: SRV-002, CRY-002
  Acceptance: Play Store approval, feature parity with iOS

MOB-003: Implement secure enclave key storage
  Owner: Mobile Team
  Effort: 3 weeks
  Dependencies: MOB-001, MOB-002
  Acceptance: Keys in Secure Enclave/Keystore, no export

MOB-004: Offline credential presentation
  Owner: Mobile Team
  Effort: 4 weeks
  Dependencies: MOB-003, CRY-002
  Acceptance: Works without internet, cached pub keys

MOB-005: Smart card integration
  Owner: Hardware Team
  Effort: 6 weeks
  Dependencies: CRY-001
  Acceptance: NFC read, JavaCard applet
```

### Integration Tasks

```
INT-001: Civil Registry integration
  Owner: Integration Team
  Effort: 4 weeks
  Dependencies: SRV-004, SRV-005
  Acceptance: CitizenshipVC issuance, NIN generation

INT-002: Tax Authority integration
  Owner: Integration Team
  Effort: 4 weeks
  Dependencies: SRV-004, SRV-005
  Acceptance: TaxStatusVC, IncomeRangeVC

INT-003: Health Ministry integration
  Owner: Integration Team
  Effort: 4 weeks
  Dependencies: SRV-004, SRV-005
  Acceptance: HealthInsuranceVC, vaccination records

INT-004: Developer portal + sandbox
  Owner: DevEx Team
  Effort: 6 weeks
  Dependencies: SRV-002, SRV-004
  Acceptance: Interactive docs, test citizens, SDKs

INT-005: SDKs (JS, Python, Go, Java, Swift)
  Owner: DevEx Team
  Effort: 8 weeks
  Dependencies: INT-004
  Acceptance: All SDKs published, example apps work
```

### Security Tasks

```
SEC-001: Threat modeling (STRIDE)
  Owner: Security Team
  Effort: 2 weeks
  Dependencies: SRV-001, SRV-002, SRV-004
  Acceptance: All threats documented, mitigations in place

SEC-002: Penetration testing
  Owner: External vendor
  Effort: 4 weeks
  Dependencies: Phase 1 complete
  Acceptance: No critical vulnerabilities

SEC-003: Bug bounty program
  Owner: Security Team
  Effort: 2 weeks
  Dependencies: Phase 1 complete
  Acceptance: Program live on HackerOne/Bugcrowd

SEC-004: Security monitoring (SIEM)
  Owner: Security Team
  Effort: 3 weeks
  Dependencies: INF-002
  Acceptance: Real-time alerting, 24/7 SOC

SEC-005: Key ceremony procedures
  Owner: Security Team
  Effort: 2 weeks
  Dependencies: INF-001
  Acceptance: 3-of-5 ceremony documented, tested
```

### Testing Tasks

```
TST-001: Unit test coverage > 80%
  Owner: All teams
  Effort: Ongoing
  Dependencies: All
  Acceptance: CI blocks on < 80% coverage

TST-002: Integration test suite
  Owner: QA Team
  Effort: 4 weeks
  Dependencies: Phase 1 complete
  Acceptance: Full E2E flows automated

TST-003: Load testing (50M users)
  Owner: SRE Team
  Effort: 3 weeks
  Dependencies: Phase 1 complete
  Acceptance: System handles 10k auth/sec

TST-004: Chaos engineering
  Owner: SRE Team
  Effort: 2 weeks
  Dependencies: INF-002
  Acceptance: Auto-failover < 30 seconds

TST-005: Disaster recovery drill
  Owner: SRE Team
  Effort: 1 week
  Dependencies: INF-001
  Acceptance: RPO 0, RTO < 30 minutes
```

---

*End of CTO Draft — Proceeding to Security Review*


---

# PART 2: SECURITY REVIEW — CRITICAL FINDINGS & HARDENING

## 2.1 Executive Summary

**Reviewer:** Security Lead  
**Review Scope:** Full KNDIS architecture v1.0 + CTO Draft v1.0  
**Findings:** 14 critical issues identified, 9 high-priority, 12 medium-priority  
**Recommendation:** DO NOT PROCEED to production without addressing critical findings

---

## 2.2 Critical Findings (MUST FIX)

### 🔴 CRIT-001: HSM Key Extraction Risk in CIV

**Finding:** The CTO draft describes CIV computing SPIDs but doesn't specify how HSM-resident keys are protected against extraction during the HMAC operation.

**Attack Scenario:**
1. Attacker gains code execution on CIV application server
2. CIV has HSM session open for SPID generation
3. Attacker crafts malicious HMAC requests to extract key material through side channels

**Risk:** Complete compromise of sector SPID derivation → all pseudonyms linkable

**Hardened Fix:**
```
1. Use HSM's KEY HANDLE mode, never exportable keys
2. HMAC operation performed ENTIRELY within HSM boundary
3. CIV sends: NIN_hash || sector_constant to HSM
4. HSM returns: SPID only, never exposes HMAC key
5. Implement HSM request signing with ephemeral keys
6. Rate limit: 1000 HMAC ops/sec per HSM cluster
7. Alert on anomalous HMAC patterns
```

**Implementation:**
- Hardware: Thales Luna 7 HSMs with PED authentication
- Key ceremony: 3-of-5 split, geographic distribution
- Key usage: Dedicated HSM partition per sector
- Audit: Every HMAC operation logged with request hash

---

### 🔴 CRIT-002: Token Cache Redis Compromise = Session Hijacking

**Finding:** Token cache stores active session data. If Redis is compromised, attacker gets valid tokens.

**Attack Scenario:**
1. Attacker exploits Redis vulnerability (e.g., Lua sandbox escape)
2. Extracts all active tokens
3. Uses tokens before expiry (15 minutes = massive window)

**Risk:** Mass session hijacking, unauthorized data access

**Hardened Fix:**
```yaml
Token Cache Hardening:
  1. Encryption at Rest:
     - AES-256-GCM with HSM-wrapped DEK
     - Each token encrypted with unique IV
     
  2. Shortened TTL:
     - Access tokens: 15 min → 5 min
     - Refresh tokens: 30 days → 7 days
     
  3. Token Binding:
     - DPoP mandatory (already in design ✓)
     - Device fingerprint in token
     - Geo-binding for high-risk operations
     
  4. Redis Security:
     - No Lua scripting (attack surface)
     - ACLs: token service only
     - TLS 1.3 mandatory
     - No external network access
     
  5. Compromise Detection:
     - Canary tokens in Redis
     - Anomaly detection on token usage patterns
     - Automatic token revocation on breach signal
```

---

### 🔴 CRIT-003: Consent Engine ABAC Policy Bypass

**Finding:** ABAC policies rely on consent receipts stored in PostgreSQL. SQL injection or privilege escalation could bypass consent checks.

**Attack Scenario:**
1. Attacker finds SQL injection in consent check API
2. Modifies consent_receipts table to add fake consent
3. ABAC engine reads fake consent, permits unauthorized access

**Risk:** Unauthorized citizen data access, regulatory violation

**Hardened Fix:**
```
ABAC Hardening:
  1. Database Layer:
     - Prepared statements ONLY (no string concatenation)
     - Row-level security policies
     - Separate DB user for reads vs writes
     - Consent receipts table: INSERT-only, no UPDATE
     
  2. Application Layer:
     - Consent check results signed by Consent Engine
     - Signature verified by KonohaX before data release
     - Double-check: verify consent receipt signature matches
     
  3. Cryptographic Binding:
     - Consent receipt includes hash of citizen SPID + attributes
     - Any tampering breaks signature verification
     
  4. Audit:
     - Every consent check logged to immutable audit log
     - Citizen notified of all consent grants
```

---

### 🔴 CRIT-004: DPoP Implementation Weakness

**Finding:** DPoP proof verification may be skipped or incorrectly implemented, allowing token theft and replay.

**Attack Scenario:**
1. Attacker steals access token (via XSS, network sniffing)
2. Attacker doesn't have DPoP private key
3. If DPoP verification is optional → token works
4. If DPoP binding check is weak → token works

**Risk:** Token theft = account compromise

**Hardened Fix:**
```
DPoP Enforcement:
  1. Mandatory DPoP:
     - All access tokens MUST be DPoP-bound
     - Requests without DPoP proof: 401 Unauthorized
     
  2. Strict Verification:
     - Extract jkt from token cnf claim
     - Verify DPoP proof signature against jwk
     - Verify ath claim matches access token hash
     - Verify htm/htu match actual request
     - Verify iat within 60 seconds
     - Reject replay: cache jti for 2x proof lifetime
     
  3. Key Rotation:
     - DPoP keys rotated every 24 hours
     - Old keys valid for 1-hour grace period
     
  4. Client Implementation:
     - Wallet generates fresh DPoP key per session
     - Private key in secure enclave only
```

---

### 🔴 CRIT-005: ZKP Circuit Implementation Bugs

**Finding:** Custom ZKP circuits (Groth16) are prone to implementation errors that can allow fake proofs.

**Attack Scenario:**
1. Attacker finds under-constrained variable in age verification circuit
2. Generates proof that passes verification but proves false statement
3. Gains access to age-restricted services while underage

**Risk:** Fake credentials, regulatory violation, safety issues

**Hardened Fix:**
```
ZKP Security:
  1. Formal Verification:
     - Circuits formally verified with Circom verifier
     - Use battle-tested libraries: snarkjs, arkworks
     - NO custom crypto
     
  2. Trusted Setup:
     - MPC ceremony with 100+ participants
     - If any participant is honest, setup is secure
     - Publish transcript for public verification
     
  3. Circuit Audits:
     - External audit by ZK security firm (Trail of Bits, Zellic)
     - Bug bounty specifically for ZKP bypasses
     
  4. Fallback:
     - If ZKP fails, fall back to VC presentation
     - Never rely solely on ZKP for critical decisions
     
  5. Proof Verification:
     - Verify on server side (not client)
     - Use constant-time verification
     - Cache verification keys, validate checksums
```

---

### 🔴 CRIT-006: Insider Threat — CIV Administrator

**Finding:** CIV administrators with sufficient privileges could potentially extract NIN→SPID mappings.

**Attack Scenario:**
1. Rogue CIV admin with HSM access
2. Uses administrative functions to dump mapping tables
3. Sells/leaks data → complete citizen identity exposure

**Risk:** Total system compromise, mass surveillance

**Hardened Fix:**
```
CIV Insider Protection:
  1. Multi-Party Authorization:
     - Any CIV operation requires 2-of-3 approvers
     - Approvers: different teams, different locations
     - Time-bound approvals (expire in 1 hour)
     
  2. HSM Key Ceremony:
     - Root keys generated in HSM, never exported
     - Key shares: 3-of-5 split
     - Share holders: CIV Director, DPC Commissioner, 
       Judicial Officer, Parliamentary Officer, Auditor General
     - Geographic separation of share holders
     
  3. No Direct Access:
     - CIV operators use read-only dashboards
     - No SQL access to production
     - All operations via audited API
     
  4. Canary Checks:
     - Fake citizen records in CIV
     - Monitored for unauthorized access
     - Alert triggers immediate investigation
     
  5. Background Checks:
     - CIV personnel: security clearance required
     - Regular re-screening
     - 2-person rule for physical HSM access
```

---

### 🔴 CRIT-007: KonohaX Gateway Request Replay

**Finding:** Signed requests to KonohaX could be replayed if timestamps aren't strictly enforced.

**Attack Scenario:**
1. Attacker intercepts legitimate signed request
2. Replays request to access citizen data multiple times
3. Consumes consent access count, accesses data without fresh consent

**Risk:** Unauthorized data access, consent bypass

**Hardened Fix:**
```
Replay Protection:
  1. Timestamp Enforcement:
     - Max drift: 60 seconds (not 300)
     - Clock sync: NTP with authentication
     - Reject requests with future timestamps
     
  2. Request ID Uniqueness:
     - X-KonohaX-Request-ID: UUID v4
     - Cache seen IDs for 5 minutes
     - Reject duplicate IDs
     
  3. Idempotency Keys:
     - Safe operations (GET) use idempotency keys
     - Unsafe operations (POST) require fresh signatures
     
  4. Signature Scope:
     - Signature includes: method + path + body + timestamp + request_id
     - Any change invalidates signature
```

---

## 2.3 High-Priority Findings

### 🟠 HIGH-001: FIDO2 Credential Loss Recovery

**Finding:** If citizen loses all FIDO2 credentials (phone + backup), recovery is undefined.

**Fix:**
```
Recovery Options (citizen chooses at enrollment):
  Option A: Recovery Codes
    - 10 single-use codes, printed and stored safely
    - Requires in-person verification at government office
    
  Option B: Trusted Contacts
    - 3 trusted contacts designated
    - 2-of-3 must approve recovery
    
  Option C: Biometric + Document
    - In-person at enrollment center
    - Biometric match + physical document verification
    - New credentials issued after 7-day cooling period
    
  Option D: Legal Process
    - Court order for identity recovery
    - Used for deceased estates, legal guardianship
```

---

### 🟠 HIGH-002: Wallet App Compromise

**Finding:** If Hokage Wallet is compromised, attacker has access to all citizen credentials.

**Fix:**
```
Wallet Security Layers:
  1. Biometric Lock:
     - Face/fingerprint required for every use
     - No "remember me" option
     
  2. Key Encryption:
     - Private keys encrypted with biometric-derived key
     - Keys never in application memory unencrypted
     
  3. Remote Wipe:
     - Citizen can remotely wipe wallet via web portal
     - Wipe propagates within 60 seconds
     
  4. Jailbreak/Root Detection:
     - App refuses to run on compromised devices
     - Attestation check on each launch
     
  5. Transaction Signing:
     - High-value operations require explicit confirmation
     - Visual hash of transaction shown for verification
```

---

### 🟠 HIGH-003: Audit Log Tampering

**Finding:** If audit log system is compromised, malicious activity can be hidden.

**Fix:**
```
Audit Log Hardening:
  1. Immutable Storage:
     - ImmuDB with Merkle-tree verification
     - Separate infrastructure from main system
     - Different admin team
     
  2. External Anchors:
     - Daily Merkle root published to:
       - National gazette
       - Blockchain (Bitcoin/Ethereum) for timestamp
       - Multiple notary services
     
  3. Tamper Detection:
     - Citizens can verify their own audit entries
     - Public transparency portal
     - Third-party auditors have read access
     
  4. Retention:
     - 7 years minimum retention
     - Geographic replication
     - Air-gapped backup monthly
```

---

### 🟠 HIGH-004: Supply Chain Attacks

**Finding:** Compromised dependencies or build pipeline could inject backdoors.

**Fix:**
```
Supply Chain Security:
  1. Dependency Management:
     - Pin all dependencies to exact versions
     - SCA scanning (Snyk, Dependabot) in CI
     - No dependencies with known CVEs
     
  2. Build Security:
     - Reproducible builds
     - Build in isolated, ephemeral environments
     - Signed artifacts only
     
  3. SBOM:
     - Generate Software Bill of Materials
     - Publish with each release
     - Vulnerability tracking by component
     
  4. Vendor Security:
     - HSM vendor: source code escrow
     - Security audit of vendor practices
     - Alternative vendor identified for continuity
```

---

### 🟠 HIGH-005: Smart Card Cloning

**Finding:** Smart cards could be cloned if physical security is compromised.

**Fix:**
```
Smart Card Security:
  1. Secure Element:
     - JavaCard with GlobalPlatform security
     - Private keys generated on-card, never exported
     
  2. Cloning Detection:
     - Each card has unique counter
     - Counter checked on each use
     - Clone detection = immediate revocation
     
  3. PIN Protection:
     - 6-digit PIN required
     - 3 wrong attempts = card lock
     - Unlock requires in-person visit
     
  4. Revocation:
     - Cards revocable via wallet or hotline
     - Revocation list updated every 6 hours
     - Online verification preferred when possible
```

---

## 2.4 Security Model Summary (Hardened)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    KNDIS SECURITY ARCHITECTURE (HARDENED)                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  LAYER 1: PERIMETER                                                      │
│  ├── DDoS protection (Cloudflare/AWS Shield)                            │
│  ├── WAF with custom rules for KNDIS APIs                               │
│  ├── Rate limiting per IP/client/citizen                                │
│  └── Geo-blocking for high-risk countries                               │
│                                                                          │
│  LAYER 2: TRANSPORT                                                      │
│  ├── TLS 1.3 mandatory (no downgrade)                                   │
│  ├── mTLS for all inter-service communication                           │
│  ├── Certificate pinning in mobile apps                                 │
│  └── HSTS with preload                                                  │
│                                                                          │
│  LAYER 3: AUTHENTICATION                                                 │
│  ├── FIDO2/WebAuthn mandatory (no passwords)                            │
│  ├── DPoP token binding enforced                                        │
│  ├── Risk-adaptive MFA                                                  │
│  └── Device attestation                                                 │
│                                                                          │
│  LAYER 4: AUTHORIZATION                                                  │
│  ├── ABAC with fine-grained policies                                    │
│  ├── Consent receipts cryptographically signed                          │
│  ├── Principle of least privilege                                       │
│  └── Just-in-time access for admins                                     │
│                                                                          │
│  LAYER 5: DATA PROTECTION                                                │
│  ├── Encryption at rest (AES-256-GCM)                                   │
│  ├── Encryption in transit (TLS 1.3)                                    │
│  ├── HSM-resident keys only                                             │
│  └── Tokenization (NIN never exposed)                                   │
│                                                                          │
│  LAYER 6: AUDIT & MONITORING                                             │
│  ├── Immutable audit log (Merkle-tree)                                  │
│  ├── Real-time SIEM alerting                                            │
│  ├── Anomaly detection ML                                               │
│  └── 24/7 Security Operations Center                                    │
│                                                                          │
│  LAYER 7: GOVERNANCE                                                     │
│  ├── Multi-party authorization for sensitive ops                        │
│  ├── Regular penetration testing                                        │
│  ├── Bug bounty program                                                 │
│  └── External security audits                                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2.5 Security Review Conclusion

**Verdict:** Architecture is sound but requires hardening before production.

**Critical Path to Production:**
1. Address all 7 critical findings
2. Complete penetration testing
3. Bug bounty program active for 90 days
4. External security audit passed
5. SOC 2 Type II certification (or equivalent)

**Estimated Security Hardening Effort:** +8 weeks to Phase 1 timeline

---

*End of Security Review — Proceeding to SRE Review*


---

# PART 3: SRE REVIEW — SCALE & RELIABILITY WAR GAME

## 3.1 Executive Summary

**Reviewer:** SRE Lead  
**Test Scenarios:** 10M → 50M citizens, peak election day load, disaster scenarios  
**Findings:** 6 critical bottlenecks, 8 failure modes, 5 scaling concerns  
**Recommendation:** Architecture viable with modifications for 50M scale

---

## 3.2 Scale Assumptions & Projections

### Citizen Population Projections

| Year | Citizens | Daily Active | Peak Concurrent | Auth Requests/sec |
|------|----------|--------------|-----------------|-------------------|
| Y1 | 10M | 2M (20%) | 100K | 500 |
| Y2 | 20M | 5M (25%) | 300K | 1,500 |
| Y3 | 35M | 10M (29%) | 700K | 3,500 |
| Y5 | 50M | 15M (30%) | 1.5M | 7,500 |
| Election Day | 50M | 40M (80%) | 5M | 25,000 |

### Peak Load Scenarios

```
SCENARIO 1: Normal Peak (Morning Rush)
- Time: 08:00-09:00 local time
- Load: 3x average
- Pattern: Citizens accessing services before work

SCENARIO 2: Tax Deadline
- Date: April 15
- Load: 10x average for Tax Authority
- Pattern: Last-minute filing, payment processing

SCENARIO 3: Election Day
- Date: National election
- Load: 50x average
- Pattern: Voter verification, result checking
- Duration: 18 hours (06:00-00:00)

SCENARIO 4: Health Crisis
- Event: Pandemic, vaccination drive
- Load: 20x average for Health Ministry
- Pattern: Appointment booking, certificate verification

SCENARIO 5: Cyber Attack
- Event: DDoS, system under attack
- Load: 1000x fake requests
- Pattern: Attack traffic mixed with legitimate
```

---

## 3.3 Critical Bottlenecks Identified

### 🔴 BOTTLENECK-001: CIV HSM Throughput

**Finding:** HSMs have finite cryptographic throughput. At 50M citizens, SPID generation could become a bottleneck.

**Analysis:**
```
HSM Performance (Thales Luna 7):
- HMAC-SHA256: ~5,000 ops/sec per HSM
- 3 HSM clusters × 2 HSMs each = 6 HSMs
- Total capacity: 30,000 HMAC ops/sec

Peak Load:
- Election day: 25,000 auth requests/sec
- Each auth requires: 1 SPID generation
- Margin: 5,000 ops/sec (20% headroom)

PROBLEM: No headroom for:
- Batch operations
- SPID rotation events
- Administrative queries
- HSM maintenance/failover
```

**Fix:**
```
1. HSM Scaling:
   - Increase to 5 HSMs per cluster (15 total)
   - Capacity: 75,000 ops/sec
   - Headroom: 200%

2. Connection Pooling:
   - Maintain persistent HSM sessions
   - Reduce session establishment overhead
   - Connection pool: 100 per CIV instance

3. Batch Operations:
   - Batch SPID generation API
   - Process 100 SPIDs per HSM call
   - Reduces HSM round trips

4. Caching Layer:
   - Cache SPID for session duration
   - 95% of requests use cached SPID
   - Only 5% hit HSM

5. Read Replicas:
   - SPID resolution (rare) on read replicas
   - Write operations on primary only
```

---

### 🔴 BOTTLENECK-002: K-IdP Session State

**Finding:** K-IdP with OAuth 2.1 requires session state. At scale, session storage becomes a bottleneck.

**Analysis:**
```
Session Storage Requirements:
- 50M citizens × 2 active sessions each = 100M sessions
- Session size: ~2KB each
- Total storage: 200GB

Current Design:
- Sessions in Redis
- 6-node cluster
- Memory per node: 64GB
- Usable: ~50GB per node (after overhead)
- Total: 300GB

PROBLEM:
- Redis memory fragmentation
- Session expiry cleanup overhead
- Failover = session loss
```

**Fix:**
```
1. Stateless Sessions:
   - Move session data to JWT
   - Only store revocation list in Redis
   - Reduces storage by 95%

2. Redis Cluster Optimization:
   - 12 nodes (double current)
   - 128GB per node
   - Total: 1.5TB usable

3. Session Sharding:
   - Shard by citizen SPID hash
   - Predictable routing
   - Hot key distribution

4. Hybrid Approach:
   - Active sessions: Redis (fast)
   - Idle sessions: PostgreSQL (cheap)
   - Promote on access

5. Session Compression:
   - Compress session data with zstd
   - 3x reduction in size
```

---

### 🔴 BOTTLENECK-003: KonohaX Gateway Latency

**Finding:** Cross-agency requests through KonohaX add latency. At scale, cascading delays occur.

**Analysis:**
```
Request Latency Breakdown:
- Client → KonohaX: 20ms
- KonohaX auth check: 5ms
- KonohaX → Agency: 30ms
- Agency processing: 100ms
- Agency → KonohaX: 30ms
- KonohaX response: 5ms
- Total: 190ms

Target: < 300ms p99

PROBLEM:
- Agency latency varies (50-500ms)
- Cascading timeouts
- Retry storms during degradation
```

**Fix:**
```
1. Circuit Breakers:
   - Per-agency circuit breakers
   - Open after 50% error rate
   - Half-open after 30s cooldown

2. Request Coalescing:
   - Deduplicate identical requests
   - Single request to agency serves multiple clients
   - Cache for 1 second

3. Async Where Possible:
   - Fire-and-forget for non-critical events
   - Webhook callbacks instead of polling
   - Event-driven architecture

4. Connection Pooling:
   - Persistent connections to agencies
   - HTTP/2 multiplexing
   - Reduce connection overhead

5. Timeout Hierarchy:
   - Client timeout: 5s
   - KonohaX timeout: 3s
   - Agency SLA: 2s
   - Cascading timeout prevention

6. Edge Caching:
   - Cache public data at edge
   - Revocation lists, schemas, pub keys
   - 6-hour TTL acceptable
```

---

### 🔴 BOTTLENECK-004: Kafka Event Bus Saturation

**Finding:** Event-driven architecture depends on Kafka. At peak load, event volume could saturate brokers.

**Analysis:**
```
Event Volume Projections:
- Auth events: 25,000/sec (election day)
- Consent events: 5,000/sec
- Audit events: 50,000/sec (every data access)
- Total: 80,000 events/sec

Kafka Capacity (5 brokers):
- Per broker: 20,000 writes/sec
- Total: 100,000 writes/sec
- Replication factor 3: 300,000 writes/sec

PROBLEM:
- Consumer lag during peak
- Disk I/O saturation
- Network bandwidth limits
```

**Fix:**
```
1. Kafka Scaling:
   - 10 brokers (double current)
   - 3.6M writes/sec capacity
   - Headroom: 1000%

2. Topic Partitioning:
   - auth.events: 24 partitions
   - consent.events: 12 partitions
   - audit.events: 48 partitions
   - Parallel consumption

3. Tiered Storage:
   - Hot data: SSD (7 days)
   - Warm data: HDD (90 days)
   - Cold data: S3 (7 years)

4. Consumer Optimization:
   - Batch processing: 100 events per poll
   - Parallel consumers per partition
   - Backpressure handling

5. Event Sampling:
   - Audit events: 100% (required)
   - Metrics events: 1% sample at peak
   - Reduce non-critical volume
```

---

### 🔴 BOTTLENECK-005: Database Connection Exhaustion

**Finding:** PostgreSQL for consent and service registry has connection limits.

**Analysis:**
```
PostgreSQL Limits:
- Max connections: 100 (default)
- Can increase to: 500
- Each connection: ~10MB RAM
- 500 connections = 5GB RAM

Connection Requirements:
- K-IdP: 50 connections
- Consent Engine: 100 connections
- KonohaX: 50 connections
- Background jobs: 50 connections
- Total: 250 connections

PROBLEM:
- Connection leaks
- Slow queries hold connections
- Burst traffic exhausts pool
```

**Fix:**
```
1. Connection Pooling (PgBouncer):
   - Transaction-level pooling
   - Max 1000 client connections
   - 100 server connections
   - 10:1 multiplexing

2. Read Replicas:
   - 3 read replicas
   - Read traffic distributed
   - Writes to primary only

3. Query Optimization:
   - All queries < 10ms
   - Index on all lookup columns
   - Query plan analysis in CI

4. Circuit Breaker:
   - DB circuit breaker
   - Fail fast when DB slow
   - Queue requests, don't exhaust pool

5. Async Database:
   - Use async PostgreSQL driver
   - Non-blocking I/O
   - Better connection utilization
```

---

### 🔴 BOTTLENECK-006: Edge Node Synchronization

**Finding:** Rural edge nodes sync every 6 hours. During emergencies, stale data is a problem.

**Analysis:**
```
Sync Schedule:
- Normal: Every 6 hours
- Emergency: Manual trigger
- Revocation list: Could be 6 hours stale

Risk Scenarios:
- Compromised credential used in rural area
- Revocation not propagated for 6 hours
- Fraud possible during window
```

**Fix:**
```
1. Priority Sync:
   - Revocations: Push within 60 seconds
   - Critical updates: Push immediately
   - Normal data: 6-hour batch

2. Satellite Backup:
   - Starlink terminals at edge nodes
   - Always-on connectivity option
   - Fallback to batch if satellite down

3. Hierarchical Sync:
   - Edge nodes sync from regional hubs
   - Regional hubs sync from central
   - Reduces central load

4. Delta Sync:
   - Only sync changes, not full dataset
   - 95% reduction in sync volume
   - Faster sync completion

5. Offline Verification Fallback:
   - If sync > 24 hours stale
   - Require online verification
   - Degraded service but secure
```

---

## 3.4 Failure Mode Analysis

### Failure Mode Matrix

| Component | Failure Mode | Impact | Detection | Recovery | RTO |
|-----------|--------------|--------|-----------|----------|-----|
| CIV Primary | HSM failure | SPID generation stops | Health check | Failover to secondary | 30s |
| CIV All | Complete outage | No new auth possible | Multi-region alert | Emergency unlock | 30min |
| K-IdP | Node failure | 33% capacity loss | Load balancer | Auto-restart | 10s |
| K-IdP All | Complete outage | No authentication | External probe | Regional failover | 30s |
| Redis | Node failure | Cache miss increase | Cluster health | Replica promotion | 5s |
| Redis All | Complete outage | Session loss | Timeout | Cold start from DB | 5min |
| Kafka | Broker failure | Event delay | Metrics | Replica leader election | 3s |
| PostgreSQL | Primary failure | Write outage | Replication lag | Replica promotion | 60s |
| KonohaX | Gateway failure | Cross-agency blocked | Health check | Auto-scaling | 30s |
| Agency API | Slow/down | Service degradation | Timeout | Circuit breaker | 5s |

### Detailed Failure Scenarios

#### SCENARIO-001: CIV Primary HSM Failure

```
Timeline:
T+0s    - HSM health check fails
T+1s    - Alert fired to on-call
T+5s    - Automatic failover initiated
T+10s   - Secondary HSM promoted to primary
T+15s   - CIV reconnects to new primary
T+30s   - Service restored

Data Loss: 0 (synchronous replication)
Impact: 30-second auth delay
Mitigation: Clients retry with exponential backoff
```

#### SCENARIO-002: DDoS Attack on K-IdP

```
Timeline:
T+0s    - Traffic spike detected (10x normal)
T+5s    - Rate limiting activated per IP
T+10s   - Challenge-response (CAPTCHA) for suspicious IPs
T+15s   - Geo-blocking for high-risk countries
T+30s   - DDoS scrubbing service activated
T+60s   - Attack traffic filtered
T+120s  - Normal service restored

Legitimate Impact: < 5% request failure
Mitigation: Multi-layer defense, gradual escalation
```

#### SCENARIO-003: Database Corruption

```
Timeline:
T+0s    - Checksum mismatch detected
T+1s    - Database taken offline
T+5s    - Replica promoted to primary
T+10s   - Service restored with replica
T+1h    - Root cause analysis
T+24h   - Corrupted DB restored from backup
T+48h   - Full verification complete

Data Loss: < 1 minute (synchronous replication)
Impact: 10-second outage
Mitigation: Immutable backups, point-in-time recovery
```

#### SCENARIO-004: Complete Regional Failure

```
Timeline:
T+0s    - Region health checks fail
T+5s    - DNS failover to secondary region
T+10s   - Traffic routed to standby region
T+30s   - Service restored from secondary
T+1h    - Investigation begins
T+4h    - Primary region restored
T+8h    - Traffic gradually shifted back

Data Loss: 0 (cross-region sync)
Impact: 30-second outage
Mitigation: Active-standby, automated failover
```

---

## 3.5 Observability Design

### Metrics (Prometheus/Grafana)

```yaml
# Golden Signals
authentication_requests_total:
  type: counter
  labels: [status, sector, auth_method]
  
authentication_latency_seconds:
  type: histogram
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5]
  
active_sessions:
  type: gauge
  labels: [sector]
  
token_cache_hit_ratio:
  type: gauge
  
hsm_operations_total:
  type: counter
  labels: [operation, status]
  
consent_checks_total:
  type: counter
  labels: [outcome]
  
kafka_consumer_lag:
  type: gauge
  labels: [topic, consumer_group]
  
database_connections_active:
  type: gauge
  
# Custom Metrics
citizen_data_access_total:
  type: counter
  labels: [sector, purpose, outcome]
  
revocation_propagation_delay_seconds:
  type: histogram
  
edge_node_sync_age_seconds:
  type: gauge
  labels: [node_id]
```

### Logging (Structured JSON)

```json
{
  "timestamp": "2026-04-02T10:23:44.123Z",
  "level": "info",
  "service": "k-idp",
  "trace_id": "abc123",
  "span_id": "def456",
  "event": "authentication_success",
  "citizen_spid": "H-XXX...",
  "sector": "health",
  "auth_method": "fido2",
  "risk_score": 15,
  "latency_ms": 245,
  "client_ip": "203.0.113.42",
  "user_agent": "HokageWallet/2.1.0"
}
```

### Alerting (PagerDuty)

| Alert | Condition | Severity | Response |
|-------|-----------|----------|----------|
| K-IdP High Error Rate | > 1% 5xx for 2min | P1 | Page on-call |
| CIV HSM Unavailable | Any HSM down | P1 | Page on-call |
| Auth Latency Spike | p99 > 1s for 5min | P2 | Page on-call |
| Token Cache Miss Spike | > 50% for 10min | P2 | Notify team |
| Kafka Consumer Lag | > 1000 messages | P2 | Notify team |
| Edge Node Stale | Sync > 12h old | P3 | Ticket |
| High CPU | > 80% for 30min | P3 | Ticket |

### Distributed Tracing (Jaeger)

```
Trace: Authentication Flow
├── K-IdP: /oauth/authorize (20ms)
│   ├── Risk Engine: check (5ms)
│   └── Consent Check: query (3ms)
├── K-IdP: /oauth/token (50ms)
│   ├── CIV: GenerateSPID (10ms)
│   ├── Token Cache: Store (2ms)
│   └── Audit Log: Write (5ms)
└── KonohaX: First API Call (100ms)
    ├── Gateway: Auth (5ms)
    ├── Consent: Verify (5ms)
    └── Agency: Process (90ms)
```

---

## 3.6 Scaling Strategy

### Horizontal Scaling

```
Auto-Scaling Rules:

K-IdP:
  Min: 3 pods per region
  Max: 30 pods per region
  Scale up: CPU > 70% or Latency p99 > 500ms
  Scale down: CPU < 30% for 10min

KonohaX Gateway:
  Min: 3 pods per region
  Max: 20 pods per region
  Scale up: Request queue > 100
  Scale down: Request queue < 10 for 10min

Consent Engine:
  Min: 3 pods per region
  Max: 15 pods per region
  Scale up: DB connection pool > 80%
  Scale down: Connection pool < 30% for 10min
```

### Vertical Scaling

```
HSM Scaling:
  - Start: 2 HSMs per cluster
  - Scale trigger: > 60% capacity
  - Add: 1 HSM per cluster
  - Max: 5 HSMs per cluster

Redis Scaling:
  - Start: 6 nodes (2 shards × 3 replicas)
  - Scale trigger: Memory > 70%
  - Add: 2 nodes per shard
  - Max: 12 nodes (4 shards × 3 replicas)
```

### Database Sharding

```
Consent Database Sharding:
  - Shard by citizen SPID hash mod 16
  - 16 shards, each with primary + 2 replicas
  - Cross-shard queries: aggregation service
  - Rebalancing: online, no downtime
```

---

## 3.7 SRE Review Conclusion

**Verdict:** Architecture can scale to 50M citizens with modifications.

**Critical Scaling Requirements:**
1. HSM cluster expansion (15 HSMs total)
2. Kafka broker expansion (10 brokers)
3. Stateless session design
4. Database connection pooling
5. Edge node priority sync

**Estimated Scaling Infrastructure Cost:**
- Year 1: $2M (10M citizens)
- Year 3: $5M (35M citizens)
- Year 5: $8M (50M citizens)

**Reliability Targets (SLOs):**
| Service | Availability | Latency p99 | Error Rate |
|---------|--------------|-------------|------------|
| K-IdP | 99.99% | 500ms | 0.1% |
| KonohaX | 99.99% | 300ms | 0.1% |
| Consent | 99.95% | 100ms | 0.01% |
| CIV | 99.999% | 10ms | 0.001% |

---

*End of SRE Review — Proceeding to Iteration Loop*


---

# PART 4: ITERATION LOOP — REVISED DESIGN

## 4.1 Security + SRE Feedback Integration

### Feedback Summary

| Source | Finding | Severity | Resolution |
|--------|---------|----------|------------|
| Security | HSM key extraction risk | Critical | HMAC entirely within HSM boundary |
| Security | Token cache compromise | Critical | Encryption at rest, shortened TTL |
| Security | ABAC policy bypass | Critical | Signed consent receipts, INSERT-only DB |
| Security | DPoP weakness | Critical | Mandatory DPoP, strict verification |
| Security | ZKP circuit bugs | Critical | Formal verification, external audit |
| Security | Insider threat | Critical | 3-of-5 key ceremony, multi-party auth |
| Security | Request replay | Critical | 60s timestamp drift, request ID cache |
| Security | FIDO2 recovery | High | Recovery codes, trusted contacts |
| Security | Wallet compromise | High | Biometric lock, remote wipe |
| Security | Audit tampering | High | External anchors, public verification |
| Security | Supply chain | High | Reproducible builds, SBOM |
| Security | Smart card cloning | High | Secure element, cloning detection |
| SRE | HSM throughput | Critical | 15 HSMs, batch operations, caching |
| SRE | Session state | Critical | Stateless JWT sessions |
| SRE | KonohaX latency | Critical | Circuit breakers, connection pooling |
| SRE | Kafka saturation | Critical | 10 brokers, tiered storage |
| SRE | DB connections | Critical | PgBouncer, read replicas |
| SRE | Edge sync | Critical | Priority sync, satellite backup |

### Design Changes Made

#### Change 1: HSM Architecture Hardening

**Original:** CIV computes SPIDs with HSM-assisted HMAC
**Revised:** HSM performs complete HMAC operation, key never leaves HSM

```
BEFORE:
  CIV → HSM: Export key handle
  CIV → Compute HMAC locally
  
AFTER:
  CIV → HSM: Send NIN_hash || sector_constant
  HSM → Compute HMAC internally
  HSM → Return SPID only
  Key: Never leaves HSM boundary
```

#### Change 2: Stateless Session Architecture

**Original:** Sessions stored in Redis
**Revised:** Session data in JWT, only revocation list in Redis

```
BEFORE:
  Redis: 100M sessions × 2KB = 200GB
  
AFTER:
  JWT: Self-contained session
  Redis: 100M revocation entries × 16 bytes = 1.6GB
  Reduction: 99.2%
```

#### Change 3: Consent Receipt Signing

**Original:** Consent receipts in PostgreSQL, ABAC checks DB
**Revised:** Consent receipts signed, ABAC verifies signature

```
BEFORE:
  ABAC → PostgreSQL: Check consent
  ABAC → Permit/Deny
  
AFTER:
  ABAC → PostgreSQL: Fetch receipt
  ABAC → Verify Ed25519 signature
  ABAC → Permit/Deny (with signature proof)
  KonohaX → Verify ABAC signature
```

#### Change 4: HSM Scaling

**Original:** 6 HSMs (2 per cluster × 3 clusters)
**Revised:** 15 HSMs (5 per cluster × 3 clusters)

```
BEFORE:
  Capacity: 30,000 HMAC ops/sec
  Margin: 20% at peak
  
AFTER:
  Capacity: 75,000 HMAC ops/sec
  Margin: 200% at peak
  Supports: Batch operations, maintenance, growth
```

#### Change 5: Kafka Scaling

**Original:** 5 Kafka brokers
**Revised:** 10 Kafka brokers with tiered storage

```
BEFORE:
  Capacity: 100,000 writes/sec
  Replication: 300,000 writes/sec
  
AFTER:
  Capacity: 200,000 writes/sec
  Replication: 600,000 writes/sec
  Tiered: Hot (SSD 7d), Warm (HDD 90d), Cold (S3 7y)
```

---

## 4.2 Revised Implementation Timeline

### Phase 1: Foundation (Months 1-14)

| Month | Original | Revised | Change |
|-------|----------|---------|--------|
| 1-2 | CIV HSM setup | CIV HSM setup (15 HSMs) | +3 HSMs |
| 2-3 | K-IdP dev | K-IdP dev (stateless) | Architecture change |
| 3-4 | KonohaX | KonohaX + circuit breakers | +2 weeks |
| 4-5 | Token cache | Token cache (encrypted) | +1 week |
| 5-6 | FIDO2 | FIDO2 + recovery | +2 weeks |
| 6-7 | Wallet MVP | Wallet (hardened) | +2 weeks |
| 7-8 | Consent v1 | Consent (signed receipts) | +2 weeks |
| 8-9 | Audit log | Audit log + external anchors | +1 week |
| 9-10 | Dev portal | Dev portal | No change |
| 10-11 | Integration | Integration | No change |
| 11-12 | Security audit | Security audit + pen test | +2 weeks |
| 12-14 | - | Buffer for hardening | +8 weeks |

**Total Phase 1 Extension:** +8 weeks (from 12 to 14 months)

---

## 4.3 Revised Engineering Tasks

### New Security Tasks

```
SEC-006: Implement HSM-enclosed HMAC operations
  Effort: +2 weeks
  Owner: Crypto Team
  
SEC-007: Implement consent receipt signing
  Effort: +1 week
  Owner: Privacy Team
  
SEC-008: Formal verification of ZKP circuits
  Effort: +3 weeks
  Owner: External vendor (Trail of Bits)
  
SEC-009: Implement 3-of-5 key ceremony
  Effort: +2 weeks
  Owner: Security Team
  
SEC-010: Implement request replay protection
  Effort: +1 week
  Owner: Auth Team
  
SEC-011: Implement wallet remote wipe
  Effort: +1 week
  Owner: Mobile Team
  
SEC-012: Implement audit log external anchors
  Effort: +1 week
  Owner: Security Team
```

### New SRE Tasks

```
SRE-006: Scale HSM clusters to 15 HSMs
  Effort: +2 weeks
  Owner: Platform Team
  
SRE-007: Implement stateless JWT sessions
  Effort: +2 weeks
  Owner: Auth Team
  
SRE-008: Implement circuit breakers
  Effort: +1 week
  Owner: Integration Team
  
SRE-009: Scale Kafka to 10 brokers
  Effort: +1 week
  Owner: Platform Team
  
SRE-010: Deploy PgBouncer connection pooling
  Effort: +1 week
  Owner: Data Team
  
SRE-011: Implement priority edge sync
  Effort: +2 weeks
  Owner: Infrastructure Team
  
SRE-012: Deploy satellite backup at edge nodes
  Effort: +3 weeks
  Owner: Infrastructure Team
```

---

## 4.4 Validation Checklist

### Security Validation

- [ ] HSM operations verified: keys never leave HSM
- [ ] Penetration test: no critical vulnerabilities
- [ ] Bug bounty: 90 days active, no P1 issues
- [ ] DPoP: mandatory, strict verification
- [ ] Consent receipts: signed, tamper-evident
- [ ] ZKP circuits: formally verified
- [ ] Key ceremony: 3-of-5 tested
- [ ] Recovery flows: tested end-to-end

### SRE Validation

- [ ] Load test: 50M users, 25k auth/sec
- [ ] HSM capacity: 75k ops/sec sustained
- [ ] Failover test: all components
- [ ] Disaster recovery: RPO 0, RTO < 30min
- [ ] Chaos engineering: auto-recovery verified
- [ ] Edge sync: revocation < 60s propagation
- [ ] Circuit breakers: tested under load
- [ ] Database: connection pooling verified

---

*End of Iteration Loop — Proceeding to Final Orchestrator Output*


---

# PART 5: FINAL BLUEPRINT — EXECUTION-READY SPECIFICATION

## 5.1 Final Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    KONOHA NATIONAL DIGITAL IDENTITY SYSTEM (KNDIS)                       │
│                          Production Architecture v2.0 (Hardened)                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         SOVEREIGN SECURITY ZONE (Air-Gapped)                     │    │
│  │                                                                                  │    │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                         │    │
│  │   │  CIV-1      │◄──►│  CIV-2      │◄──►│  CIV-3      │   15 HSMs Total         │    │
│  │   │  (Primary)  │    │ (Secondary) │    │ (Tertiary)  │   FIPS 140-3 L3         │    │
│  │   │  5 HSMs     │    │  5 HSMs     │    │  5 HSMs     │   Raft Consensus        │    │
│  │   │ Konoha City │    │North Hills  │    │Coastal Zone │   2-of-3 Quorum         │    │
│  │   └─────────────┘    └─────────────┘    └─────────────┘                         │    │
│  │          ▲                  ▲                  ▲                                 │    │
│  │          └──────────────────┴──────────────────┘                                 │    │
│  │                     gRPC + mTLS (Internal Only)                                  │    │
│  │                                                                                  │    │
│  │   Security: 3-of-5 Key Ceremony │ Multi-Party Auth │ Tamper-Evident Audit       │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                           │                                              │
│                                           ▼ gRPC/mTLS                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         GOVERNMENT CLOUD ZONE (Kubernetes)                       │    │
│  │                                                                                  │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐               │    │
│  │  │   K-IdP          │  │  KonohaX         │  │   Consent        │               │    │
│  │  │   (OAuth 2.1/    │  │   Gateway        │  │   Engine         │               │    │
│  │  │    OIDC Core)    │  │   (API GW)       │  │   (ABAC)         │               │    │
│  │  │   3-30 pods      │  │   3-20 pods      │  │   3-15 pods      │               │    │
│  │  │   Stateless JWT  │  │   Circuit Breaker│  │   Signed Receipts│               │    │
│  │  │   DPoP Mandatory │  │   Connection Pool│  │   INSERT-Only DB │               │    │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘               │    │
│  │           ▲                   ▲                   ▲                              │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐               │    │
│  │  │   Token Cache    │  │   Kafka          │  │   Audit Log      │               │    │
│  │  │   (Redis 12x)    │  │   (10 Brokers)   │  │   (ImmuDB 3x)    │               │    │
│  │  │   Encrypted      │  │   Tiered Storage │  │   Merkle Tree    │               │    │
│  │  │   Revocation Only│  │   600k writes/s  │  │   External Anchors│              │    │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘               │    │
│  │                                                                                  │    │
│  │  Region 1: Konoha City (Primary)      Region 2: Northern (Hot Standby)         │    │
│  │  Auto-Failover: < 30 seconds                                                     │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                           │                                              │
│                                           ▼ mTLS + Request Signing                      │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         AGENCY NETWORK ZONE                                      │    │
│  │                                                                                  │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │    │
│  │  │  Health  │  │   Tax    │  │  Banking │  │  Elect.  │  │  Travel  │          │    │
│  │  │  Ministry│  │  Auth    │  │  Reg     │  │  Comm.   │  │  Immig.  │          │    │
│  │  │  Security│  │  Security│  │  Security│  │  Security│  │  Security│          │    │
│  │  │  Server  │  │  Server  │  │  Server  │  │  Server  │  │  Server  │          │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘          │    │
│  │                                                                                  │    │
│  │  Security: mTLS │ Request Signing │ Rate Limiting │ Schema Validation          │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                           │                                              │
│                                           ▼ HTTPS/WSS + DPoP                            │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         CITIZEN INTERFACE ZONE                                   │    │
│  │                                                                                  │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐               │    │
│  │  │   Hokage Wallet  │  │   Smart Card     │  │   Edge Nodes     │               │    │
│  │  │   (iOS/Android)  │  │   (NFC/Chip)     │  │   (50 Rural)     │               │    │
│  │  │   Secure Enclave │  │   JavaCard       │  │   Priority Sync  │               │    │
│  │  │   Biometric Lock │  │   Cloning Detect │  │   Satellite BKUP │               │    │
│  │  │   Remote Wipe    │  │   PIN Protected  │  │   Offline Verify │               │    │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘               │    │
│  │                                                                                  │    │
│  │  Offline Capability: Level 1-4 (Full rural coverage)                             │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         OBSERVABILITY STACK                                      │    │
│  │                                                                                  │    │
│  │  Prometheus │ Grafana │ Jaeger │ ELK │ PagerDuty │ 24/7 SOC                      │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5.2 Data & Cryptography Specifications

### Cryptographic Algorithm Suite

| Purpose | Algorithm | Standard | Quantum-Ready |
|---------|-----------|----------|---------------|
| Token Signing | Ed25519 | RFC 8032 | CRYSTALS-Dilithium |
| Key Exchange | X25519 | RFC 7748 | CRYSTALS-Kyber |
| Hashing | SHA-256 | FIPS 180-4 | SHA3-256 |
| HMAC | HMAC-SHA256 | FIPS 198-1 | HMAC-SHA3-256 |
| Symmetric | AES-256-GCM | FIPS 197 | AES-256-GCM |
| VCs | BBS+ | Draft | Lattice-based |
| ZKPs | Groth16 | Academic | STARKs |

### Key Hierarchy

```
Root of Trust:
└── Konoha Government Root CA (HSM-protected, 3-of-5 ceremony)
    ├── K-IdP Signing Key (rotates annually)
    ├── KonohaX Gateway Key (rotates annually)
    ├── Sector HMAC Keys (per sector, rotates annually)
    │   ├── Health Sector Key
    │   ├── Tax Sector Key
    │   ├── Banking Sector Key
    │   └── ... (7 sectors)
    ├── DID Registry Key (rotates bi-annually)
    └── Audit Log Signing Key (rotates annually)
```

### Token Specifications

| Token Type | Format | TTL | Binding | Storage |
|------------|--------|-----|---------|---------|
| Access Token | JWT (Ed25519) | 5 min | DPoP mandatory | Client memory only |
| Refresh Token | Opaque | 7 days | Device-bound | Client secure storage |
| ID Token | JWT (Ed25519) | 5 min | Session-bound | Not stored |
| One-Time Token | JWT (Ed25519) | 60 sec | Request-bound | Not stored |

---

## 5.3 API Contracts (Final)

### K-IdP OAuth 2.1 Endpoints

```yaml
# Authorization Endpoint
GET https://idp.konoha.gov/oauth/v1/authorize
  Query Parameters:
    client_id: uuid (required, registered)
    redirect_uri: https://... (required, pre-registered)
    response_type: code (required, only "code" supported)
    scope: "openid profile {sector}:{action}" (required)
    state: string (required, min 32 bytes, CSRF protection)
    code_challenge: base64url (required, PKCE S256)
    code_challenge_method: S256 (required)
    nonce: string (required for OIDC, min 16 bytes)
    prompt: none | login | consent | select_account
  
  Response (Success):
    HTTP 302
    Location: {redirect_uri}?code={auth_code}&state={state}
  
  Response (Error):
    HTTP 302
    Location: {redirect_uri}?error={error}&error_description={desc}&state={state}
  
  Rate Limit: 10 req/min per IP (429 with Retry-After)

# Token Endpoint
POST https://idp.konoha.gov/oauth/v1/token
  Headers:
    Content-Type: application/x-www-form-urlencoded
    DPoP: {dpop_proof_jwt} (required)
  
  Body (authorization_code grant):
    grant_type=authorization_code
    &code={auth_code}
    &redirect_uri={same_as_authorize}
    &code_verifier={pkce_verifier}
    &client_id={client_id}
  
  Body (refresh_token grant):
    grant_type=refresh_token
    &refresh_token={refresh_token}
    &client_id={client_id}
    &scope={optional_subset}
  
  Response (Success):
    HTTP 200
    {
      "access_token": "eyJ...",      // JWT, 5min TTL
      "token_type": "DPoP",           // DPoP-bound
      "expires_in": 300,
      "refresh_token": "opaque...",   // Rotates on use
      "id_token": "eyJ...",           // OIDC claims
      "scope": "openid profile health:read"
    }
  
  Response (Error):
    HTTP 400/401
    {
      "error": "invalid_grant | invalid_client | invalid_request",
      "error_description": "..."
    }
  
  Rate Limit: 30 req/min per client

# UserInfo Endpoint
GET https://idp.konoha.gov/oauth/v1/userinfo
  Headers:
    Authorization: DPoP {access_token}
    DPoP: {fresh_dpop_proof}
  
  Response:
    HTTP 200
    {
      "sub": "H-KQNM4VWPX2JRYTF8BGZDA3E7U",
      "name": "Naruto Uzumaki",
      "given_name": "Naruto",
      "family_name": "Uzumaki",
      "birthdate": "1990-07-15",
      "nationality": "Konoha",
      "sector_spid": "H-KQNM4VWPX2JRYTF8BGZDA3E7U"
    }

# Token Revocation
POST https://idp.konoha.gov/oauth/v1/revoke
  Headers:
    Authorization: Basic {client_credentials}
  Body:
    token={token_to_revoke}
    &token_type_hint=access_token|refresh_token
  Response: HTTP 200 (always, for privacy)
```

### KonohaX Gateway Endpoints

```yaml
# Service Discovery
GET https://gateway.konoha.gov/konohax/v1/services
  Headers:
    Authorization: Bearer {access_token}
    X-KonohaX-Signature: {ed25519_signature}
    X-KonohaX-Timestamp: {unix_timestamp}
    X-KonohaX-Request-ID: {uuid}
  
  Response:
    HTTP 200
    {
      "services": [
        {
          "service_id": "konoha.health.citizen-records.v2",
          "owner_agency": "ministry-of-health",
          "base_url": "https://api.health.gov.kn/v2",
          "auth_scopes": ["health:read", "health:write"],
          "requires_consent": true,
          "data_classification": "SENSITIVE"
        }
      ]
    }

# Cross-Agency Request
POST https://gateway.konoha.gov/konohax/v1/request
  Headers:
    Authorization: DPoP {access_token}
    X-KonohaX-Signature: {ed25519_signature}
    X-KonohaX-Timestamp: {unix_timestamp}
    X-KonohaX-Request-ID: {uuid}
  
  Body:
    {
      "target_service": "konoha.health.citizen-records.v2",
      "operation": "read_medical_history",
      "parameters": {
        "patient_spid": "H-KQNM4VWPX2JRYTF8BGZDA3E7U",
        "date_range": {"from": "2024-01-01", "to": "2024-12-31"}
      },
      "purpose": "emergency_treatment",
      "citizen_spid": "H-KQNM4VWPX2JRYTF8BGZDA3E7U",
      "consent_receipt_id": "c8f4e2a1-..."
    }
  
  Response:
    HTTP 200
    {
      "request_id": "req-uuid",
      "status": "success",
      "data": { ... },
      "audit_log_id": "audit-uuid"
    }
  
  Circuit Breaker:
    - Open after 50% error rate in 60s window
    - Half-open after 30s cooldown
    - Closed after 5 consecutive successes
```

### Consent Engine Endpoints

```yaml
# Grant Consent
POST https://consent.konoha.gov/v1/grant
  Headers:
    Authorization: DPoP {access_token}
  
  Body:
    {
      "granted_to": "did:konoha:org:nairobi-general-hospital",
      "attributes": ["health:medical_history", "identity:name"],
      "purpose": "emergency_treatment",
      "valid_from": "2026-04-02T10:00:00Z",
      "valid_until": "2026-04-02T23:59:59Z",
      "max_access_count": 3,
      "storage_allowed": false,
      "downstream_sharing_allowed": false
    }
  
  Response:
    HTTP 201
    {
      "receipt_id": "c8f4e2a1-83c7-4d2f-b591-0e6f3a7c9d18",
      "receipt_signature": "Ed25519:...",
      "receipt_timestamp": "2026-04-02T10:23:44Z"
    }

# Check Consent (Internal)
POST https://consent.konoha.gov/v1/check
  Headers:
    X-Internal-Auth: {service_token}
  
  Body:
    {
      "citizen_spid": "H-KQNM4VWPX2JRYTF8BGZDA3E7U",
      "requester_did": "did:konoha:org:nairobi-general-hospital",
      "attribute": "health:medical_history",
      "purpose": "emergency_treatment"
    }
  
  Response:
    HTTP 200
    {
      "granted": true,
      "receipt_id": "c8f4e2a1-...",
      "remaining_accesses": 2,
      "receipt_signature_valid": true
    }

# Revoke Consent
POST https://consent.konoha.gov/v1/revoke/{receipt_id}
  Headers:
    Authorization: DPoP {access_token}
  
  Response: HTTP 204
  Effect: Immediate (< 1 second propagation)

# Activity Log
GET https://consent.konoha.gov/v1/activity
  Headers:
    Authorization: DPoP {access_token}
  
  Query:
    from=2026-03-01T00:00:00Z
    &to=2026-04-02T23:59:59Z
    &limit=100
  
  Response:
    HTTP 200
    {
      "activities": [
        {
          "timestamp": "2026-04-02T10:23:44Z",
          "actor": "Nairobi General Hospital",
          "action": "data.read",
          "resource": "health:medical_history",
          "purpose": "emergency_treatment",
          "outcome": "permitted"
        }
      ]
    }
```

---

## 5.4 Infrastructure Design

### Kubernetes Deployment

```yaml
# K-IdP Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: k-idp
  namespace: identity
spec:
  replicas: 3
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: k-idp
        image: konoha/k-idp:v2.0.0
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2000m
            memory: 2Gi
        ports:
        - containerPort: 8080
        env:
        - name: HSM_HOST
          value: "civ-hsm-cluster.internal"
        - name: REDIS_URL
          value: "redis://token-cache:6379"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: k-idp
            topologyKey: kubernetes.io/hostname

---
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: k-idp-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: k-idp
  minReplicas: 3
  maxReplicas: 30
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: authentication_latency_p99
      target:
        type: AverageValue
        averageValue: 500m
```

### Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k-idp-network-policy
spec:
  podSelector:
    matchLabels:
      app: k-idp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: token-cache
    ports:
    - protocol: TCP
      port: 6379
  - to:
    - podSelector:
        matchLabels:
          app: civ-hsm
    ports:
    - protocol: TCP
      port: 1792
```

### HSM Configuration

```
Thales Luna 7 HSM Configuration:

Partition Layout:
  Partition 1: K-IdP Signing Keys
  Partition 2: KonohaX Gateway Keys
  Partition 3-9: Sector HMAC Keys (7 sectors)
  Partition 10: DID Registry Keys
  Partition 11: Audit Log Keys
  Partition 12: Backup/Recovery

Access Control:
  - HSM Admin: 3-of-5 key ceremony required
  - Partition Admin: 2-of-3 approvers
  - Crypto User: Service accounts only
  - Crypto Officer: Emergency access only

High Availability:
  - Synchronous replication within cluster
  - Asynchronous replication across regions
  - Automatic failover: < 5 seconds
  - Manual failover: < 30 seconds
```

---

## 5.5 Implementation Roadmap

### Phase 1: Foundation (Months 1-14)

**Month 1-2: Infrastructure Setup**
- [ ] Procure 15 HSMs (Thales Luna 7)
- [ ] Deploy Kubernetes clusters (2 regions)
- [ ] Set up Redis cluster (12 nodes)
- [ ] Deploy Kafka cluster (10 brokers)
- [ ] Deploy ImmuDB audit log
- [ ] Configure mTLS mesh

**Month 3-4: Core Services**
- [ ] Implement CIV gRPC service (HSM-enclosed HMAC)
- [ ] Build K-IdP OAuth 2.1 server (stateless JWT)
- [ ] Implement FIDO2/WebAuthn server
- [ ] Build KonohaX Gateway (circuit breakers)

**Month 5-6: Security Layer**
- [ ] Implement DPoP token binding
- [ ] Build Consent Engine (signed receipts)
- [ ] Implement ABAC policies
- [ ] Deploy PgBouncer connection pooling

**Month 7-8: Mobile & Client**
- [ ] Hokage Wallet iOS (secure enclave)
- [ ] Hokage Wallet Android (keystore)
- [ ] Implement offline credential presentation
- [ ] Remote wipe functionality

**Month 9-10: Integration**
- [ ] Civil Registry integration
- [ ] Tax Authority integration
- [ ] Health Ministry integration
- [ ] Developer portal + sandbox

**Month 11-12: Testing & Security**
- [ ] Load testing (50M users)
- [ ] Chaos engineering
- [ ] Penetration testing
- [ ] Bug bounty launch

**Month 13-14: Buffer & Hardening**
- [ ] Security hardening (8 weeks of findings)
- [ ] Performance optimization
- [ ] Disaster recovery drills
- [ ] Production readiness review

### Phase 2: Expansion (Months 15-30)

**Quarter 1-2: Full Government**
- [ ] All 7 sector SPIDs live
- [ ] All agencies on KonohaX
- [ ] ZKP age verification (Groth16)
- [ ] Full VC catalog (12 types)

**Quarter 3-4: Advanced Features**
- [ ] Pre-filled tax returns
- [ ] Delegation/guardian flows
- [ ] Recovery code system
- [ ] Trusted contacts

### Phase 3: Private Sector + International (Months 31-60)

**Quarter 5-6: Private Sector**
- [ ] Banking integration (licensed)
- [ ] Telecom integration
- [ ] Developer Tier 2+3 launch

**Quarter 7-8: International**
- [ ] EU eIDAS 2.0 compatibility
- [ ] Rural edge nodes (50 locations)
- [ ] Blind-signature voting system

**Quarter 9-12: Future-Proofing**
- [ ] Post-quantum crypto migration
- [ ] Advanced ZKP use cases
- [ ] AI-assisted fraud detection

---

## 5.6 Engineering Tasks (Final List — 42 Tasks)

### Infrastructure (7 tasks)

| ID | Task | Owner | Effort | Dependencies |
|----|------|-------|--------|--------------|
| INF-001 | HSM procurement & setup (15 units) | Platform | 4w | - |
| INF-002 | Kubernetes deployment (2 regions) | Platform | 2w | INF-001 |
| INF-003 | Redis cluster (12 nodes, encrypted) | Data | 1w | INF-002 |
| INF-004 | Kafka cluster (10 brokers, tiered) | Platform | 2w | INF-002 |
| INF-005 | ImmuDB audit log (Merkle tree) | Security | 2w | INF-002 |
| INF-006 | mTLS mesh (Istio) | Platform | 2w | INF-002 |
| INF-007 | Edge nodes (50 rural + satellite) | Infra | 8w | INF-002 |

### Core Services (7 tasks)

| ID | Task | Owner | Effort | Dependencies |
|----|------|-------|--------|--------------|
| SRV-001 | CIV gRPC (HSM-enclosed HMAC) | Identity | 6w | INF-001 |
| SRV-002 | K-IdP OAuth 2.1 (stateless JWT) | Auth | 8w | INF-002, SRV-001 |
| SRV-003 | FIDO2/WebAuthn server | Auth | 4w | SRV-002 |
| SRV-004 | KonohaX Gateway (circuit breakers) | Integration | 6w | INF-002, INF-006 |
| SRV-005 | Consent Engine (signed receipts) | Privacy | 6w | INF-005 |
| SRV-006 | Service Registry | Integration | 3w | SRV-004 |
| SRV-007 | Token rotation service | Auth | 2w | SRV-002 |

### Cryptography (6 tasks)

| ID | Task | Owner | Effort | Dependencies |
|----|------|-------|--------|--------------|
| CRY-001 | Ed25519 signing (HSM-resident) | Crypto | 3w | INF-001 |
| CRY-002 | BBS+ signature scheme | Crypto | 4w | CRY-001 |
| CRY-003 | ZKP circuits (Groth16, formal verify) | Crypto | 6w | CRY-002 |
| CRY-004 | SPID derivation (HSM-enclosed) | Crypto | 2w | SRV-001 |
| CRY-005 | DPoP token binding (mandatory) | Auth | 2w | SRV-002 |
| CRY-006 | 3-of-5 key ceremony procedures | Security | 2w | INF-001 |

### Mobile/Client (6 tasks)

| ID | Task | Owner | Effort | Dependencies |
|----|------|-------|--------|--------------|
| MOB-001 | Hokage Wallet iOS | Mobile | 10w | SRV-002, CRY-002 |
| MOB-002 | Hokage Wallet Android | Mobile | 10w | SRV-002, CRY-002 |
| MOB-003 | Secure enclave key storage | Mobile | 3w | MOB-001, MOB-002 |
| MOB-004 | Offline credential presentation | Mobile | 4w | MOB-003, CRY-002 |
| MOB-005 | Remote wipe functionality | Mobile | 2w | MOB-003 |
| MOB-006 | Smart card integration | Hardware | 6w | CRY-001 |

### Integration (5 tasks)

| ID | Task | Owner | Effort | Dependencies |
|----|------|-------|--------|--------------|
| INT-001 | Civil Registry integration | Integration | 4w | SRV-004, SRV-005 |
| INT-002 | Tax Authority integration | Integration | 4w | SRV-004, SRV-005 |
| INT-003 | Health Ministry integration | Integration | 4w | SRV-004, SRV-005 |
| INT-004 | Developer portal + sandbox | DevEx | 6w | SRV-002, SRV-004 |
| INT-005 | SDKs (JS, Python, Go, Java, Swift) | DevEx | 8w | INT-004 |

### Security (7 tasks)

| ID | Task | Owner | Effort | Dependencies |
|----|------|-------|--------|--------------|
| SEC-001 | Threat modeling (STRIDE) | Security | 2w | SRV-001, SRV-002, SRV-004 |
| SEC-002 | Penetration testing | External | 4w | Phase 1 complete |
| SEC-003 | Bug bounty program | Security | 2w | Phase 1 complete |
| SEC-004 | Security monitoring (SIEM) | Security | 3w | INF-002 |
| SEC-005 | Key ceremony procedures | Security | 2w | INF-001 |
| SEC-006 | Formal ZKP verification | External | 3w | CRY-003 |
| SEC-007 | Request replay protection | Auth | 1w | SRV-002 |

### SRE (4 tasks)

| ID | Task | Owner | Effort | Dependencies |
|----|------|-------|--------|--------------|
| SRE-001 | Load testing (50M users) | SRE | 3w | Phase 1 complete |
| SRE-002 | Chaos engineering | SRE | 2w | INF-002 |
| SRE-003 | Disaster recovery drill | SRE | 1w | INF-001 |
| SRE-004 | PgBouncer deployment | Data | 1w | INF-002 |

---

## 5.7 Security Model (Hardened)

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         KNDIS SECURITY MODEL                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  LAYER 1: PERIMETER                                                      │
│  ├── DDoS Protection (Cloudflare/AWS Shield)                            │
│  │   └── 10 Tbps mitigation capacity                                     │
│  ├── Web Application Firewall                                           │
│  │   └── Custom rules for KNDIS API patterns                            │
│  ├── Rate Limiting                                                      │
│  │   ├── Per IP: 10 req/min (auth), 1000 req/min (API)                 │
│  │   ├── Per client: 30 req/min (token), 1000 req/min (KonohaX)        │
│  │   └── Per citizen: 100 req/min (all services)                       │
│  └── Geo-blocking                                                       │
│      └── High-risk countries blocked at edge                            │
│                                                                          │
│  LAYER 2: TRANSPORT                                                      │
│  ├── TLS 1.3 Mandatory (no downgrade)                                   │
│  │   └── Certificate pinning in mobile apps                             │
│  ├── Mutual TLS (all inter-service)                                     │
│  │   └── Konoha Government Root CA only                                 │
│  └── HSTS with preload                                                  │
│                                                                          │
│  LAYER 3: AUTHENTICATION                                                 │
│  ├── FIDO2/WebAuthn (Passkeys) - Primary                                │
│  │   └── Phishing-resistant, hardware-bound                             │
│  ├── TOTP Fallback (RFC 6238)                                          │
│  │   └── Offline-capable, no vendor lock-in                             │
│  ├── Risk-Adaptive MFA                                                  │
│  │   └── Low/Medium/High risk scoring                                   │
│  └── Device Attestation                                                 │
│      └── No jailbroken/rooted devices                                   │
│                                                                          │
│  LAYER 4: AUTHORIZATION                                                  │
│  ├── DPoP Token Binding (Mandatory)                                     │
│  │   └── Tokens bound to device key, theft = useless                    │
│  ├── ABAC with Fine-Grained Policies                                    │
│  │   └── Subject + Resource + Action + Environment                      │
│  ├── Signed Consent Receipts                                            │
│  │   └── Tamper-evident, cryptographically verified                     │
│  └── Principle of Least Privilege                                       │
│      └── Just-in-time access for admins                                 │
│                                                                          │
│  LAYER 5: DATA PROTECTION                                                │
│  ├── Tokenization (NIN never exposed)                                   │
│  │   └── Sector Pseudonymous IDs (SPIDs)                                │
│  ├── Encryption at Rest (AES-256-GCM)                                   │
│  │   └── HSM-wrapped data encryption keys                               │
│  ├── Encryption in Transit (TLS 1.3)                                    │
│  └── HSM-Resident Keys Only                                             │
│      └── Keys never leave HSM boundary                                  │
│                                                                          │
│  LAYER 6: APPLICATION SECURITY                                           │
│  ├── Input Validation                                                   │
│  │   └── JSON Schema validation on all APIs                             │
│  ├── SQL Injection Prevention                                           │
│  │   └── Prepared statements only, no string concatenation              │
│  ├── Request Replay Protection                                          │
│  │   └── 60s timestamp drift, request ID cache                          │
│  └── Circuit Breakers                                                   │
│      └── Fail fast, prevent cascade failures                            │
│                                                                          │
│  LAYER 7: AUDIT & MONITORING                                             │
│  ├── Immutable Audit Log (Merkle-tree)                                  │
│  │   └── Tamper-evident, publicly verifiable                            │
│  ├── External Anchors                                                   │
│  │   └── Daily Merkle root in gazette + blockchain                      │
│  ├── Real-Time SIEM Alerting                                            │
│  │   └── 24/7 Security Operations Center                                │
│  └── Anomaly Detection ML                                               │
│      └── Behavioral analysis for fraud detection                        │
│                                                                          │
│  LAYER 8: GOVERNANCE                                                     │
│  ├── Multi-Party Authorization                                          │
│  │   └── 3-of-5 key ceremony for sensitive ops                          │
│  ├── Regular Penetration Testing                                        │
│  │   └── Quarterly external assessments                                 │
│  ├── Bug Bounty Program                                                 │
│  │   └── Public program on HackerOne                                    │
│  └── External Security Audits                                           │
│      └── Annual SOC 2 Type II certification                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Threat Mitigation Matrix

| Threat | Likelihood | Impact | Mitigation | Residual Risk |
|--------|------------|--------|------------|---------------|
| Phishing | High | Medium | FIDO2 (no passwords) | Low |
| Credential Theft | Medium | High | DPoP binding | Low |
| Session Hijacking | Medium | High | Short TTL, revocation | Low |
| Mass Data Breach | Low | Critical | SPID unlinkability | Low |
| Insider Threat | Low | Critical | 3-of-5 key ceremony | Low |
| DDoS Attack | High | Medium | Multi-layer defense | Low |
| Supply Chain | Low | High | Reproducible builds, SBOM | Medium |
| Quantum Computing | Low | Medium | Crypto agility | Low |

---

## 5.8 Scaling Strategy

### Horizontal Scaling

```yaml
Auto-Scaling Configuration:

K-IdP:
  Min Replicas: 3 per region
  Max Replicas: 30 per region
  Scale Up Trigger:
    - CPU > 70% for 2 minutes
    - Latency p99 > 500ms for 2 minutes
    - Request queue > 100
  Scale Down Trigger:
    - CPU < 30% for 10 minutes
    - Request queue < 10 for 10 minutes

KonohaX Gateway:
  Min Replicas: 3 per region
  Max Replicas: 20 per region
  Scale Up Trigger:
    - Request queue > 100
    - Connection pool > 80%
  Scale Down Trigger:
    - Request queue < 10 for 10 minutes

Consent Engine:
  Min Replicas: 3 per region
  Max Replicas: 15 per region
  Scale Up Trigger:
    - DB connection pool > 80%
    - Consent check latency > 50ms
  Scale Down Trigger:
    - Connection pool < 30% for 10 minutes
```

### Database Sharding

```
Consent Database Sharding Strategy:

Shard Key: citizen_spid hash mod 16
Number of Shards: 16
Replication: Primary + 2 replicas per shard

Shard Assignment:
  Shard 0: SPIDs starting with 0-1
  Shard 1: SPIDs starting with 2-3
  ...
  Shard 15: SPIDs starting with E-F

Cross-Shard Queries:
  - Aggregation service for cross-shard queries
  - Async processing for reports
  - Cached results for common queries

Rebalancing:
  - Online rebalancing (no downtime)
  - Triggered at 70% capacity
  - Gradual migration with verification
```

### Caching Strategy

```
Multi-Layer Caching:

L1: In-Memory (Application)
  - Token validation cache
  - Consent check results
  - TTL: 1 minute
  - Size: 100MB per pod

L2: Redis Cluster
  - Active sessions (revocation list)
  - Public keys
  - Service registry
  - TTL: 5-60 minutes
  - Size: 64GB per node

L3: Edge Cache (CDN)
  - Static assets
  - Public schemas
  - Revocation lists
  - TTL: 6 hours
  - Global distribution

L4: Browser/Client Cache
  - Wallet assets
  - Cached credentials
  - Offline verification keys
  - TTL: 24 hours
```

---

## 5.9 Failure Modes & Mitigations

### Failure Mode Matrix (Final)

| Component | Failure Mode | Impact | Detection | Automatic Recovery | RTO |
|-----------|--------------|--------|-----------|-------------------|-----|
| CIV HSM | Single HSM failure | None (redundancy) | Health check | Automatic failover | 5s |
| CIV Cluster | Complete outage | No new auth | Multi-region | Emergency unlock | 30min |
| K-IdP | Pod failure | 1/30 capacity | K8s health | Auto-restart | 10s |
| K-IdP | Regional outage | Failover region | External probe | DNS failover | 30s |
| Redis | Node failure | Cache miss increase | Cluster health | Replica promotion | 5s |
| Redis | Full outage | Session validation fails | Timeout | Cold start from DB | 5min |
| Kafka | Broker failure | Event delay | Metrics | Leader election | 3s |
| PostgreSQL | Primary failure | Write outage | Replication lag | Replica promotion | 60s |
| KonohaX | Gateway failure | Cross-agency blocked | Health check | Auto-scaling | 30s |
| Agency API | Slow/down | Service degradation | Timeout | Circuit breaker | 5s |

### Disaster Recovery Procedures

#### Procedure 1: CIV Complete Outage

```
Trigger: All 3 CIV clusters unreachable

Response:
1. Page on-call SRE (automated)
2. Activate emergency authentication mode
3. Use cached SPID mappings (read-only)
4. Allow authentication with degraded features
5. No new citizen enrollment
6. No SPID rotation
7. Full restoration target: 30 minutes

Emergency Contacts:
- Primary: SRE Lead (+xxx-xxx-xxxx)
- Secondary: Security Lead (+xxx-xxx-xxxx)
- Escalation: CTO (+xxx-xxx-xxxx)
```

#### Procedure 2: Regional Failure

```
Trigger: Primary region health checks fail

Response (Automated):
1. DNS failover to secondary region (30 seconds)
2. Traffic routed to standby region
3. Service continues from secondary
4. Investigation begins
5. Primary region restoration
6. Gradual traffic shift back

RPO: 0 (synchronous replication)
RTO: 30 seconds
```

#### Procedure 3: Database Corruption

```
Trigger: Checksum mismatch on primary DB

Response:
1. Take corrupted DB offline (automated)
2. Promote replica to primary (automated)
3. Service restored (10 seconds)
4. Root cause analysis
5. Restore corrupted DB from backup
6. Verify data integrity
7. Return to normal operation

RPO: < 1 minute (synchronous replication)
RTO: 10 seconds
```

---

## 5.10 End-to-End Use Case: Bank Account Opening

### Scenario Flow

```
CITIZEN: Naruto Uzumaki
ACTION: Open bank account at KCB Bank
TIME TARGET: < 2 minutes

┌─────────────────────────────────────────────────────────────────────────┐
│                         BANK ACCOUNT OPENING FLOW                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  T+0:00  Naruto opens KCB Bank app, taps "Open Account"                 │
│          └── Bank app generates PKCE challenge                          │
│              code_verifier = random(32 bytes)                           │
│              code_challenge = BASE64URL(SHA256(code_verifier))          │
│                                                                          │
│  T+0:05  Bank app redirects to K-IdP                                    │
│          GET https://idp.konoha.gov/oauth/v1/authorize                  │
│            ?client_id=kcb-bank-uuid                                     │
│            &redirect_uri=https://kcb.com/callback                       │
│            &scope=openid profile konoha:bank:kyc                        │
│            &response_type=code                                          │
│            &code_challenge=xxx                                          │
│            &code_challenge_method=S256                                  │
│            &state=random-state                                          │
│            &nonce=random-nonce                                          │
│                                                                          │
│  T+0:08  K-IdP sends auth request to Hokage Wallet                      │
│          └── Push notification to Naruto's phone                        │
│                                                                          │
│  T+0:10  Wallet shows consent request                                   │
│          "KCB Bank requests:                                            │
│           - Name                                                        │
│           - Nationality                                                 │
│           - Date of Birth                                               │
│           - Income Range (not exact figure)                             │
│           Purpose: Bank account KYC verification"                       │
│                                                                          │
│  T+0:20  Naruto reviews and taps APPROVE                                │
│          └── Can selectively disclose (BBS+ selective disclosure)       │
│                                                                          │
│  T+0:22  Wallet performs FIDO2 biometric unlock                         │
│          └── Device-local biometric verification                        │
│                                                                          │
│  T+0:24  Wallet generates:                                              │
│          - Scoped SST (sector=banking)                                  │
│          - BBS+ derived VC presentation                                 │
│          - DPoP proof                                                   │
│                                                                          │
│  T+0:28  Token + VC sent to K-IdP → forwarded to KCB Bank               │
│          └── Authorization code exchange                                │
│              POST /oauth/v1/token                                       │
│              Response: access_token, id_token, refresh_token            │
│                                                                          │
│  T+0:32  KCB Bank verifies:                                             │
│          - VC signature valid (BBS+ verify)                             │
│          - Income range sufficient for account type                     │
│          - DPoP binding valid                                           │
│          └── All verification local (no central call)                   │
│                                                                          │
│  T+0:45  KCB Bank creates account                                       │
│          └── Pre-fills KYC from VC (no forms)                           │
│                                                                          │
│  T+1:50  Account open. Virtual card issued.                             │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│  Total time: ~110 seconds                                               │
│  Forms filled: 0                                                        │
│  Documents scanned: 0                                                   │
│  Citizen data exposed: Minimal (only what's needed)                     │
│  Privacy: Income range, not exact figure                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  KCB    │────►│ K-IdP   │────►│  CIV    │────►│  HSM    │     │         │
│  Bank   │◄────│         │◄────│         │◄────│ Cluster │     │         │
└────┬────┘     └────┬────┘     └─────────┘     └─────────┘     │         │
     │               │                                           │         │
     │               │         ┌─────────┐                       │         │
     │               └────────►│ Hokage  │◄──────────────────────┘         │
     │                  VC     │ Wallet  │    Biometric unlock             │
     │                  Token  │         │    (device-local)               │
     │                         └─────────┘                                 │
     │                                                                     │
     │         ┌─────────┐     ┌─────────┐                                 │
     └────────►│ KonohaX │────►│  Tax    │                                 │
       Verify  │ Gateway │     │  Auth   │                                 │
       Income  │         │     │         │                                 │
               └─────────┘     └─────────┘                                 │
                                                                            │
┌─────────────────────────────────────────────────────────────────────────┐│
│ AUDIT TRAIL (Immutable)                                                  ││
│ - Citizen: Naruto Uzumaki (B-RTYU7CXMN4QPWJK8ALVFB5ZGH)                 ││
│ - Action: consent.granted                                               ││
│ - Recipient: KCB Bank                                                   ││
│ - Attributes: name, nationality, dob, income_range                      ││
│ - Purpose: bank_account_kyc                                             ││
│ - Timestamp: 2026-04-02T10:23:44Z                                       ││
│ - Receipt: Ed25519:xxx... (signed)                                      ││
└─────────────────────────────────────────────────────────────────────────┘│
```

---

## 5.11 Production Readiness Checklist

### Security

- [ ] All 7 critical security findings addressed
- [ ] Penetration test passed (no critical vulnerabilities)
- [ ] Bug bounty program active (90 days)
- [ ] DPoP mandatory and verified
- [ ] Consent receipts signed and verified
- [ ] ZKP circuits formally verified
- [ ] 3-of-5 key ceremony tested
- [ ] Recovery flows tested
- [ ] SOC 2 Type II certification initiated

### Scalability

- [ ] Load test: 50M users, 25k auth/sec passed
- [ ] HSM capacity: 75k ops/sec verified
- [ ] Failover test: all components passed
- [ ] Disaster recovery: RPO 0, RTO < 30min verified
- [ ] Chaos engineering: auto-recovery verified
- [ ] Edge sync: revocation < 60s propagation verified
- [ ] Circuit breakers: tested under load
- [ ] Database connection pooling verified

### Reliability

- [ ] 99.99% uptime target validated
- [ ] All SLOs defined and monitored
- [ ] Alerting configured (PagerDuty)
- [ ] Runbooks documented
- [ ] On-call rotation established
- [ ] Incident response process defined
- [ ] Backup/restore tested
- [ ] DR drills completed

### Compliance

- [ ] Data protection impact assessment
- [ ] Privacy policy published
- [ ] Terms of service published
- [ ] Cookie consent implemented
- [ ] Accessibility audit passed (WCAG 2.1 AA)
- [ ] Internationalization ready
- [ ] Audit log transparency portal live

---

## 5.12 Cost Estimates

### Infrastructure Costs (Annual)

| Component | Year 1 (10M) | Year 3 (35M) | Year 5 (50M) |
|-----------|--------------|--------------|--------------|
| HSMs (15 units) | $1,500,000 | $1,500,000 | $1,500,000 |
| Kubernetes (2 regions) | $200,000 | $400,000 | $600,000 |
| Redis (12 nodes) | $100,000 | $200,000 | $300,000 |
| Kafka (10 brokers) | $150,000 | $300,000 | $400,000 |
| PostgreSQL (sharded) | $100,000 | $300,000 | $500,000 |
| ImmuDB (audit) | $50,000 | $100,000 | $150,000 |
| Edge Nodes (50) | $200,000 | $200,000 | $200,000 |
| CDN/Edge Cache | $50,000 | $150,000 | $250,000 |
| Monitoring/Observability | $100,000 | $200,000 | $300,000 |
| Security Tools (SIEM, etc.) | $200,000 | $300,000 | $400,000 |
| **Total Infrastructure** | **$2,650,000** | **$3,850,000** | **$4,600,000** |

### Personnel Costs (Annual)

| Team | Headcount | Avg Salary | Total |
|------|-----------|------------|-------|
| Engineering | 40 | $150,000 | $6,000,000 |
| Security | 10 | $180,000 | $1,800,000 |
| SRE | 8 | $160,000 | $1,280,000 |
| Product/Design | 6 | $140,000 | $840,000 |
| Management | 4 | $200,000 | $800,000 |
| **Total Personnel** | **68** | | **$10,720,000** |

### Total Cost of Ownership

| Year | Infrastructure | Personnel | Other | Total |
|------|----------------|-----------|-------|-------|
| 1 | $2,650,000 | $10,720,000 | $500,000 | $13,870,000 |
| 3 | $3,850,000 | $12,000,000 | $750,000 | $16,600,000 |
| 5 | $4,600,000 | $14,000,000 | $1,000,000 | $19,600,000 |

**Per-Citizen Cost:**
- Year 1: $1.39
- Year 3: $0.47
- Year 5: $0.39

---

# CONCLUSION

## Final Orchestrator Decision

**STATUS: ✅ APPROVED FOR IMPLEMENTATION**

The Konoha National Digital Identity System (KNDIS) has undergone a comprehensive multi-agent architecture review:

1. **CTO Draft** established the technical foundation with 35+ engineering tasks
2. **Security Review** identified 14 critical findings and provided hardened mitigations
3. **SRE Review** stress-tested for 50M citizens and identified scaling requirements
4. **Iteration Loop** integrated all feedback into a revised design
5. **Final Blueprint** synthesizes everything into an execution-ready specification

### Key Decisions

| Decision | Rationale |
|----------|-----------|
| HSM-enclosed HMAC | Keys never leave HSM boundary, prevents extraction |
| Stateless JWT sessions | 99.2% reduction in session storage, better scaling |
| Mandatory DPoP | Token theft becomes useless attack |
| Signed consent receipts | Tamper-evident, cryptographically verified |
| 15 HSMs (not 6) | 200% headroom for peak + growth |
| 10 Kafka brokers | 1000% headroom for event volume |
| 14-month Phase 1 | Security hardening is non-negotiable |

### Success Criteria

The system will be considered production-ready when:

1. All 42 engineering tasks complete
2. Security validation checklist passed
3. SRE validation checklist passed
4. 50M user load test passed
5. Disaster recovery drill passed
6. SOC 2 Type II certification obtained
7. Bug bounty program active (90 days, no P1 issues)

### Next Steps

1. **Week 1:** Kickoff Phase 1, procure HSMs
2. **Month 1-2:** Infrastructure setup
3. **Month 3-6:** Core services development
4. **Month 7-10:** Integration and testing
5. **Month 11-14:** Security hardening and production readiness
6. **Month 15:** Production launch (10M citizens)

---

**Document Version:** 2.0  
**Last Updated:** 2026-04-02  
**Review Cycle:** Quarterly  
**Next Review:** 2026-07-02  

*This blueprint is a living document. Updates will be made as the system evolves.*

---

*KNDIS — Built for Konoha. Designed for Humanity.*
