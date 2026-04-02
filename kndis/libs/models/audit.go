package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	EventTypeAuthSuccess       AuditEventType = "auth.success"
	EventTypeAuthFailure       AuditEventType = "auth.failure"
	EventTypeTokenIssued       AuditEventType = "token.issued"
	EventTypeTokenRefreshed    AuditEventType = "token.refreshed"
	EventTypeTokenRevoked      AuditEventType = "token.revoked"
	EventTypeConsentGranted    AuditEventType = "consent.granted"
	EventTypeConsentRevoked    AuditEventType = "consent.revoked"
	EventTypeConsentChecked    AuditEventType = "consent.checked"
	EventTypeDataAccess        AuditEventType = "data.access"
	EventTypeDataWrite         AuditEventType = "data.write"
	EventTypeSPIDGenerated     AuditEventType = "spid.generated"
	EventTypeSPIDRenewed       AuditEventType = "spid.renewed"
	EventTypeCredentialIssued  AuditEventType = "credential.issued"
	EventTypeCredentialVerified AuditEventType = "credential.verified"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	EventID          string         `json:"event_id" gorm:"primaryKey"`
	Timestamp        time.Time      `json:"timestamp" gorm:"index"`
	EventType        AuditEventType `json:"event_type"`
	ActorType        string         `json:"actor_type"` // citizen, agency, system, admin
	ActorID          string         `json:"actor_id"`
	ActorSPID        string         `json:"actor_spid,omitempty"`
	Action           string         `json:"action"`
	ResourceType     string         `json:"resource_type"`
	ResourceID       string         `json:"resource_id"`
	CitizenSPID      string         `json:"citizen_spid,omitempty" gorm:"index"`
	Sector           string         `json:"sector,omitempty"`
	Purpose          string         `json:"purpose,omitempty"`
	Outcome          string         `json:"outcome"` // permitted, denied, error
	ConsentReceiptID string         `json:"consent_receipt_id,omitempty"`
	RequestID        string         `json:"request_id,omitempty"`
	ClientID         string         `json:"client_id,omitempty"`
	IPAddress        string         `json:"ip_address,omitempty"`
	UserAgent        string         `json:"user_agent,omitempty"`
	ErrorMessage     string         `json:"error_message,omitempty"`
	EvidenceHash     string         `json:"evidence_hash,omitempty"`
	PreviousHash     string         `json:"previous_hash"`
	MerkleRoot       string         `json:"merkle_root"`
	CreatedAt        time.Time      `json:"created_at"`
}

// NewAuditEvent creates a new audit event
func NewAuditEvent(eventType AuditEventType, actorType, actorID, action, resourceType, resourceID, outcome string) *AuditEvent {
	return &AuditEvent{
		EventID:      uuid.New().String(),
		Timestamp:    time.Now(),
		EventType:    eventType,
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Outcome:      outcome,
		CreatedAt:    time.Now(),
	}
}

// ComputeHash computes the hash of the audit event for Merkle tree
func (ae *AuditEvent) ComputeHash() string {
	data := ae.EventID + ae.Timestamp.String() + string(ae.EventType) +
		ae.ActorID + ae.Action + ae.ResourceID + ae.Outcome + ae.PreviousHash
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// AuditQuery represents query parameters for audit logs
type AuditQuery struct {
	CitizenSPID string         `form:"citizen_spid"`
	EventType   AuditEventType `form:"event_type"`
	ActorID     string         `form:"actor_id"`
	Sector      string         `form:"sector"`
	Outcome     string         `form:"outcome"`
	From        *time.Time     `form:"from"`
	To          *time.Time     `form:"to"`
	Limit       int            `form:"limit,default=100" binding:"max=1000"`
	Offset      int            `form:"offset,default=0"`
}

// AuditResponse represents a paginated audit log response
type AuditResponse struct {
	Events []AuditEvent `json:"events"`
	Total  int64        `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Hash  string `json:"hash"`
	Left  string `json:"left,omitempty"`
	Right string `json:"right,omitempty"`
}

// MerkleTree represents a simple Merkle tree for audit log integrity
type MerkleTree struct {
	Root  string       `json:"root"`
	Nodes []MerkleNode `json:"nodes"`
	Size  int          `json:"size"`
}

// BuildMerkleTree builds a Merkle tree from audit event hashes
func BuildMerkleTree(hashes []string) *MerkleTree {
	if len(hashes) == 0 {
		return &MerkleTree{}
	}

	nodes := make([]MerkleNode, 0)
	currentLevel := hashes

	for len(currentLevel) > 1 {
		nextLevel := make([]string, 0)
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := currentLevel[i] + currentLevel[i+1]
				hash := sha256.Sum256([]byte(combined))
				hashStr := hex.EncodeToString(hash[:])
				nodes = append(nodes, MerkleNode{
					Hash:  hashStr,
					Left:  currentLevel[i],
					Right: currentLevel[i+1],
				})
				nextLevel = append(nextLevel, hashStr)
			} else {
				// Odd node, promote to next level
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		currentLevel = nextLevel
	}

	return &MerkleTree{
		Root:  currentLevel[0],
		Nodes: nodes,
		Size:  len(hashes),
	}
}

// MerkleProof represents a proof of inclusion in the Merkle tree
type MerkleProof struct {
	LeafHash string   `json:"leaf_hash"`
	RootHash string   `json:"root_hash"`
	Path     []string `json:"path"`
	Indices  []int    `json:"indices"` // 0 for left, 1 for right
}

// VerifyMerkleProof verifies a Merkle proof
func VerifyMerkleProof(proof *MerkleProof) bool {
	currentHash := proof.LeafHash
	for i, sibling := range proof.Path {
		var combined string
		if proof.Indices[i] == 0 {
			combined = currentHash + sibling
		} else {
			combined = sibling + currentHash
		}
		hash := sha256.Sum256([]byte(combined))
		currentHash = hex.EncodeToString(hash[:])
	}
	return currentHash == proof.RootHash
}

// DailyMerkleRoot represents a daily published Merkle root
type DailyMerkleRoot struct {
	Date      time.Time `json:"date" gorm:"primaryKey"`
	RootHash  string    `json:"root_hash"`
	EventCount int64    `json:"event_count"`
	PublishedAt time.Time `json:"published_at"`
	GazetteRef  string    `json:"gazette_ref,omitempty"`
	BlockchainRef string `json:"blockchain_ref,omitempty"`
}

// AuditStats represents statistics for audit logs
type AuditStats struct {
	TotalEvents      int64            `json:"total_events"`
	EventsToday      int64            `json:"events_today"`
	EventsThisWeek   int64            `json:"events_this_week"`
	EventsThisMonth  int64            `json:"events_this_month"`
	EventsByType     map[string]int64 `json:"events_by_type"`
	EventsByOutcome  map[string]int64 `json:"events_by_outcome"`
	TopActors        []ActorStat      `json:"top_actors"`
}

// ActorStat represents statistics for an actor
type ActorStat struct {
	ActorID string `json:"actor_id"`
	Count   int64  `json:"count"`
}

// TransparencyReport represents a public transparency report
type TransparencyReport struct {
	Period           string           `json:"period"`
	TotalDataAccess  int64            `json:"total_data_access"`
	AccessBySector   map[string]int64 `json:"access_by_sector"`
	AccessByPurpose  map[string]int64 `json:"access_by_purpose"`
	ConsentGrants    int64            `json:"consent_grants"`
	ConsentRevocations int64          `json:"consent_revocations"`
	ActiveTokens     int64            `json:"active_tokens"`
	MerkleRoot       string           `json:"merkle_root"`
	PublishedAt      time.Time        `json:"published_at"`
}