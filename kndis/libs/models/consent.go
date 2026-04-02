// Package models provides shared data models for KNDIS
package models

import (
	"time"

	"github.com/google/uuid"
)

// ConsentReceipt represents a citizen's consent grant
type ConsentReceipt struct {
	ReceiptID                string            `json:"receipt_id" gorm:"primaryKey"`
	CitizenSPID              string            `json:"citizen_spid" gorm:"index"`
	Sector                   string            `json:"sector"`
	GrantedToDID             string            `json:"granted_to_did"`
	GrantedToName            string            `json:"granted_to_name,omitempty"`
	Attributes               []ConsentAttribute `json:"attributes" gorm:"foreignKey:ReceiptID"`
	Purpose                  string            `json:"purpose"`
	ValidFrom                time.Time         `json:"valid_from"`
	ValidUntil               time.Time         `json:"valid_until"`
	MaxAccessCount           *int              `json:"max_access_count,omitempty"`
	AccessCount              int               `json:"access_count" gorm:"default:0"`
	StorageAllowed           bool              `json:"storage_allowed"`
	DownstreamSharingAllowed bool              `json:"downstream_sharing_allowed"`
	Revoked                  bool              `json:"revoked" gorm:"default:false"`
	RevokedAt                *time.Time        `json:"revoked_at,omitempty"`
	CreatedAt                time.Time         `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt                time.Time         `json:"updated_at" gorm:"autoUpdateTime"`
	ReceiptSignature         string            `json:"receipt_signature"`
}

// ConsentAttribute represents a single attribute in a consent grant
type ConsentAttribute struct {
	ID          uint   `json:"-" gorm:"primaryKey"`
	ReceiptID   string `json:"-" gorm:"index"`
	Attribute   string `json:"attribute"`
	Purpose     string `json:"purpose"`
	LegalBasis  string `json:"legal_basis"`
	Sensitivity string `json:"sensitivity"`
}

// ConsentCheckRequest represents a request to check consent
type ConsentCheckRequest struct {
	CitizenSPID  string `json:"citizen_spid" binding:"required"`
	RequesterDID string `json:"requester_did" binding:"required"`
	Attribute    string `json:"attribute" binding:"required"`
	Purpose      string `json:"purpose" binding:"required"`
}

// ConsentCheckResponse represents the response to a consent check
type ConsentCheckResponse struct {
	Granted          bool   `json:"granted"`
	ReceiptID        string `json:"receipt_id,omitempty"`
	RemainingAccesses *int  `json:"remaining_accesses,omitempty"`
	ReceiptSignatureValid bool `json:"receipt_signature_valid"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

// GrantConsentRequest represents a request to grant consent
type GrantConsentRequest struct {
	GrantedToDID             string                `json:"granted_to_did" binding:"required"`
	GrantedToName            string                `json:"granted_to_name,omitempty"`
	Attributes               []ConsentAttributeReq `json:"attributes" binding:"required,min=1"`
	Purpose                  string                `json:"purpose" binding:"required"`
	ValidFrom                time.Time             `json:"valid_from"`
	ValidUntil               time.Time             `json:"valid_until" binding:"required,gtfield=ValidFrom"`
	MaxAccessCount           *int                  `json:"max_access_count,omitempty"`
	StorageAllowed           bool                  `json:"storage_allowed"`
	DownstreamSharingAllowed bool                  `json:"downstream_sharing_allowed"`
}

// ConsentAttributeReq represents an attribute request in consent grant
type ConsentAttributeReq struct {
	Attribute   string `json:"attribute" binding:"required"`
	Purpose     string `json:"purpose" binding:"required"`
	LegalBasis  string `json:"legal_basis" binding:"required,oneof=vital_interests legitimate_interest legal_obligation consent"`
	Sensitivity string `json:"sensitivity" binding:"required,oneof=low medium high critical"`
}

// RevokeConsentRequest represents a request to revoke consent
type RevokeConsentRequest struct {
	ReceiptID string `json:"receipt_id" binding:"required"`
	Reason    string `json:"reason,omitempty"`
}

// ActivityLogEntry represents an entry in the citizen's activity log
type ActivityLogEntry struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	CitizenSPID     string    `json:"citizen_spid" gorm:"index"`
	Timestamp       time.Time `json:"timestamp"`
	ActorDID        string    `json:"actor_did"`
	ActorName       string    `json:"actor_name,omitempty"`
	Action          string    `json:"action"`
	ResourceType    string    `json:"resource_type"`
	ResourceID      string    `json:"resource_id"`
	Purpose         string    `json:"purpose"`
	Outcome         string    `json:"outcome"`
	ConsentReceiptID *string  `json:"consent_receipt_id,omitempty"`
}

// NewConsentReceipt creates a new consent receipt
func NewConsentReceipt(req *GrantConsentRequest, citizenSPID, sector string) (*ConsentReceipt, error) {
	now := time.Now()

	// Set default valid_from if not provided
	validFrom := req.ValidFrom
	if validFrom.IsZero() {
		validFrom = now
	}

	receipt := &ConsentReceipt{
		ReceiptID:                uuid.New().String(),
		CitizenSPID:              citizenSPID,
		Sector:                   sector,
		GrantedToDID:             req.GrantedToDID,
		GrantedToName:            req.GrantedToName,
		Purpose:                  req.Purpose,
		ValidFrom:                validFrom,
		ValidUntil:               req.ValidUntil,
		MaxAccessCount:           req.MaxAccessCount,
		AccessCount:              0,
		StorageAllowed:           req.StorageAllowed,
		DownstreamSharingAllowed: req.DownstreamSharingAllowed,
		Revoked:                  false,
		CreatedAt:                now,
	}

	// Convert attributes
	for _, attr := range req.Attributes {
		receipt.Attributes = append(receipt.Attributes, ConsentAttribute{
			ReceiptID:   receipt.ReceiptID,
			Attribute:   attr.Attribute,
			Purpose:     attr.Purpose,
			LegalBasis:  attr.LegalBasis,
			Sensitivity: attr.Sensitivity,
		})
	}

	return receipt, nil
}

// IsValid checks if the consent receipt is currently valid
func (cr *ConsentReceipt) IsValid() bool {
	now := time.Now()

	// Check if revoked
	if cr.Revoked {
		return false
	}

	// Check time validity
	if now.Before(cr.ValidFrom) || now.After(cr.ValidUntil) {
		return false
	}

	// Check access count limit
	if cr.MaxAccessCount != nil && cr.AccessCount >= *cr.MaxAccessCount {
		return false
	}

	return true
}

// RecordAccess increments the access count
func (cr *ConsentReceipt) RecordAccess() bool {
	if !cr.IsValid() {
		return false
	}

	cr.AccessCount++
	return true
}

// Revoke marks the consent as revoked
func (cr *ConsentReceipt) Revoke() {
	now := time.Now()
	cr.Revoked = true
	cr.RevokedAt = &now
}

// RemainingAccesses returns the number of remaining accesses
func (cr *ConsentReceipt) RemainingAccesses() *int {
	if cr.MaxAccessCount == nil {
		return nil
	}

	remaining := *cr.MaxAccessCount - cr.AccessCount
	if remaining < 0 {
		remaining = 0
	}
	return &remaining
}

// HasAttribute checks if the consent includes a specific attribute
func (cr *ConsentReceipt) HasAttribute(attribute string) bool {
	for _, attr := range cr.Attributes {
		if attr.Attribute == attribute {
			return true
		}
	}
	return false
}

// GetAttribute returns a specific attribute if present
func (cr *ConsentReceipt) GetAttribute(attribute string) *ConsentAttribute {
	for _, attr := range cr.Attributes {
		if attr.Attribute == attribute {
			return &attr
		}
	}
	return nil
}

// ActivityLogQuery represents query parameters for activity logs
type ActivityLogQuery struct {
	CitizenSPID string     `form:"citizen_spid" binding:"required"`
	From        *time.Time `form:"from"`
	To          *time.Time `form:"to"`
	Limit       int        `form:"limit,default=100" binding:"max=1000"`
	Offset      int        `form:"offset,default=0"`
}

// ActivityLogResponse represents a paginated activity log response
type ActivityLogResponse struct {
	Activities []ActivityLogEntry `json:"activities"`
	Total      int64              `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
}