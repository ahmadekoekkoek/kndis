// Consent Service - Manages citizen consent grants and ABAC policy enforcement
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/konoha/kndis/libs/auth"
	"github.com/konoha/kndis/libs/crypto"
	"github.com/konoha/kndis/libs/middleware"
	"github.com/konoha/kndis/libs/models"
	"github.com/sirupsen/logrus"
)

var (
	consentStore  map[string]*models.ConsentReceipt
	activityLogs  map[string][]models.ActivityLogEntry
	jwtManager    *crypto.JWTManager
	signingKey    ed25519.PrivateKey
	verifyKey     ed25519.PublicKey
	logger        *logrus.Logger
)

// ConsentCheckInternalRequest represents an internal consent check request
type ConsentCheckInternalRequest struct {
	CitizenSPID  string `json:"citizen_spid" binding:"required"`
	RequesterDID string `json:"requester_did" binding:"required"`
	Attribute    string `json:"attribute" binding:"required"`
	Purpose      string `json:"purpose" binding:"required"`
}

// ConsentCheckInternalResponse represents an internal consent check response
type ConsentCheckInternalResponse struct {
	Granted               bool   `json:"granted"`
	ReceiptID             string `json:"receipt_id,omitempty"`
	RemainingAccesses     *int   `json:"remaining_accesses,omitempty"`
	ReceiptSignatureValid bool   `json:"receipt_signature_valid"`
	ReceiptSignature      string `json:"receipt_signature,omitempty"`
}

// RevokeConsentInternalRequest represents an internal revoke request
type RevokeConsentInternalRequest struct {
	ReceiptID string `json:"receipt_id" binding:"required"`
	Reason    string `json:"reason,omitempty"`
}

// ActivityLogQuery represents a query for activity logs
type ActivityLogQuery struct {
	CitizenSPID string     `form:"citizen_spid" binding:"required"`
	From        *time.Time `form:"from" time_format:"2006-01-02T15:04:05Z07:00"`
	To          *time.Time `form:"to" time_format:"2006-01-02T15:04:05Z07:00"`
	Limit       int        `form:"limit,default=100" binding:"max=1000"`
	Offset      int        `form:"offset,default=0"`
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Initialize JWT manager
	jwtManager = crypto.NewJWTManager()
	jwtManager.GenerateSigningKey("ES256")

	// Initialize in-memory stores (use PostgreSQL in production)
	consentStore = make(map[string]*models.ConsentReceipt)
	activityLogs = make(map[string][]models.ActivityLogEntry)

	// Generate Ed25519 key for signing consent receipts
	var err error
	verifyKey, signingKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Fatal("Failed to generate signing key:", err)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	// Global middleware
	loggerConfig := middleware.DefaultLoggerConfig()
	loggerConfig.Logger = logger
	r.Use(middleware.Logger(loggerConfig))
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.RequestIDMiddleware())
	r.Use(middleware.CORSMiddleware([]string{"*"}))
	r.Use(middleware.SecurityHeadersMiddleware())
	r.Use(middleware.ErrorHandler())

	// Health endpoints
	r.GET("/health", healthHandler)
	r.GET("/health/live", livenessHandler)
	r.GET("/health/ready", readinessHandler)
	r.GET("/metrics", metricsHandler)

	// Public consent endpoints (require authentication)
	v1 := r.Group("/v1")
	v1.Use(auth.AuthMiddleware(auth.NewConfig(jwtManager)))
	{
		// Grant consent
		v1.POST("/consent/grant", grantConsentHandler)

		// Revoke consent
		v1.POST("/consent/revoke/:receipt_id", revokeConsentHandler)

		// Get citizen's activity log
		v1.GET("/consent/activity", activityLogHandler)

		// Get citizen's active consents
		v1.GET("/consent/active", activeConsentsHandler)
	}

	// Internal consent endpoints (for service-to-service communication)
	internal := r.Group("/internal/v1")
	{
		// Check consent (called by KonohaX Gateway)
		internal.POST("/consent/check", checkConsentInternalHandler)

		// Record data access
		internal.POST("/consent/record-access", recordAccessHandler)
	}

	logger.Infof("Consent Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server:", err)
	}
}

// healthHandler returns health status
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "consent-service",
		"version":   "1.0.0",
		"timestamp": time.Now().UTC(),
	})
}

// livenessHandler returns liveness probe status
func livenessHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "alive"})
}

// readinessHandler returns readiness probe status
func readinessHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// metricsHandler returns basic metrics
func metricsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service":          "consent-service",
		"active_consents":  len(consentStore),
		"total_revocations": countRevocations(),
	})
}

// grantConsentHandler handles consent grant requests
func grantConsentHandler(c *gin.Context) {
	citizenSPID := auth.GetSubject(c)
	if citizenSPID == "" {
		middleware.UnauthorizedError(c, "No citizen identity in token")
		return
	}

	var req models.GrantConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Get sector from token
	sector, _ := c.Get("sector")
	sectorStr, _ := sector.(string)
	if sectorStr == "" {
		sectorStr = "unknown"
	}

	// Create consent receipt
	receipt, err := models.NewConsentReceipt(&req, citizenSPID, sectorStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "creation_failed",
			"message": "Failed to create consent receipt",
		})
		return
	}

	// Sign the receipt
	receipt.ReceiptSignature = signReceipt(receipt)

	// Store receipt
	consentStore[receipt.ReceiptID] = receipt

	// Log activity
	logActivity(citizenSPID, req.GrantedToDID, "consent.granted", receipt.ReceiptID, "permitted")

	logger.WithFields(logrus.Fields{
		"citizen_spid": citizenSPID,
		"receipt_id":   receipt.ReceiptID,
		"granted_to":   req.GrantedToDID,
		"purpose":      req.Purpose,
	}).Info("Consent granted")

	c.JSON(http.StatusCreated, receipt)
}

// revokeConsentHandler handles consent revocation requests
func revokeConsentHandler(c *gin.Context) {
	citizenSPID := auth.GetSubject(c)
	if citizenSPID == "" {
		middleware.UnauthorizedError(c, "No citizen identity in token")
		return
	}

	receiptID := c.Param("receipt_id")

	// Find the receipt
	receipt, exists := consentStore[receiptID]
	if !exists {
		middleware.NotFoundError(c, "Consent receipt")
		return
	}

	// Verify the receipt belongs to the citizen
	if receipt.CitizenSPID != citizenSPID {
		middleware.ForbiddenError(c, "Cannot revoke consent that does not belong to you")
		return
	}

	// Revoke the consent
	receipt.Revoke()

	// Log activity
	logActivity(citizenSPID, receipt.GrantedToDID, "consent.revoked", receiptID, "permitted")

	logger.WithFields(logrus.Fields{
		"citizen_spid": citizenSPID,
		"receipt_id":   receiptID,
	}).Info("Consent revoked")

	c.Status(http.StatusNoContent)
}

// checkConsentInternalHandler handles internal consent checks (from KonohaX)
func checkConsentInternalHandler(c *gin.Context) {
	var req ConsentCheckInternalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Search for valid consent receipts
	var matchingReceipt *models.ConsentReceipt
	for _, receipt := range consentStore {
		if !receipt.IsValid() {
			continue
		}
		if receipt.CitizenSPID != req.CitizenSPID {
			continue
		}
		if receipt.GrantedToDID != req.RequesterDID {
			continue
		}
		if !receipt.HasAttribute(req.Attribute) {
			continue
		}
		if receipt.Purpose != req.Purpose {
			continue
		}

		matchingReceipt = receipt
		break
	}

	if matchingReceipt == nil {
		c.JSON(http.StatusOK, ConsentCheckInternalResponse{
			Granted:               false,
			ReceiptSignatureValid: false,
		})
		return
	}

	// Verify receipt signature
	signatureValid := verifyReceiptSignature(matchingReceipt)

	response := ConsentCheckInternalResponse{
		Granted:               true,
		ReceiptID:             matchingReceipt.ReceiptID,
		ReceiptSignatureValid: signatureValid,
		ReceiptSignature:      matchingReceipt.ReceiptSignature,
	}

	if matchingReceipt.MaxAccessCount != nil {
		response.RemainingAccesses = matchingReceipt.RemainingAccesses()
	}

	c.JSON(http.StatusOK, response)
}

// recordAccessHandler records a data access event
func recordAccessHandler(c *gin.Context) {
	var req struct {
		CitizenSPID      string `json:"citizen_spid" binding:"required"`
		ActorDID         string `json:"actor_did" binding:"required"`
		Action           string `json:"action" binding:"required"`
		ResourceType     string `json:"resource_type" binding:"required"`
		ResourceID       string `json:"resource_id" binding:"required"`
		Purpose          string `json:"purpose"`
		Outcome          string `json:"outcome" binding:"required"`
		ConsentReceiptID string `json:"consent_receipt_id,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// If consent receipt provided, increment access count
	if req.ConsentReceiptID != "" {
		if receipt, exists := consentStore[req.ConsentReceiptID]; exists {
			receipt.RecordAccess()
		}
	}

	// Log activity
	logActivity(req.CitizenSPID, req.ActorDID, req.Action, req.ConsentReceiptID, req.Outcome)

	c.JSON(http.StatusOK, gin.H{
		"recorded": true,
		"timestamp": time.Now().Unix(),
	})
}

// activityLogHandler returns a citizen's activity log
func activityLogHandler(c *gin.Context) {
	citizenSPID := auth.GetSubject(c)
	if citizenSPID == "" {
		middleware.UnauthorizedError(c, "No citizen identity in token")
		return
	}

	var query ActivityLogQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		middleware.ValidationError(c, "query", err.Error())
		return
	}

	// Override citizen SPID from auth token
	query.CitizenSPID = citizenSPID

	// Get activity logs for citizen
	logs := activityLogs[citizenSPID]

	// Filter by time range
	var filtered []models.ActivityLogEntry
	for _, log := range logs {
		if query.From != nil && log.Timestamp.Before(*query.From) {
			continue
		}
		if query.To != nil && log.Timestamp.After(*query.To) {
			continue
		}
		filtered = append(filtered, log)
	}

	// Apply pagination
	total := len(filtered)
	start := query.Offset
	if start > total {
		start = total
	}
	end := start + query.Limit
	if end > total {
		end = total
	}
	paginated := filtered[start:end]

	c.JSON(http.StatusOK, models.ActivityLogResponse{
		Activities: paginated,
		Total:      int64(total),
		Limit:      query.Limit,
		Offset:     query.Offset,
	})
}

// activeConsentsHandler returns a citizen's active consents
func activeConsentsHandler(c *gin.Context) {
	citizenSPID := auth.GetSubject(c)
	if citizenSPID == "" {
		middleware.UnauthorizedError(c, "No citizen identity in token")
		return
	}

	var active []*models.ConsentReceipt
	for _, receipt := range consentStore {
		if receipt.CitizenSPID == citizenSPID && receipt.IsValid() {
			active = append(active, receipt)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"consents": active,
		"count":    len(active),
	})
}

// Helper functions

func signReceipt(receipt *models.ConsentReceipt) string {
	// Create a canonical representation of the receipt for signing
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%d:%d",
		receipt.ReceiptID,
		receipt.CitizenSPID,
		receipt.GrantedToDID,
		receipt.Purpose,
		receipt.ValidUntil.Format(time.RFC3339),
		receipt.ValidFrom.Unix(),
		receipt.ValidUntil.Unix(),
	)

	signature := ed25519.Sign(signingKey, []byte(data))
	return base64.StdEncoding.EncodeToString(signature)
}

func verifyReceiptSignature(receipt *models.ConsentReceipt) bool {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%d:%d",
		receipt.ReceiptID,
		receipt.CitizenSPID,
		receipt.GrantedToDID,
		receipt.Purpose,
		receipt.ValidUntil.Format(time.RFC3339),
		receipt.ValidFrom.Unix(),
		receipt.ValidUntil.Unix(),
	)

	signature, err := base64.StdEncoding.DecodeString(receipt.ReceiptSignature)
	if err != nil {
		return false
	}

	return ed25519.Verify(verifyKey, []byte(data), signature)
}

func logActivity(citizenSPID, actorDID, action, consentReceiptID, outcome string) {
	entry := models.ActivityLogEntry{
		CitizenSPID:      citizenSPID,
		Timestamp:        time.Now(),
		ActorDID:         actorDID,
		Action:           action,
		Outcome:          outcome,
		ConsentReceiptID: &consentReceiptID,
	}

	activityLogs[citizenSPID] = append(activityLogs[citizenSPID], entry)
}

func countRevocations() int {
	count := 0
	for _, receipt := range consentStore {
		if receipt.Revoked {
			count++
		}
	}
	return count
}

// GenerateECDSASigningKey generates an ECDSA key pair for signing
// This is used for demo purposes
func GenerateECDSASigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}