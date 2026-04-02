// Credential Issuer Service - Issues and verifies Verifiable Credentials
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/konoha/kndis/libs/auth"
	"github.com/konoha/kndis/libs/crypto"
	"github.com/konoha/kndis/libs/middleware"
	"github.com/sirupsen/logrus"
)

var (
	jwtManager       *crypto.JWTManager
	issuedCredentials map[string]*VerifiableCredential
	issuerKeys       map[string]*ecdsa.PrivateKey
	logger           *logrus.Logger
)

// VerifiableCredential represents a W3C Verifiable Credential
type VerifiableCredential struct {
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            Issuer                 `json:"issuer"`
	IssuanceDate      time.Time              `json:"issuanceDate"`
	ExpirationDate    *time.Time             `json:"expirationDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             *Proof                 `json:"proof,omitempty"`
}

// Issuer represents the credential issuer
type Issuer struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Proof represents the cryptographic proof of a credential
type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	JWS                string    `json:"jws,omitempty"`
	ProofValue         string    `json:"proofValue,omitempty"`
}

// CredentialSubject represents the subject of a credential
type CredentialSubject struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type,omitempty"`
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
}

// IssueCredentialRequest represents a request to issue a credential
type IssueCredentialRequest struct {
	CitizenSPID    string                 `json:"citizen_spid" binding:"required"`
	CredentialType string                 `json:"credential_type" binding:"required"`
	Claims         map[string]interface{} `json:"claims" binding:"required"`
	ValidDays      int                    `json:"valid_days" binding:"required,min=1,max=3650"`
}

// VerifyCredentialRequest represents a request to verify a credential
type VerifyCredentialRequest struct {
	Credential VerifiableCredential `json:"credential" binding:"required"`
}

// VerifyCredentialResponse represents a credential verification response
type VerifyCredentialResponse struct {
	Valid         bool      `json:"valid"`
	Issuer        string    `json:"issuer"`
	Subject       string    `json:"subject"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Expired       bool      `json:"expired"`
	Revoked       bool      `json:"revoked"`
	Claims        map[string]interface{} `json:"claims,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// PresentationRequest represents a request for selective disclosure
type PresentationRequest struct {
	Credential      VerifiableCredential `json:"credential" binding:"required"`
	RevealClaims    []string             `json:"reveal_claims" binding:"required"`
}

// Presentation represents a derived credential presentation
type Presentation struct {
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	VerifiableCredential VerifiableCredential `json:"verifiableCredential"`
	RevealedClaims    map[string]interface{} `json:"revealedClaims"`
	Proof             *Proof                 `json:"proof,omitempty"`
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Initialize JWT manager
	jwtManager = crypto.NewJWTManager()
	jwtManager.GenerateSigningKey("ES256")

	// Initialize storage
	issuedCredentials = make(map[string]*VerifiableCredential)
	issuerKeys = make(map[string]*ecdsa.PrivateKey)

	// Generate issuer keys
	generateIssuerKeys()
}

func generateIssuerKeys() {
	// Civil Registry Key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerKeys["civil-registry"] = key

	// Health Ministry Key
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerKeys["health-ministry"] = key

	// Tax Authority Key
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerKeys["tax-authority"] = key
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8089"
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

	// Credential endpoints
	v1 := r.Group("/v1")
	{
		// Verify credential
		v1.POST("/credentials/verify", verifyCredentialHandler)

		// Get credential schema
		v1.GET("/schemas/:type", credentialSchemaHandler)
	}

	// Protected endpoints (require authentication)
	protected := r.Group("/v1")
	protected.Use(auth.AuthMiddleware(auth.NewConfig(jwtManager)))
	{
		// Issue credential
		protected.POST("/credentials/issue", issueCredentialHandler)

		// Create presentation (selective disclosure)
		protected.POST("/credentials/present", createPresentationHandler)

		// Revoke credential
		protected.POST("/credentials/revoke", revokeCredentialHandler)

		// List issued credentials
		protected.GET("/credentials/issued", listIssuedCredentialsHandler)
	}

	logger.Infof("Credential Issuer Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server:", err)
	}
}

// healthHandler returns health status
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "credential-issuer",
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
		"service":             "credential-issuer",
		"issued_credentials":  len(issuedCredentials),
	})
}

// issueCredentialHandler issues a new verifiable credential
func issueCredentialHandler(c *gin.Context) {
	var req IssueCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Get sector from token
	sector, _ := c.Get("sector")
	sectorStr, _ := sector.(string)

	// Determine issuer based on sector
	issuerID := "civil-registry"
	issuerName := "Konoha Civil Registry"

	switch sectorStr {
	case crypto.SectorHealth:
		issuerID = "health-ministry"
		issuerName = "Ministry of Health"
	case crypto.SectorTax:
		issuerID = "tax-authority"
		issuerName = "Revenue Authority"
	}

	// Calculate expiration
	expirationDate := time.Now().AddDate(0, 0, req.ValidDays)

	// Create credential
	credential := &VerifiableCredential{
		ID:           fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Type:         []string{"VerifiableCredential", req.CredentialType},
		Issuer:       Issuer{ID: fmt.Sprintf("did:konoha:gov:%s", issuerID), Name: issuerName},
		IssuanceDate: time.Now(),
		ExpirationDate: &expirationDate,
		CredentialSubject: map[string]interface{}{
			"id":   fmt.Sprintf("did:konoha:citizen:%s", req.CitizenSPID),
			"type": req.CredentialType,
		},
	}

	// Add claims
	for key, value := range req.Claims {
		credential.CredentialSubject[key] = value
	}

	// Sign the credential
	if err := signCredential(credential, issuerID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "signing_failed",
			"message": "Failed to sign credential",
		})
		return
	}

	// Store credential
	issuedCredentials[credential.ID] = credential

	logger.WithFields(logrus.Fields{
		"credential_id": credential.ID,
		"citizen_spid":  req.CitizenSPID,
		"type":          req.CredentialType,
		"issuer":        issuerID,
	}).Info("Credential issued")

	c.JSON(http.StatusCreated, credential)
}

// verifyCredentialHandler verifies a credential
func verifyCredentialHandler(c *gin.Context) {
	var req VerifyCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	response := VerifyCredentialResponse{}

	// Check expiration
	if req.Credential.ExpirationDate != nil {
		response.ExpiresAt = *req.Credential.ExpirationDate
		if time.Now().After(*req.Credential.ExpirationDate) {
			response.Expired = true
			response.Valid = false
			response.Error = "Credential has expired"
			c.JSON(http.StatusOK, response)
			return
		}
	}

	// Verify signature
	valid, err := verifyCredentialSignature(&req.Credential)
	if err != nil {
		response.Valid = false
		response.Error = fmt.Sprintf("Signature verification failed: %v", err)
		c.JSON(http.StatusOK, response)
		return
	}

	if !valid {
		response.Valid = false
		response.Error = "Invalid signature"
		c.JSON(http.StatusOK, response)
		return
	}

	// Extract subject
	if subjectID, ok := req.Credential.CredentialSubject["id"].(string); ok {
		response.Subject = subjectID
	}

	response.Valid = true
	response.Issuer = req.Credential.Issuer.ID
	response.IssuedAt = req.Credential.IssuanceDate
	response.Claims = req.Credential.CredentialSubject

	c.JSON(http.StatusOK, response)
}

// createPresentationHandler creates a selective disclosure presentation
func createPresentationHandler(c *gin.Context) {
	var req PresentationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Verify the original credential first
	valid, err := verifyCredentialSignature(&req.Credential)
	if err != nil || !valid {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_credential",
			"message": "Credential signature is invalid",
		})
		return
	}

	// Create revealed claims map
	revealedClaims := make(map[string]interface{})
	for _, claim := range req.RevealClaims {
		if value, exists := req.Credential.CredentialSubject[claim]; exists {
			revealedClaims[claim] = value
		}
	}

	// Create presentation
	presentation := &Presentation{
		ID:                fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Type:              []string{"VerifiablePresentation"},
		VerifiableCredential: req.Credential,
		RevealedClaims:    revealedClaims,
	}

	// Sign presentation
	presentation.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now(),
		ProofPurpose:       "authentication",
		VerificationMethod: "did:konoha:citizen:holder#key-1",
		ProofValue:         "demo-signature", // In production, actual signature
	}

	c.JSON(http.StatusOK, presentation)
}

// revokeCredentialHandler revokes a credential
func revokeCredentialHandler(c *gin.Context) {
	var req struct {
		CredentialID string `json:"credential_id" binding:"required"`
		Reason       string `json:"reason,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	credential, exists := issuedCredentials[req.CredentialID]
	if !exists {
		middleware.NotFoundError(c, "Credential")
		return
	}

	// Mark as revoked by removing proof
	credential.Proof = nil

	logger.WithFields(logrus.Fields{
		"credential_id": req.CredentialID,
		"reason":        req.Reason,
	}).Info("Credential revoked")

	c.JSON(http.StatusOK, gin.H{
		"message":       "Credential revoked",
		"credential_id": req.CredentialID,
	})
}

// listIssuedCredentialsHandler lists credentials issued by this issuer
func listIssuedCredentialsHandler(c *gin.Context) {
	citizenSPID := c.Query("citizen_spid")

	var credentials []*VerifiableCredential
	for _, cred := range issuedCredentials {
		if citizenSPID != "" {
			if subjectID, ok := cred.CredentialSubject["id"].(string); ok {
				expectedID := fmt.Sprintf("did:konoha:citizen:%s", citizenSPID)
				if subjectID != expectedID {
					continue
				}
			}
		}
		credentials = append(credentials, cred)
	}

	c.JSON(http.StatusOK, gin.H{
		"credentials": credentials,
		"count":       len(credentials),
	})
}

// credentialSchemaHandler returns the schema for a credential type
func credentialSchemaHandler(c *gin.Context) {
	credentialType := c.Param("type")

	schemas := map[string]interface{}{
		"CitizenshipCredential": gin.H{
			"type": "object",
			"properties": gin.H{
				"citizenship":  gin.H{"type": "string"},
				"dateOfBirth":  gin.H{"type": "string", "format": "date"},
				"nationality":  gin.H{"type": "string"},
				"province":     gin.H{"type": "string"},
			},
			"required": []string{"citizenship", "nationality"},
		},
		"AgeCredential": gin.H{
			"type": "object",
			"properties": gin.H{
				"ageAbove18": gin.H{"type": "boolean"},
				"ageAbove21": gin.H{"type": "boolean"},
			},
			"required": []string{"ageAbove18"},
		},
		"HealthInsuranceCredential": gin.H{
			"type": "object",
			"properties": gin.H{
				"covered":    gin.H{"type": "boolean"},
				"tier":       gin.H{"type": "string"},
				"validUntil": gin.H{"type": "string", "format": "date"},
			},
			"required": []string{"covered"},
		},
		"TaxStatusCredential": gin.H{
			"type": "object",
			"properties": gin.H{
				"taxCompliant": gin.H{"type": "boolean"},
				"filingYear":   gin.H{"type": "integer"},
			},
			"required": []string{"taxCompliant"},
		},
	}

	schema, exists := schemas[credentialType]
	if !exists {
		middleware.NotFoundError(c, "Schema")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"type":   credentialType,
		"schema": schema,
	})
}

// Helper functions

func signCredential(credential *VerifiableCredential, issuerID string) error {
	key, exists := issuerKeys[issuerID]
	if !exists {
		return fmt.Errorf("issuer key not found: %s", issuerID)
	}

	// Create canonical representation for signing
	canonicalData, err := json.Marshal(map[string]interface{}{
		"id":                credential.ID,
		"type":              credential.Type,
		"issuer":            credential.Issuer.ID,
		"issuanceDate":      credential.IssuanceDate.Format(time.RFC3339),
		"credentialSubject": credential.CredentialSubject,
	})
	if err != nil {
		return err
	}

	// Hash the data
	hash := sha256.Sum256(canonicalData)

	// Sign (simplified - in production use proper JWS)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return err
	}

	signature := base64.RawURLEncoding.EncodeToString(r.Bytes()) + "." +
		base64.RawURLEncoding.EncodeToString(s.Bytes())

	credential.Proof = &Proof{
		Type:               "EcdsaSecp256r1Signature2019",
		Created:            time.Now(),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: fmt.Sprintf("did:konoha:gov:%s#key-1", issuerID),
		JWS:                signature,
	}

	return nil
}

func verifyCredentialSignature(credential *VerifiableCredential) (bool, error) {
	if credential.Proof == nil {
		return false, fmt.Errorf("credential has no proof")
	}

	// Extract issuer ID from verification method
	issuerID := ""
	if credential.Proof.VerificationMethod != "" {
		// Parse did:konoha:gov:{issuer}#key-1
		parts := strings.Split(credential.Proof.VerificationMethod, ":")
		if len(parts) >= 4 {
			issuerParts := strings.Split(parts[3], "#")
			issuerID = issuerParts[0]
		}
	}

	key, exists := issuerKeys[issuerID]
	if !exists {
		return false, fmt.Errorf("issuer key not found: %s", issuerID)
	}

	// For demo, we accept the signature
	// In production, implement full verification
	_ = key
	return true, nil
}