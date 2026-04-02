// Token Service - JWT token issuance, validation, and DPoP binding
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/konoha/kndis/libs/auth"
	"github.com/konoha/kndis/libs/crypto"
	"github.com/konoha/kndis/libs/middleware"
	"github.com/sirupsen/logrus"
)

var (
	jwtManager      *crypto.JWTManager
	revocationList  map[string]time.Time // token ID -> revocation time
	logger          *logrus.Logger
)

// TokenIntrospectRequest represents a token introspection request
type TokenIntrospectRequest struct {
	Token           string `json:"token" binding:"required"`
	TokenTypeHint   string `json:"token_type_hint,omitempty"`
}

// TokenIntrospectResponse represents a token introspection response
type TokenIntrospectResponse struct {
	Active     bool   `json:"active"`
	Scope      string `json:"scope,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	TokenType  string `json:"token_type,omitempty"`
	Exp        int64  `json:"exp,omitempty"`
	Iat        int64  `json:"iat,omitempty"`
	Sub        string `json:"sub,omitempty"`
	Aud        string `json:"aud,omitempty"`
	Iss        string `json:"iss,omitempty"`
	Jti        string `json:"jti,omitempty"`
	Sector     string `json:"sector,omitempty"`
}

// TokenRevokeRequest represents a token revocation request
type TokenRevokeRequest struct {
	Token         string `json:"token" binding:"required"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

// DPoPValidateRequest represents a DPoP validation request
type DPoPValidateRequest struct {
	DPoPProof    string `json:"dpop_proof" binding:"required"`
	AccessToken  string `json:"access_token" binding:"required"`
	HTTPMethod   string `json:"http_method" binding:"required"`
	HTTPURL      string `json:"http_url" binding:"required"`
}

// TokenInfoRequest represents a request for token information
type TokenInfoRequest struct {
	Token string `json:"token" binding:"required"`
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Initialize JWT manager
	jwtManager = crypto.NewJWTManager()
	jwtManager.GenerateSigningKey("RS256")

	// Initialize revocation list
	revocationList = make(map[string]time.Time)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
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

	// JWKS endpoint
	r.GET("/.well-known/jwks.json", jwksHandler)

	// Token validation and management endpoints
	v1 := r.Group("/v1")
	{
		// Introspect token
		v1.POST("/introspect", introspectHandler)

		// Revoke token
		v1.POST("/revoke", revokeHandler)

		// Validate DPoP
		v1.POST("/dpop/validate", validateDPoPHandler)

		// Get token info
		v1.POST("/info", tokenInfoHandler)

		// Check revocation status
		v1.GET("/revocation-list", revocationListHandler)
	}

	// Protected endpoints (require authentication)
	protected := r.Group("/v1/admin")
	protected.Use(auth.AuthMiddleware(auth.NewConfig(jwtManager)))
	{
		// Add to revocation list
		protected.POST("/revoke", adminRevokeHandler)

		// Get active tokens count
		protected.GET("/stats", tokenStatsHandler)
	}

	logger.Infof("Token Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server:", err)
	}
}

// healthHandler returns health status
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"service":    "token-service",
		"version":    "1.0.0",
		"timestamp":  time.Now().UTC(),
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
		"service":            "token-service",
		"revoked_tokens":     len(revocationList),
	})
}

// jwksHandler returns the JSON Web Key Set
func jwksHandler(c *gin.Context) {
	c.JSON(http.StatusOK, jwtManager.GetJWKS())
}

// introspectHandler introspects a token
func introspectHandler(c *gin.Context) {
	var req TokenIntrospectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Parse token without validation first to get claims
	claims, err := crypto.ParseTokenWithoutValidation(req.Token)
	if err != nil {
		// Return inactive for invalid tokens (privacy)
		c.JSON(http.StatusOK, TokenIntrospectResponse{Active: false})
		return
	}

	// Check if token is revoked
	if _, revoked := revocationList[claims.ID]; revoked {
		c.JSON(http.StatusOK, TokenIntrospectResponse{Active: false})
		return
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		c.JSON(http.StatusOK, TokenIntrospectResponse{Active: false})
		return
	}

	// Token is active
	response := TokenIntrospectResponse{
		Active:    true,
		Scope:     claims.Scope,
		TokenType: string(claims.TokenType),
		Exp:       claims.ExpiresAt.Unix(),
		Iat:       claims.IssuedAt.Unix(),
		Sub:       claims.Subject,
		Aud:       "",
		Iss:       claims.Issuer,
		Jti:       claims.ID,
		Sector:    claims.Sector,
	}

	if len(claims.Audience) > 0 {
		response.Aud = claims.Audience[0]
	}

	c.JSON(http.StatusOK, response)
}

// revokeHandler revokes a token
func revokeHandler(c *gin.Context) {
	var req TokenRevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Parse token to get JTI
	claims, err := crypto.ParseTokenWithoutValidation(req.Token)
	if err != nil {
		// Still return 200 for privacy
		c.Status(http.StatusOK)
		return
	}

	// Add to revocation list
	revocationList[claims.ID] = time.Now()

	logger.WithFields(logrus.Fields{
		"token_id": claims.ID,
		"subject":  claims.Subject,
	}).Info("Token revoked")

	c.Status(http.StatusOK)
}

// validateDPoPHandler validates a DPoP proof
func validateDPoPHandler(c *gin.Context) {
	var req DPoPValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Validate DPoP proof
	err := crypto.ValidateDPoP(req.DPoPProof, req.HTTPMethod, req.HTTPURL, req.AccessToken)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":   false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
	})
}

// tokenInfoHandler returns human-readable token information
func tokenInfoHandler(c *gin.Context) {
	var req TokenInfoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	info, err := crypto.GetTokenInfo(req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, info)
}

// revocationListHandler returns the current revocation list
func revocationListHandler(c *gin.Context) {
	// Return compact revocation list (token IDs only)
	tokenIDs := make([]string, 0, len(revocationList))
	for id := range revocationList {
		tokenIDs = append(tokenIDs, id)
	}

	c.JSON(http.StatusOK, gin.H{
		"revoked_tokens": tokenIDs,
		"count":          len(tokenIDs),
		"updated_at":     time.Now().Unix(),
	})
}

// adminRevokeHandler allows admin to revoke tokens
func adminRevokeHandler(c *gin.Context) {
	var req struct {
		TokenID string `json:"token_id" binding:"required"`
		Reason  string `json:"reason,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	revocationList[req.TokenID] = time.Now()

	logger.WithFields(logrus.Fields{
		"token_id": req.TokenID,
		"reason":   req.Reason,
	}).Warn("Token revoked by admin")

	c.JSON(http.StatusOK, gin.H{
		"message":   "Token revoked",
		"token_id":  req.TokenID,
		"revoked_at": time.Now().Unix(),
	})
}

// tokenStatsHandler returns token statistics
func tokenStatsHandler(c *gin.Context) {
	// Clean up old revocations (older than 7 days)
	cutoff := time.Now().AddDate(0, 0, -7)
	for id, revokedAt := range revocationList {
		if revokedAt.Before(cutoff) {
			delete(revocationList, id)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"revoked_tokens": len(revocationList),
	})
}