// Package auth provides authentication and authorization middleware
package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/konoha/kndis/libs/crypto"
)

// Config holds authentication middleware configuration
type Config struct {
	JWTManager       *crypto.JWTManager
	RequiredScopes   []string
	RequireDPoP      bool
	SkipAuthPaths    []string
	TokenHeader      string
}

// NewConfig creates a default auth config
func NewConfig(jwtManager *crypto.JWTManager) *Config {
	return &Config{
		JWTManager:    jwtManager,
		TokenHeader:   "Authorization",
		SkipAuthPaths: []string{"/health", "/.well-known", "/oauth/v1/authorize"},
	}
}

// AuthMiddleware creates a Gin middleware for JWT authentication
func AuthMiddleware(config *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for certain paths
		for _, path := range config.SkipAuthPaths {
			if strings.HasPrefix(c.Request.URL.Path, path) {
				c.Next()
				return
			}
		}

		// Extract token from header
		authHeader := c.GetHeader(config.TokenHeader)
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_request",
				"error_description": "Missing authorization header",
			})
			c.Abort()
			return
		}

		// Parse token (support "Bearer" and "DPoP" token types)
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_request",
				"error_description": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		tokenType := parts[0]
		tokenString := parts[1]

		if tokenType != "Bearer" && tokenType != "DPoP" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_request",
				"error_description": "Unsupported token type",
			})
			c.Abort()
			return
		}

		// Validate DPoP if required
		if config.RequireDPoP || tokenType == "DPoP" {
			dpopProof := c.GetHeader("DPoP")
			if dpopProof == "" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":             "invalid_request",
					"error_description": "DPoP proof required",
				})
				c.Abort()
				return
			}

			// Validate DPoP proof
			if err := crypto.ValidateDPoP(dpopProof, c.Request.Method, c.Request.URL.String(), tokenString); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":             "invalid_dpop_proof",
					"error_description": err.Error(),
				})
				c.Abort()
				return
			}
		}

		// Validate JWT
		claims, err := config.JWTManager.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": err.Error(),
			})
			c.Abort()
			return
		}

		// Check if token is expired
		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Token has expired",
			})
			c.Abort()
			return
		}

		// Check required scopes
		if len(config.RequiredScopes) > 0 {
			tokenScopes := strings.Split(claims.Scope, " ")
			scopeSet := make(map[string]bool)
			for _, s := range tokenScopes {
				scopeSet[s] = true
			}

			for _, required := range config.RequiredScopes {
				if !scopeSet[required] {
					c.JSON(http.StatusForbidden, gin.H{
						"error":             "insufficient_scope",
						"error_description": "Token missing required scope: " + required,
					})
					c.Abort()
					return
				}
			}
		}

		// Set claims in context for downstream handlers
		c.Set("claims", claims)
		c.Set("subject", claims.Subject)
		c.Set("scope", claims.Scope)
		c.Set("sector", claims.Sector)

		c.Next()
	}
}

// RequireScope creates middleware that requires specific scopes
func RequireScope(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenScope, exists := c.Get("scope")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": "No scope in context",
			})
			c.Abort()
			return
		}

		scopeStr, ok := tokenScope.(string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "server_error",
				"error_description": "Invalid scope in context",
			})
			c.Abort()
			return
		}

		tokenScopes := strings.Split(scopeStr, " ")
		scopeSet := make(map[string]bool)
		for _, s := range tokenScopes {
			scopeSet[s] = true
		}

		for _, required := range scopes {
			if !scopeSet[required] {
				c.JSON(http.StatusForbidden, gin.H{
					"error":             "insufficient_scope",
					"error_description": "Missing required scope: " + required,
					"scope":             strings.Join(scopes, " "),
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RequireSector creates middleware that requires a specific sector
func RequireSector(sector string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenSector, exists := c.Get("sector")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "invalid_sector",
				"error_description": "No sector in context",
			})
			c.Abort()
			return
		}

		sectorStr, ok := tokenSector.(string)
		if !ok || sectorStr != sector {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "invalid_sector",
				"error_description": "Token not valid for this sector",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetClaims extracts claims from Gin context
func GetClaims(c *gin.Context) *crypto.KNDISClaims {
	claims, exists := c.Get("claims")
	if !exists {
		return nil
	}

	kndisClaims, ok := claims.(*crypto.KNDISClaims)
	if !ok {
		return nil
	}

	return kndisClaims
}

// GetSubject extracts the subject (SPID) from context
func GetSubject(c *gin.Context) string {
	subject, exists := c.Get("subject")
	if !exists {
		return ""
	}

	subStr, ok := subject.(string)
	if !ok {
		return ""
	}

	return subStr
}

// ClientAuthMiddleware validates client credentials (for token endpoint)
func ClientAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// For simplicity, we accept client_id in form data
		// In production, this would validate client_secret or use mTLS
		clientID := c.PostForm("client_id")
		if clientID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": "Client authentication required",
			})
			c.Abort()
			return
		}

		c.Set("client_id", clientID)
		c.Next()
	}
}

// RateLimitMiddleware creates a simple rate limiting middleware
// In production, use Redis-based distributed rate limiting
func RateLimitMiddleware(requests int, window time.Duration) gin.HandlerFunc {
	// Simple in-memory rate limiter (for demo only)
	// In production, use Redis or dedicated rate limiter service
	type clientInfo struct {
		count     int
		resetTime time.Time
	}

	clients := make(map[string]*clientInfo)

	return func(c *gin.Context) {
		clientID := c.ClientIP()
		now := time.Now()

		info, exists := clients[clientID]
		if !exists || now.After(info.resetTime) {
			clients[clientID] = &clientInfo{
				count:     1,
				resetTime: now.Add(window),
			}
			c.Next()
			return
		}

		if info.count >= requests {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many requests",
				"retry_after":       int(info.resetTime.Sub(now).Seconds()),
			})
			c.Abort()
			return
		}

		info.count++
		c.Next()
	}
}