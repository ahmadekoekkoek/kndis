// K-IdP - Konoha Identity Provider
// OAuth 2.1 + OpenID Connect Core implementation
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/konoha/kndis/libs/auth"
	"github.com/konoha/kndis/libs/crypto"
	"github.com/konoha/kndis/libs/middleware"
	"github.com/konoha/kndis/libs/models"
	"github.com/sirupsen/logrus"
)

var (
	jwtManager    *crypto.JWTManager
	spidGenerator *crypto.SPIDGenerator
	clients       map[string]*models.Client
	authCodes     map[string]*models.AuthorizationCode
	refreshTokens map[string]*models.RefreshToken
	sessions      map[string]*models.Session
	logger        *logrus.Logger
)

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Initialize JWT manager
	jwtManager = crypto.NewJWTManager()
	_, err := jwtManager.GenerateSigningKey("RS256")
	if err != nil {
		logger.Fatal("Failed to generate signing key:", err)
	}

	// Initialize SPID generator with demo keys
	sectorKeys := map[string][]byte{
		crypto.SectorHealth:  []byte("demo-health-key-32bytes-long!!"),
		crypto.SectorTax:     []byte("demo-tax-key-32bytes-long!!!!!"),
		crypto.SectorBanking: []byte("demo-banking-key-32bytes-long!"),
		crypto.SectorVoting:  []byte("demo-voting-key-32bytes-long!!"),
	}
	spidGenerator = crypto.NewSPIDGenerator(sectorKeys)

	// Initialize in-memory stores (use Redis/DB in production)
	clients = make(map[string]*models.Client)
	authCodes = make(map[string]*models.AuthorizationCode)
	refreshTokens = make(map[string]*models.RefreshToken)
	sessions = make(map[string]*models.Session)

	// Register demo clients
	registerDemoClients()
}

func registerDemoClients() {
	// Demo banking client
	clients["kcb-bank-client"] = &models.Client{
		ID:                   "kcb-bank-client",
		Secret:               "hashed-secret", // In production, properly hash
		Name:                 "KCB Bank",
		RedirectURIs:         []string{"https://kcb.konoha.bank/callback", "http://localhost:8081/callback"},
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
		AllowedScopes:        []string{"openid", "profile", "konoha:bank:kyc", "konoha:bank:read"},
		Sector:               crypto.SectorBanking,
		Active:               true,
	}

	// Demo health client
	clients["health-ministry-client"] = &models.Client{
		ID:                   "health-ministry-client",
		Secret:               "hashed-secret",
		Name:                 "Health Ministry Portal",
		RedirectURIs:         []string{"https://health.konoha.gov/callback"},
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
		AllowedScopes:        []string{"openid", "profile", "health:read", "health:write"},
		Sector:               crypto.SectorHealth,
		Active:               true,
	}

	// Demo tax client
	clients["tax-authority-client"] = &models.Client{
		ID:                   "tax-authority-client",
		Secret:               "hashed-secret",
		Name:                 "Revenue Authority",
		RedirectURIs:         []string{"https://tax.konoha.gov/callback"},
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
		AllowedScopes:        []string{"openid", "profile", "tax:read", "tax:write"},
		Sector:               crypto.SectorTax,
		Active:               true,
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Set Gin mode
	ginMode := os.Getenv("GIN_MODE")
	if ginMode == "" {
		ginMode = gin.DebugMode
	}
	gin.SetMode(ginMode)

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

	// OIDC Discovery
	r.GET("/.well-known/openid-configuration", discoveryHandler)
	r.GET("/.well-known/jwks.json", jwksHandler)

	// OAuth2 endpoints
	oauth := r.Group("/oauth/v1")
	{
		oauth.GET("/authorize", middleware.RateLimitMiddleware(10, time.Minute), authorizeHandler)
		oauth.POST("/token", middleware.RateLimitMiddleware(30, time.Minute), tokenHandler)
		oauth.POST("/revoke", revokeHandler)
		oauth.POST("/introspect", introspectHandler)
	}

	// UserInfo endpoint (protected)
	api := r.Group("/oauth/v1")
	api.Use(auth.AuthMiddleware(auth.NewConfig(jwtManager)))
	{
		api.GET("/userinfo", userinfoHandler)
	}

	// Session management
	session := r.Group("/session/v1")
	{
		session.POST("/authenticate", sessionAuthHandler)
	}

	logger.Infof("K-IdP starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server:", err)
	}
}

// healthHandler returns health status
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "k-idp",
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
	// Check dependencies
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// discoveryHandler returns OIDC discovery document
func discoveryHandler(c *gin.Context) {
	baseURL := "https://idp.konoha.gov"
	if os.Getenv("KONOHA_BASE_URL") != "" {
		baseURL = os.Getenv("KONOHA_BASE_URL")
	}

	c.JSON(http.StatusOK, models.OpenIDConfiguration{
		Issuer:                            baseURL,
		AuthorizationEndpoint:             baseURL + "/oauth/v1/authorize",
		TokenEndpoint:                     baseURL + "/oauth/v1/token",
		UserInfoEndpoint:                  baseURL + "/oauth/v1/userinfo",
		JWKSURI:                           baseURL + "/.well-known/jwks.json",
		ScopesSupported:                   []string{"openid", "profile", "email", "konoha:bank:kyc", "health:read", "tax:read"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported: []string{
			"sub", "name", "given_name", "family_name", "birthdate",
			"nationality", "sector_spid", "auth_time", "acr", "amr",
		},
		CodeChallengeMethodsSupported: []string{"S256"},
	})
}

// jwksHandler returns the JSON Web Key Set
func jwksHandler(c *gin.Context) {
	c.JSON(http.StatusOK, jwtManager.GetJWKS())
}

// authorizeHandler handles OAuth2 authorization requests
func authorizeHandler(c *gin.Context) {
	var req models.AuthorizationRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_request", "Invalid request parameters", "")
		return
	}

	// Validate client
	client, exists := clients[req.ClientID]
	if !exists || !client.Active {
		redirectError(c, req.RedirectURI, req.State, "unauthorized_client", "Invalid client")
		return
	}

	// Validate redirect URI
	if !client.ValidateRedirectURI(req.RedirectURI) {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_request", "Invalid redirect URI", "")
		return
	}

	// Validate response type
	if req.ResponseType != "code" {
		redirectError(c, req.RedirectURI, req.State, "unsupported_response_type", "Only 'code' response type is supported", "")
		return
	}

	// Validate scope
	requestedScopes := strings.Split(req.Scope, " ")
	if !client.ValidateScope(requestedScopes) {
		redirectError(c, req.RedirectURI, req.State, "invalid_scope", "Invalid or unauthorized scope", "")
		return
	}

	// In a real implementation, this would redirect to a login/consent page
	// For demo, we'll simulate a successful authentication

	// Generate SPID for the citizen in this sector
	// In production, this would come from authenticated session
	demoNIN := crypto.GenerateNIN()
	spid, err := spidGenerator.GenerateSPID(demoNIN, client.Sector)
	if err != nil {
		redirectError(c, req.RedirectURI, req.State, "server_error", "Failed to generate SPID", "")
		return
	}

	// Create authorization code
	authCode := models.NewAuthorizationCode(
		req.ClientID,
		spid,
		client.Sector,
		req.RedirectURI,
		req.Scope,
		req.CodeChallenge,
		req.CodeChallengeMethod,
		req.Nonce,
	)
	authCodes[authCode.Code] = authCode

	logger.WithFields(logrus.Fields{
		"client_id":  req.ClientID,
		"citizen_spid": spid,
		"scope":      req.Scope,
	}).Info("Authorization code issued")

	// Redirect back to client with authorization code
	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	q.Set("state", req.State)
	redirectURL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// tokenHandler handles OAuth2 token requests
func tokenHandler(c *gin.Context) {
	var req models.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_request", "Invalid request parameters", "")
		return
	}

	// Validate client
	client, exists := clients[req.ClientID]
	if !exists || !client.Active {
		middleware.OAuthError(c, http.StatusUnauthorized, "invalid_client", "Invalid client", "")
		return
	}

	switch req.GrantType {
	case "authorization_code":
		handleAuthorizationCodeGrant(c, &req, client)
	case "refresh_token":
		handleRefreshTokenGrant(c, &req, client)
	default:
		middleware.OAuthError(c, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type", "")
	}
}

func handleAuthorizationCodeGrant(c *gin.Context, req *models.TokenRequest, client *models.Client) {
	// Validate authorization code
	authCode, exists := authCodes[req.Code]
	if !exists || authCode.Used || authCode.IsExpired() {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_grant", "Invalid or expired authorization code", "")
		return
	}

	// Validate client matches
	if authCode.ClientID != client.ID {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_grant", "Authorization code was not issued to this client", "")
		return
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != req.RedirectURI {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_grant", "Redirect URI mismatch", "")
		return
	}

	// Validate PKCE
	if !validatePKCE(authCode.CodeChallenge, req.CodeVerifier) {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_grant", "Invalid code verifier", "")
		return
	}

	// Mark code as used
	authCode.Used = true

	// Generate DPoP confirmation (simplified for demo)
	cnf := map[string]interface{}{
		"jkt": crypto.GenerateDPoPThumbprint([]byte("demo-dpop-key")),
	}

	// Generate access token
	accessTokenResp, err := jwtManager.GenerateAccessToken(
		authCode.CitizenSPID,
		"service:"+client.Sector,
		authCode.Scope,
		authCode.Sector,
		cnf,
		5*time.Minute,
	)
	if err != nil {
		middleware.OAuthError(c, http.StatusInternalServerError, "server_error", "Failed to generate access token", "")
		return
	}

	// Generate ID token if openid scope requested
	var idToken string
	if strings.Contains(authCode.Scope, "openid") {
		idToken, err = jwtManager.GenerateIDToken(
			authCode.CitizenSPID,
			client.ID,
			"Demo Citizen", // In production, fetch from citizen profile
			"Demo",
			"Citizen",
			"1990-01-01",
			"Konoha",
			authCode.CitizenSPID,
			authCode.Nonce,
			5*time.Minute,
		)
		if err != nil {
			middleware.OAuthError(c, http.StatusInternalServerError, "server_error", "Failed to generate ID token", "")
			return
		}
	}

	// Generate refresh token
	refreshToken := models.NewRefreshToken(client.ID, authCode.CitizenSPID, authCode.Sector, authCode.Scope, 7*24*time.Hour)
	refreshTokens[refreshToken.Token] = refreshToken

	logger.WithFields(logrus.Fields{
		"client_id":    client.ID,
		"citizen_spid": authCode.CitizenSPID,
		"scope":        authCode.Scope,
	}).Info("Token issued")

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenResp.AccessToken,
		"token_type":    "DPoP",
		"expires_in":    accessTokenResp.ExpiresIn,
		"refresh_token": refreshToken.Token,
		"id_token":      idToken,
		"scope":         authCode.Scope,
	})
}

func handleRefreshTokenGrant(c *gin.Context, req *models.TokenRequest, client *models.Client) {
	// Validate refresh token
	refreshToken, exists := refreshTokens[req.RefreshToken]
	if !exists || refreshToken.Revoked || refreshToken.IsExpired() {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token", "")
		return
	}

	// Validate client matches
	if refreshToken.ClientID != client.ID {
		middleware.OAuthError(c, http.StatusBadRequest, "invalid_grant", "Refresh token was not issued to this client", "")
		return
	}

	// Determine scope (can be subset of original)
	scope := refreshToken.Scope
	if req.Scope != "" {
		// Validate requested scope is subset of original
		requestedScopes := strings.Split(req.Scope, " ")
		originalScopes := strings.Split(refreshToken.Scope, " ")
		originalSet := make(map[string]bool)
		for _, s := range originalScopes {
			originalSet[s] = true
		}
		for _, s := range requestedScopes {
			if !originalSet[s] {
				middleware.OAuthError(c, http.StatusBadRequest, "invalid_scope", "Requested scope exceeds original grant", "")
				return
			}
		}
		scope = req.Scope
	}

	// Revoke old refresh token (rotation)
	refreshToken.Revoked = true

	// Generate new tokens
	cnf := map[string]interface{}{
		"jkt": crypto.GenerateDPoPThumbprint([]byte("demo-dpop-key")),
	}

	accessTokenResp, err := jwtManager.GenerateAccessToken(
		refreshToken.CitizenSPID,
		"service:"+refreshToken.Sector,
		scope,
		refreshToken.Sector,
		cnf,
		5*time.Minute,
	)
	if err != nil {
		middleware.OAuthError(c, http.StatusInternalServerError, "server_error", "Failed to generate access token", "")
		return
	}

	// Issue new refresh token
	newRefreshToken := models.NewRefreshToken(client.ID, refreshToken.CitizenSPID, refreshToken.Sector, scope, 7*24*time.Hour)
	refreshTokens[newRefreshToken.Token] = newRefreshToken

	logger.WithFields(logrus.Fields{
		"client_id":    client.ID,
		"citizen_spid": refreshToken.CitizenSPID,
		"scope":        scope,
	}).Info("Token refreshed")

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenResp.AccessToken,
		"token_type":    "DPoP",
		"expires_in":    accessTokenResp.ExpiresIn,
		"refresh_token": newRefreshToken.Token,
		"scope":         scope,
	})
}

// revokeHandler handles token revocation
func revokeHandler(c *gin.Context) {
	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")

	// Try to revoke as refresh token
	if refreshToken, exists := refreshTokens[token]; exists {
		refreshToken.Revoked = true
		logger.WithField("token_type", "refresh_token").Info("Token revoked")
	}

	// Try to revoke as access token (in production, add to revocation list)
	if tokenTypeHint == "access_token" || tokenTypeHint == "" {
		logger.WithField("token_type", "access_token").Info("Token revocation requested")
	}

	// Always return 200 for privacy (don't reveal if token existed)
	c.Status(http.StatusOK)
}

// introspectHandler handles token introspection
func introspectHandler(c *gin.Context) {
	token := c.PostForm("token")

	// Check if it's a refresh token
	if refreshToken, exists := refreshTokens[token]; exists {
		if refreshToken.Revoked || refreshToken.IsExpired() {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"active":     true,
			"client_id":  refreshToken.ClientID,
			"sub":        refreshToken.CitizenSPID,
			"scope":      refreshToken.Scope,
			"exp":        refreshToken.ExpiresAt.Unix(),
		})
		return
	}

	// Try to validate as access token
	claims, err := jwtManager.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active":    true,
		"sub":       claims.Subject,
		"scope":     claims.Scope,
		"exp":       claims.ExpiresAt.Unix(),
		"sector":    claims.Sector,
		"token_type": claims.TokenType,
	})
}

// userinfoHandler returns OIDC user info
func userinfoHandler(c *gin.Context) {
	claims := auth.GetClaims(c)
	if claims == nil {
		middleware.UnauthorizedError(c, "Invalid token")
		return
	}

	// In production, fetch from citizen profile service
	userInfo := models.OIDCUserInfo{
		Sub:         claims.Subject,
		Name:        "Demo Citizen",
		GivenName:   "Demo",
		FamilyName:  "Citizen",
		Birthdate:   "1990-01-01",
		Nationality: "Konoha",
		SectorSPID:  claims.Subject,
	}

	c.JSON(http.StatusOK, userInfo)
}

// sessionAuthHandler handles citizen authentication (simplified)
func sessionAuthHandler(c *gin.Context) {
	// In production, this would handle FIDO2/WebAuthn authentication
	// For demo, return a simulated session
	c.JSON(http.StatusOK, gin.H{
		"status": "authenticated",
		"method": "demo",
		"note":   "In production, this would use FIDO2/WebAuthn",
	})
}

// Helper functions

func redirectError(c *gin.Context, redirectURI, state, errCode, errDescription string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errCode)
	q.Set("error_description", errDescription)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func validatePKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}

	hash := sha256.Sum256([]byte(verifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return computedChallenge == challenge
}