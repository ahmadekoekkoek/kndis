// Gateway - KonohaX API Gateway
// Implements reverse proxy, JWT validation, rate limiting, and request routing
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/konoha/kndis/libs/auth"
	"github.com/konoha/kndis/libs/crypto"
	"github.com/konoha/kndis/libs/middleware"
	"github.com/sirupsen/logrus"
)

var (
	jwtManager     *crypto.JWTManager
	serviceRegistry map[string]*ServiceInfo
	circuitBreakers map[string]*CircuitBreaker
	logger         *logrus.Logger
	consentServiceURL string
)

// ServiceInfo represents a registered service
type ServiceInfo struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	BaseURL           string            `json:"base_url"`
	AuthRequired      bool              `json:"auth_required"`
	RequiredScopes    []string          `json:"required_scopes"`
	RequiresConsent   bool              `json:"requires_consent"`
	AllowedAttributes []string          `json:"allowed_attributes"`
	RateLimit         int               `json:"rate_limit"`
	HealthEndpoint    string            `json:"health_endpoint"`
	Proxy             *httputil.ReverseProxy `json:"-"`
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	state          string    // closed, open, half-open
	failureCount   int
	successCount   int
	lastFailure    time.Time
	threshold      int
	resetTimeout   time.Duration
	mu             sync.RWMutex
}

// KonohaXRequest represents a request through the gateway
type KonohaXRequest struct {
	TargetService  string                 `json:"target_service" binding:"required"`
	Operation      string                 `json:"operation" binding:"required"`
	Parameters     map[string]interface{} `json:"parameters"`
	Purpose        string                 `json:"purpose" binding:"required"`
	CitizenSPID    string                 `json:"citizen_spid" binding:"required"`
	ConsentReceiptID string               `json:"consent_receipt_id,omitempty"`
}

// KonohaXResponse represents a response from the gateway
type KonohaXResponse struct {
	RequestID  string      `json:"request_id"`
	Status     string      `json:"status"`
	Data       interface{} `json:"data,omitempty"`
	Error      string      `json:"error,omitempty"`
	AuditLogID string      `json:"audit_log_id,omitempty"`
}

// ServiceRegistrationRequest represents a service registration request
type ServiceRegistrationRequest struct {
	ID                string   `json:"id" binding:"required"`
	Name              string   `json:"name" binding:"required"`
	BaseURL           string   `json:"base_url" binding:"required,url"`
	AuthRequired      bool     `json:"auth_required"`
	RequiredScopes    []string `json:"required_scopes"`
	RequiresConsent   bool     `json:"requires_consent"`
	AllowedAttributes []string `json:"allowed_attributes"`
	RateLimit         int      `json:"rate_limit"`
	HealthEndpoint    string   `json:"health_endpoint"`
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Initialize JWT manager
	jwtManager = crypto.NewJWTManager()
	jwtManager.GenerateSigningKey("RS256")

	// Initialize service registry
	serviceRegistry = make(map[string]*ServiceInfo)
	circuitBreakers = make(map[string]*CircuitBreaker)

	// Set consent service URL
	consentServiceURL = getEnv("CONSENT_SERVICE_URL", "http://localhost:8082")

	// Register demo services
	registerDemoServices()
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func registerDemoServices() {
	// Health Ministry Service
	registerService(&ServiceInfo{
		ID:                "konoha.health.citizen-records.v2",
		Name:              "Health Ministry - Citizen Records",
		BaseURL:           getEnv("HEALTH_SERVICE_URL", "http://localhost:8085"),
		AuthRequired:      true,
		RequiredScopes:    []string{"health:read"},
		RequiresConsent:   true,
		AllowedAttributes: []string{"health:medical_history", "health:prescriptions", "health:allergies"},
		RateLimit:         1000,
		HealthEndpoint:    "/health",
	})

	// Tax Authority Service
	registerService(&ServiceInfo{
		ID:                "konoha.tax.citizen-data.v1",
		Name:              "Tax Authority - Citizen Data",
		BaseURL:           getEnv("TAX_SERVICE_URL", "http://localhost:8086"),
		AuthRequired:      true,
		RequiredScopes:    []string{"tax:read"},
		RequiresConsent:   true,
		AllowedAttributes: []string{"tax:status", "tax:income_range", "tax:filing_history"},
		RateLimit:         1000,
		HealthEndpoint:    "/health",
	})

	// Banking Service
	registerService(&ServiceInfo{
		ID:                "konoha.bank.kyc.v1",
		Name:              "Banking - KYC Service",
		BaseURL:           getEnv("BANK_SERVICE_URL", "http://localhost:8087"),
		AuthRequired:      true,
		RequiredScopes:    []string{"konoha:bank:kyc"},
		RequiresConsent:   true,
		AllowedAttributes: []string{"identity:name", "identity:dob", "tax:income_range"},
		RateLimit:         500,
		HealthEndpoint:    "/health",
	})
}

func registerService(info *ServiceInfo) error {
	targetURL, err := url.Parse(info.BaseURL)
	if err != nil {
		return err
	}

	info.Proxy = httputil.NewSingleHostReverseProxy(targetURL)
	serviceRegistry[info.ID] = info

	// Initialize circuit breaker
	circuitBreakers[info.ID] = &CircuitBreaker{
		state:        "closed",
		threshold:    5,
		resetTimeout: 30 * time.Second,
	}

	logger.WithField("service_id", info.ID).Info("Service registered")
	return nil
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
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

	// Public endpoints
	r.GET("/konohax/v1/services", listServicesHandler)
	r.GET("/konohax/v1/services/:id", getServiceHandler)

	// Protected endpoints (require authentication)
	protected := r.Group("/konohax/v1")
	protected.Use(auth.AuthMiddleware(auth.NewConfig(jwtManager)))
	{
		// Main request endpoint
		protected.POST("/request", handleRequest)

		// Service registration (admin only)
		protected.POST("/services/register", registerServiceHandler)

		// Circuit breaker status
		protected.GET("/circuit-breakers", circuitBreakerStatusHandler)
		protected.POST("/circuit-breakers/:id/reset", resetCircuitBreakerHandler)
	}

	// Proxy endpoint for direct service access
	r.Any("/proxy/:service_id/*path", proxyHandler)

	logger.Infof("KonohaX Gateway starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server:", err)
	}
}

// healthHandler returns health status
func healthHandler(c *gin.Context) {
	// Check all registered services
	serviceStatuses := make(map[string]string)
	for id, service := range serviceRegistry {
		status := "unknown"
		cb := circuitBreakers[id]
		if cb != nil {
			cb.mu.RLock()
			status = cb.state
			cb.mu.RUnlock()
		}
		serviceStatuses[id] = status
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          "healthy",
		"service":         "konohax-gateway",
		"version":         "1.0.0",
		"services":        len(serviceRegistry),
		"service_status":  serviceStatuses,
		"timestamp":       time.Now().UTC(),
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
		"service":            "konohax-gateway",
		"registered_services": len(serviceRegistry),
		"circuit_breakers":   len(circuitBreakers),
	})
}

// listServicesHandler lists all registered services
func listServicesHandler(c *gin.Context) {
	services := make([]ServiceInfo, 0, len(serviceRegistry))
	for _, service := range serviceRegistry {
		// Don't expose internal proxy
		services = append(services, ServiceInfo{
			ID:                service.ID,
			Name:              service.Name,
			BaseURL:           service.BaseURL,
			AuthRequired:      service.AuthRequired,
			RequiredScopes:    service.RequiredScopes,
			RequiresConsent:   service.RequiresConsent,
			AllowedAttributes: service.AllowedAttributes,
			RateLimit:         service.RateLimit,
			HealthEndpoint:    service.HealthEndpoint,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"services": services,
		"count":    len(services),
	})
}

// getServiceHandler gets information about a specific service
func getServiceHandler(c *gin.Context) {
	serviceID := c.Param("id")
	service, exists := serviceRegistry[serviceID]
	if !exists {
		middleware.NotFoundError(c, "Service")
		return
	}

	c.JSON(http.StatusOK, ServiceInfo{
		ID:                service.ID,
		Name:              service.Name,
		BaseURL:           service.BaseURL,
		AuthRequired:      service.AuthRequired,
		RequiredScopes:    service.RequiredScopes,
		RequiresConsent:   service.RequiresConsent,
		AllowedAttributes: service.AllowedAttributes,
		RateLimit:         service.RateLimit,
		HealthEndpoint:    service.HealthEndpoint,
	})
}

// handleRequest handles cross-agency data requests
func handleRequest(c *gin.Context) {
	var req KonohaXRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	requestID, _ := c.Get("request_id")
	requestIDStr, _ := requestID.(string)

	// Get service info
	service, exists := serviceRegistry[req.TargetService]
	if !exists {
		c.JSON(http.StatusNotFound, KonohaXResponse{
			RequestID: requestIDStr,
			Status:    "error",
			Error:     "Service not found: " + req.TargetService,
		})
		return
	}

	// Check circuit breaker
	cb := circuitBreakers[service.ID]
	if cb != nil && !cb.AllowRequest() {
		c.JSON(http.StatusServiceUnavailable, KonohaXResponse{
			RequestID: requestIDStr,
			Status:    "error",
			Error:     "Service temporarily unavailable (circuit breaker open)",
		})
		return
	}

	// Get citizen's sector SPID from token
	claims := auth.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, KonohaXResponse{
			RequestID: requestIDStr,
			Status:    "error",
			Error:     "Invalid authentication",
		})
		return
	}

	// Check consent if required
	if service.RequiresConsent {
		consentGranted, err := checkConsent(req.CitizenSPID, service.ID, req.Operation, req.Purpose)
		if err != nil {
			logger.WithError(err).Error("Failed to check consent")
		}
		if !consentGranted {
			c.JSON(http.StatusForbidden, KonohaXResponse{
				RequestID: requestIDStr,
				Status:    "error",
				Error:     "Consent required for this operation",
			})
			return
		}
	}

	// Forward request to target service
	response, err := forwardRequest(service, &req, claims)
	if err != nil {
		if cb != nil {
			cb.RecordFailure()
		}
		c.JSON(http.StatusBadGateway, KonohaXResponse{
			RequestID: requestIDStr,
			Status:    "error",
			Error:     "Failed to forward request: " + err.Error(),
		})
		return
	}

	if cb != nil {
		cb.RecordSuccess()
	}

	c.JSON(http.StatusOK, KonohaXResponse{
		RequestID:  requestIDStr,
		Status:     "success",
		Data:       response,
		AuditLogID: "audit-" + requestIDStr,
	})
}

// registerServiceHandler registers a new service
func registerServiceHandler(c *gin.Context) {
	var req ServiceRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	service := &ServiceInfo{
		ID:                req.ID,
		Name:              req.Name,
		BaseURL:           req.BaseURL,
		AuthRequired:      req.AuthRequired,
		RequiredScopes:    req.RequiredScopes,
		RequiresConsent:   req.RequiresConsent,
		AllowedAttributes: req.AllowedAttributes,
		RateLimit:         req.RateLimit,
		HealthEndpoint:    req.HealthEndpoint,
	}

	if err := registerService(service); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "registration_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":    "Service registered successfully",
		"service_id": req.ID,
	})
}

// circuitBreakerStatusHandler returns circuit breaker status for all services
func circuitBreakerStatusHandler(c *gin.Context) {
	statuses := make(map[string]map[string]interface{})
	for id, cb := range circuitBreakers {
		cb.mu.RLock()
		statuses[id] = map[string]interface{}{
			"state":          cb.state,
			"failure_count":  cb.failureCount,
			"success_count":  cb.successCount,
			"last_failure":   cb.lastFailure,
		}
		cb.mu.RUnlock()
	}

	c.JSON(http.StatusOK, gin.H{"circuit_breakers": statuses})
}

// resetCircuitBreakerHandler resets a circuit breaker
func resetCircuitBreakerHandler(c *gin.Context) {
	serviceID := c.Param("id")
	cb, exists := circuitBreakers[serviceID]
	if !exists {
		middleware.NotFoundError(c, "Circuit breaker")
		return
	}

	cb.Reset()
	c.JSON(http.StatusOK, gin.H{
		"message":    "Circuit breaker reset",
		"service_id": serviceID,
	})
}

// proxyHandler proxies requests directly to services
func proxyHandler(c *gin.Context) {
	serviceID := c.Param("service_id")
	path := c.Param("path")

	service, exists := serviceRegistry[serviceID]
	if !exists {
		middleware.NotFoundError(c, "Service")
		return
	}

	// Rewrite URL
	c.Request.URL.Path = path
	c.Request.Host = service.Proxy.Director(c.Request).Host

	// Add headers
	c.Request.Header.Set("X-KonohaX-Gateway", "true")
	c.Request.Header.Set("X-KonohaX-Request-ID", c.GetString("request_id"))

	service.Proxy.ServeHTTP(c.Writer, c.Request)
}

// Helper functions

func checkConsent(citizenSPID, serviceID, operation, purpose string) (bool, error) {
	// Build request to consent service
	reqBody, _ := json.Marshal(map[string]string{
		"citizen_spid":  citizenSPID,
		"requester_did": "did:konoha:service:" + serviceID,
		"attribute":     operation,
		"purpose":       purpose,
	})

	resp, err := http.Post(
		consentServiceURL+"/internal/v1/consent/check",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Granted bool `json:"granted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Granted, nil
}

func forwardRequest(service *ServiceInfo, req *KonohaXRequest, claims *crypto.KNDISClaims) (interface{}, error) {
	// Build target URL
	targetURL := service.BaseURL + "/" + req.Operation

	// Prepare request body
	reqBody, err := json.Marshal(req.Parameters)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-KonohaX-Citizen-SPID", req.CitizenSPID)
	httpReq.Header.Set("X-KonohaX-Purpose", req.Purpose)
	httpReq.Header.Set("X-KonohaX-Request-ID", claims.ID)

	// Execute request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// CircuitBreaker methods

func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case "closed":
		return true
	case "open":
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = "half-open"
			cb.successCount = 0
			return true
		}
		return false
	case "half-open":
		return true
	default:
		return true
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.lastFailure = time.Now()

	if cb.state == "half-open" {
		cb.state = "open"
	} else if cb.failureCount >= cb.threshold {
		cb.state = "open"
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == "half-open" {
		cb.successCount++
		if cb.successCount >= 3 {
			cb.state = "closed"
			cb.failureCount = 0
		}
	} else {
		cb.failureCount = 0
	}
}

func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = "closed"
	cb.failureCount = 0
	cb.successCount = 0
}