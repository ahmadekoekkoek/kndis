// SPID Service - Sector Pseudonymous ID Generator
// Implements HMAC-SHA256 based SPID derivation as per KNDIS blueprint
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/konoha/kndis/libs/crypto"
	"github.com/konoha/kndis/libs/middleware"
	"github.com/sirupsen/logrus"
)

var (
	spidGenerator *crypto.SPIDGenerator
	logger        *logrus.Logger
)

// SPIDRequest represents a request to generate a SPID
type SPIDRequest struct {
	NINHash           string `json:"nin_hash" binding:"required"`
	Sector            string `json:"sector" binding:"required"`
	RequestID         string `json:"request_id" binding:"required"`
	RequestingService string `json:"requesting_service" binding:"required"`
}

// SPIDResponse represents a SPID generation response
type SPIDResponse struct {
	SPID        string `json:"spid"`
	Sector      string `json:"sector"`
	GeneratedAt int64  `json:"generated_at"`
}

// BatchSPIDRequest represents a batch SPID generation request
type BatchSPIDRequest struct {
	Requests []SPIDRequest `json:"requests" binding:"required,min=1,max=100"`
}

// BatchSPIDResponse represents a batch SPID generation response
type BatchSPIDResponse struct {
	Results []SPIDResult `json:"results"`
}

// SPIDResult represents a single result in a batch response
type SPIDResult struct {
	RequestID string       `json:"request_id"`
	Success   bool         `json:"success"`
	SPID      string       `json:"spid,omitempty"`
	Error     string       `json:"error,omitempty"`
}

// ValidateSPIDRequest represents a request to validate a SPID
type ValidateSPIDRequest struct {
	SPID   string `json:"spid" binding:"required"`
	Sector string `json:"sector" binding:"required"`
}

// RotateSPIDRequest represents a request to rotate a SPID
type RotateSPIDRequest struct {
	NINHash   string `json:"nin_hash" binding:"required"`
	Sector    string `json:"sector" binding:"required"`
	OldSPID   string `json:"old_spid" binding:"required"`
	RequestID string `json:"request_id" binding:"required"`
}

// ResolveSPIDRequest represents a request to resolve a SPID to NIN hash
// This is a privileged operation requiring special authorization
type ResolveSPIDRequest struct {
	SPID            string `json:"spid" binding:"required"`
	Sector          string `json:"sector" binding:"required"`
	Justification   string `json:"justification" binding:"required"`
	CourtOrderID    string `json:"court_order_id,omitempty"`
	RequestID       string `json:"request_id" binding:"required"`
	RequestingService string `json:"requesting_service" binding:"required"`
}

// ResolveSPIDResponse represents a SPID resolution response
type ResolveSPIDResponse struct {
	NINHash       string `json:"nin_hash"`
	Found         bool   `json:"found"`
	ResolutionID  string `json:"resolution_id"`
}

// SectorInfo represents information about a sector
type SectorInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
	Description string `json:"description"`
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Initialize SPID generator with sector keys
	// In production, these keys would be stored in HSM
	sectorKeys := map[string][]byte{
		crypto.SectorHealth:    []byte("demo-health-key-32bytes-long!!"),
		crypto.SectorTax:       []byte("demo-tax-key-32bytes-long!!!!!"),
		crypto.SectorBanking:   []byte("demo-banking-key-32bytes-long!"),
		crypto.SectorVoting:    []byte("demo-voting-key-32bytes-long!!"),
		crypto.SectorEducation: []byte("demo-edu-key-32bytes-long!!!!!"),
		crypto.SectorTelecom:   []byte("demo-telecom-key-32bytes-long!"),
		crypto.SectorTravel:    []byte("demo-travel-key-32bytes-long!!"),
	}

	spidGenerator = crypto.NewSPIDGenerator(sectorKeys)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
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

	// SPID generation endpoints
	v1 := r.Group("/v1")
	{
		// Single SPID generation
		v1.POST("/spid/generate", generateSPIDHandler)

		// Batch SPID generation
		v1.POST("/spid/batch", batchGenerateSPIDHandler)

		// SPID validation
		v1.POST("/spid/validate", validateSPIDHandler)

		// SPID rotation (privileged)
		v1.POST("/spid/rotate", rotateSPIDHandler)

		// SPID resolution (highly privileged)
		v1.POST("/spid/resolve", resolveSPIDHandler)

		// Sector information
		v1.GET("/sectors", listSectorsHandler)
		v1.GET("/sectors/:id", getSectorHandler)
	}

	logger.Infof("SPID Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server:", err)
	}
}

// healthHandler returns health status
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "spid-service",
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
		"service":         "spid-service",
		"spids_generated": 0, // In production, track actual metrics
		"sectors_active":  7,
	})
}

// generateSPIDHandler generates a single SPID
func generateSPIDHandler(c *gin.Context) {
	var req SPIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Validate sector
	if !isValidSector(req.Sector) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_sector",
			"message": "Unknown or unsupported sector",
		})
		return
	}

	// In production, this would:
	// 1. Authenticate the requesting service
	// 2. Log the request to audit log
	// 3. Send the HMAC operation to HSM
	// 4. Return only the SPID (key never leaves HSM)

	// For demo, we use the local SPID generator
	// Note: In production, the NIN would come from CIV, not from hash
	nin := "demo-nin-" + req.NINHash[:8]
	spid, err := spidGenerator.GenerateSPID(nin, req.Sector)
	if err != nil {
		logger.WithError(err).Error("Failed to generate SPID")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "generation_failed",
			"message": "Failed to generate SPID",
		})
		return
	}

	logger.WithFields(logrus.Fields{
		"request_id":         req.RequestID,
		"requesting_service": req.RequestingService,
		"sector":             req.Sector,
	}).Info("SPID generated")

	c.JSON(http.StatusOK, SPIDResponse{
		SPID:        spid,
		Sector:      req.Sector,
		GeneratedAt: time.Now().Unix(),
	})
}

// batchGenerateSPIDHandler generates multiple SPIDs in a batch
func batchGenerateSPIDHandler(c *gin.Context) {
	var req BatchSPIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	results := make([]SPIDResult, 0, len(req.Requests))

	for _, r := range req.Requests {
		if !isValidSector(r.Sector) {
			results = append(results, SPIDResult{
				RequestID: r.RequestID,
				Success:   false,
				Error:     "invalid_sector",
			})
			continue
		}

		nin := "demo-nin-" + r.NINHash[:8]
		spid, err := spidGenerator.GenerateSPID(nin, r.Sector)
		if err != nil {
			results = append(results, SPIDResult{
				RequestID: r.RequestID,
				Success:   false,
				Error:     err.Error(),
			})
			continue
		}

		results = append(results, SPIDResult{
			RequestID: r.RequestID,
			Success:   true,
			SPID:      spid,
		})
	}

	logger.WithField("batch_size", len(req.Requests)).Info("Batch SPID generation completed")

	c.JSON(http.StatusOK, BatchSPIDResponse{Results: results})
}

// validateSPIDHandler validates a SPID format
func validateSPIDHandler(c *gin.Context) {
	var req ValidateSPIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	valid := crypto.ValidateSPID(req.SPID, req.Sector)

	c.JSON(http.StatusOK, gin.H{
		"valid":   valid,
		"spid":    req.SPID,
		"sector":  req.Sector,
	})
}

// rotateSPIDHandler rotates a citizen's SPID for a sector
func rotateSPIDHandler(c *gin.Context) {
	var req RotateSPIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// In production:
	// 1. Verify the old SPID belongs to the citizen
	// 2. Generate new SPID with new epoch salt
	// 3. Mark old SPID for deprecation (30-day transition)
	// 4. Notify service providers via webhook
	// 5. Log to audit log

	// For demo, just generate a new SPID
	nin := "demo-nin-" + req.NINHash[:8]
	newSPID, err := spidGenerator.GenerateSPID(nin, req.Sector)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "rotation_failed",
			"message": "Failed to rotate SPID",
		})
		return
	}

	logger.WithFields(logrus.Fields{
		"old_spid":   req.OldSPID,
		"new_spid":   newSPID,
		"sector":     req.Sector,
		"request_id": req.RequestID,
	}).Info("SPID rotated")

	c.JSON(http.StatusOK, gin.H{
		"old_spid":        req.OldSPID,
		"new_spid":        newSPID,
		"sector":          req.Sector,
		"transition_days": 30,
		"rotated_at":      time.Now().Unix(),
	})
}

// resolveSPIDHandler resolves a SPID to NIN hash (privileged operation)
func resolveSPIDHandler(c *gin.Context) {
	var req ResolveSPIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// In production, this would:
	// 1. Require multi-party authorization (3-of-5)
	// 2. Require court order or legal justification
	// 3. Log to immutable audit log
	// 4. Alert citizen within 24 hours
	// 5. Generate resolution ID for tracking

	// For demo, return a mock response
	resolutionID := fmt.Sprintf("res-%d", time.Now().Unix())

	logger.WithFields(logrus.Fields{
		"spid":             req.SPID,
		"sector":           req.Sector,
		"justification":    req.Justification,
		"court_order_id":   req.CourtOrderID,
		"requesting_service": req.RequestingService,
		"resolution_id":    resolutionID,
	}).Warn("SPID resolution performed - HIGH PRIVILEGE OPERATION")

	// Return mock NIN hash (in production, this would come from CIV)
	mockNINHash := "sha256-" + strings.Repeat("a", 64)

	c.JSON(http.StatusOK, ResolveSPIDResponse{
		NINHash:      mockNINHash,
		Found:        true,
		ResolutionID: resolutionID,
	})
}

// listSectorsHandler lists all available sectors
func listSectorsHandler(c *gin.Context) {
	sectors := []SectorInfo{
		{ID: crypto.SectorHealth, Name: "Health", Prefix: "H-", Description: "Healthcare and medical services"},
		{ID: crypto.SectorTax, Name: "Tax", Prefix: "T-", Description: "Revenue and taxation"},
		{ID: crypto.SectorBanking, Name: "Banking", Prefix: "B-", Description: "Financial services"},
		{ID: crypto.SectorVoting, Name: "Voting", Prefix: "V-", Description: "Electoral services"},
		{ID: crypto.SectorEducation, Name: "Education", Prefix: "E-", Description: "Educational institutions"},
		{ID: crypto.SectorTelecom, Name: "Telecom", Prefix: "K-", Description: "Telecommunications"},
		{ID: crypto.SectorTravel, Name: "Travel", Prefix: "P-", Description: "Passport and immigration"},
	}

	c.JSON(http.StatusOK, gin.H{
		"sectors": sectors,
		"count":   len(sectors),
	})
}

// getSectorHandler gets information about a specific sector
func getSectorHandler(c *gin.Context) {
	sectorID := c.Param("id")

	sectorMap := map[string]SectorInfo{
		crypto.SectorHealth:    {ID: crypto.SectorHealth, Name: "Health", Prefix: "H-", Description: "Healthcare and medical services"},
		crypto.SectorTax:       {ID: crypto.SectorTax, Name: "Tax", Prefix: "T-", Description: "Revenue and taxation"},
		crypto.SectorBanking:   {ID: crypto.SectorBanking, Name: "Banking", Prefix: "B-", Description: "Financial services"},
		crypto.SectorVoting:    {ID: crypto.SectorVoting, Name: "Voting", Prefix: "V-", Description: "Electoral services"},
		crypto.SectorEducation: {ID: crypto.SectorEducation, Name: "Education", Prefix: "E-", Description: "Educational institutions"},
		crypto.SectorTelecom:   {ID: crypto.SectorTelecom, Name: "Telecom", Prefix: "K-", Description: "Telecommunications"},
		crypto.SectorTravel:    {ID: crypto.SectorTravel, Name: "Travel", Prefix: "P-", Description: "Passport and immigration"},
	}

	sector, exists := sectorMap[sectorID]
	if !exists {
		middleware.NotFoundError(c, "Sector")
		return
	}

	c.JSON(http.StatusOK, sector)
}

// isValidSector checks if a sector is valid
func isValidSector(sector string) bool {
	validSectors := map[string]bool{
		crypto.SectorHealth:    true,
		crypto.SectorTax:       true,
		crypto.SectorBanking:   true,
		crypto.SectorVoting:    true,
		crypto.SectorEducation: true,
		crypto.SectorTelecom:   true,
		crypto.SectorTravel:    true,
	}
	return validSectors[sector]
}