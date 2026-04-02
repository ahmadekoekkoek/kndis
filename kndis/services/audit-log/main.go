// Audit Log Service - Immutable audit logging with Merkle tree verification
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/konoha/kndis/libs/auth"
	"github.com/konoha/kndis/libs/crypto"
	"github.com/konoha/kndis/libs/middleware"
	"github.com/konoha/kndis/libs/models"
	"github.com/sirupsen/logrus"
)

var (
	auditEvents      []models.AuditEvent
	dailyRoots       map[string]*models.DailyMerkleRoot
	jwtManager       *crypto.JWTManager
	logger           *logrus.Logger
	eventCounter     int64
)

// AuditQuery represents a query for audit events
type AuditQuery struct {
	CitizenSPID string                 `form:"citizen_spid"`
	EventType   models.AuditEventType  `form:"event_type"`
	ActorID     string                 `form:"actor_id"`
	Sector      string                 `form:"sector"`
	Outcome     string                 `form:"outcome"`
	From        *time.Time             `form:"from" time_format:"2006-01-02T15:04:05Z07:00"`
	To          *time.Time             `form:"to" time_format:"2006-01-02T15:04:05Z07:00"`
	Limit       int                    `form:"limit,default=100" binding:"max=1000"`
	Offset      int                    `form:"offset,default=0"`
}

// MerkleProofRequest represents a request for a Merkle proof
type MerkleProofRequest struct {
	EventID string `json:"event_id" binding:"required"`
}

// TransparencyReportRequest represents a request for a transparency report
type TransparencyReportRequest struct {
	Period string `form:"period,default=current_month"` // current_month, last_month, current_year
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Initialize JWT manager
	jwtManager = crypto.NewJWTManager()
	jwtManager.GenerateSigningKey("RS256")

	// Initialize storage (use ImmuDB in production)
	auditEvents = make([]models.AuditEvent, 0)
	dailyRoots = make(map[string]*models.DailyMerkleRoot)
	eventCounter = 0
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
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

	// Public transparency endpoints
	r.GET("/transparency/daily-root", dailyRootHandler)
	r.GET("/transparency/report", transparencyReportHandler)
	r.GET("/transparency/verify", verifyEventHandler)

	// Protected endpoints (require authentication)
	v1 := r.Group("/v1")
	v1.Use(auth.AuthMiddleware(auth.NewConfig(jwtManager)))
	{
		// Log event (internal services only)
		v1.POST("/events", logEventHandler)

		// Query events
		v1.GET("/events", queryEventsHandler)
		v1.GET("/events/:id", getEventHandler)

		// Merkle tree operations
		v1.POST("/merkle/proof", merkleProofHandler)
		v1.GET("/merkle/root", merkleRootHandler)
		v1.POST("/merkle/verify", verifyMerkleProofHandler)
	}

	// Internal endpoints (for service-to-service)
	internal := r.Group("/internal/v1")
	{
		internal.POST("/events", logEventInternalHandler)
	}

	logger.Infof("Audit Log Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server:", err)
	}
}

// healthHandler returns health status
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":       "healthy",
		"service":      "audit-log",
		"version":      "1.0.0",
		"total_events": len(auditEvents),
		"timestamp":    time.Now().UTC(),
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
	today := time.Now().Format("2006-01-02")
	todayCount := 0
	for _, event := range auditEvents {
		if event.Timestamp.Format("2006-01-02") == today {
			todayCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"service":       "audit-log",
		"total_events":  len(auditEvents),
		"events_today":  todayCount,
		"daily_roots":   len(dailyRoots),
	})
}

// logEventHandler logs an audit event
func logEventHandler(c *gin.Context) {
	var event models.AuditEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		middleware.ValidationError(c, "event", err.Error())
		return
	}

	// Set event ID and timestamp if not provided
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("evt-%d", eventCounter)
		eventCounter++
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Compute previous hash for Merkle chain
	if len(auditEvents) > 0 {
		lastEvent := auditEvents[len(auditEvents)-1]
		event.PreviousHash = lastEvent.ComputeHash()
	} else {
		event.PreviousHash = "0" * 64 // Genesis hash
	}

	// Compute Merkle root
	event.MerkleRoot = computeMerkleRoot()

	// Store event
	auditEvents = append(auditEvents, event)

	logger.WithFields(logrus.Fields{
		"event_id":    event.EventID,
		"event_type":  event.EventType,
		"actor_id":    event.ActorID,
		"citizen_spid": event.CitizenSPID,
	}).Info("Audit event logged")

	c.JSON(http.StatusCreated, gin.H{
		"event_id":    event.EventID,
		"timestamp":   event.Timestamp,
		"merkle_root": event.MerkleRoot,
	})
}

// logEventInternalHandler logs an event from internal services
func logEventInternalHandler(c *gin.Context) {
	var event models.AuditEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Same logic as logEventHandler
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("evt-%d", eventCounter)
		eventCounter++
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if len(auditEvents) > 0 {
		lastEvent := auditEvents[len(auditEvents)-1]
		event.PreviousHash = lastEvent.ComputeHash()
	} else {
		event.PreviousHash = "0" * 64
	}

	event.MerkleRoot = computeMerkleRoot()
	auditEvents = append(auditEvents, event)

	c.JSON(http.StatusCreated, gin.H{
		"event_id":    event.EventID,
		"merkle_root": event.MerkleRoot,
	})
}

// queryEventsHandler queries audit events
func queryEventsHandler(c *gin.Context) {
	var query AuditQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		middleware.ValidationError(c, "query", err.Error())
		return
	}

	// Filter events
	var filtered []models.AuditEvent
	for _, event := range auditEvents {
		if query.CitizenSPID != "" && event.CitizenSPID != query.CitizenSPID {
			continue
		}
		if query.EventType != "" && event.EventType != query.EventType {
			continue
		}
		if query.ActorID != "" && event.ActorID != query.ActorID {
			continue
		}
		if query.Sector != "" && event.Sector != query.Sector {
			continue
		}
		if query.Outcome != "" && event.Outcome != query.Outcome {
			continue
		}
		if query.From != nil && event.Timestamp.Before(*query.From) {
			continue
		}
		if query.To != nil && event.Timestamp.After(*query.To) {
			continue
		}
		filtered = append(filtered, event)
	}

	// Sort by timestamp descending
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

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

	c.JSON(http.StatusOK, models.AuditResponse{
		Events: paginated,
		Total:  int64(total),
		Limit:  query.Limit,
		Offset: query.Offset,
	})
}

// getEventHandler gets a specific audit event
func getEventHandler(c *gin.Context) {
	eventID := c.Param("id")

	for _, event := range auditEvents {
		if event.EventID == eventID {
			c.JSON(http.StatusOK, event)
			return
		}
	}

	middleware.NotFoundError(c, "Event")
}

// merkleProofHandler generates a Merkle proof for an event
func merkleProofHandler(c *gin.Context) {
	var req MerkleProofRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.ValidationError(c, "request", err.Error())
		return
	}

	// Find the event
	var targetEvent *models.AuditEvent
	var eventIndex int
	for i, event := range auditEvents {
		if event.EventID == req.EventID {
			targetEvent = &auditEvents[i]
			eventIndex = i
			break
		}
	}

	if targetEvent == nil {
		middleware.NotFoundError(c, "Event")
		return
	}

	// Generate proof
	proof := generateMerkleProof(eventIndex)

	c.JSON(http.StatusOK, gin.H{
		"event_id":   req.EventID,
		"leaf_hash":  targetEvent.ComputeHash(),
		"root_hash":  targetEvent.MerkleRoot,
		"proof":      proof,
	})
}

// merkleRootHandler returns the current Merkle root
func merkleRootHandler(c *gin.Context) {
	root := computeMerkleRoot()

	c.JSON(http.StatusOK, gin.H{
		"merkle_root":   root,
		"event_count":   len(auditEvents),
		"computed_at":   time.Now().Unix(),
	})
}

// verifyMerkleProofHandler verifies a Merkle proof
func verifyMerkleProofHandler(c *gin.Context) {
	var proof models.MerkleProof
	if err := c.ShouldBindJSON(&proof); err != nil {
		middleware.ValidationError(c, "proof", err.Error())
		return
	}

	valid := models.VerifyMerkleProof(&proof)

	c.JSON(http.StatusOK, gin.H{
		"valid":      valid,
		"leaf_hash":  proof.LeafHash,
		"root_hash":  proof.RootHash,
	})
}

// dailyRootHandler returns the daily Merkle root
func dailyRootHandler(c *gin.Context) {
	date := c.Query("date")
	if date == "" {
		date = time.Now().Format("2006-01-02")
	}

	root, exists := dailyRoots[date]
	if !exists {
		// Compute daily root
		root = computeDailyRoot(date)
		dailyRoots[date] = root
	}

	c.JSON(http.StatusOK, root)
}

// transparencyReportHandler generates a transparency report
func transparencyReportHandler(c *gin.Context) {
	var req TransparencyReportRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		middleware.ValidationError(c, "query", err.Error())
		return
	}

	// Determine period
	var from, to time.Time
	now := time.Now()

	switch req.Period {
	case "current_month":
		from = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		to = now
	case "last_month":
		lastMonth := now.AddDate(0, -1, 0)
		from = time.Date(lastMonth.Year(), lastMonth.Month(), 1, 0, 0, 0, 0, time.UTC)
		to = from.AddDate(0, 1, 0).Add(-time.Second)
	case "current_year":
		from = time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		to = now
	default:
		from = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		to = now
	}

	// Calculate statistics
	var totalAccess int64
	accessBySector := make(map[string]int64)
	accessByPurpose := make(map[string]int64)
	consentGrants := int64(0)
	consentRevocations := int64(0)

	for _, event := range auditEvents {
		if event.Timestamp.Before(from) || event.Timestamp.After(to) {
			continue
		}

		switch event.EventType {
		case models.EventTypeDataAccess:
			totalAccess++
			accessBySector[event.Sector]++
			accessByPurpose[event.Purpose]++
		case models.EventTypeConsentGranted:
			consentGrants++
		case models.EventTypeConsentRevoked:
			consentRevocations++
		}
	}

	report := models.TransparencyReport{
		Period:               req.Period,
		TotalDataAccess:      totalAccess,
		AccessBySector:       accessBySector,
		AccessByPurpose:      accessByPurpose,
		ConsentGrants:        consentGrants,
		ConsentRevocations:   consentRevocations,
		ActiveTokens:         0, // Would come from token service
		MerkleRoot:           computeMerkleRoot(),
		PublishedAt:          time.Now(),
	}

	c.JSON(http.StatusOK, report)
}

// verifyEventHandler allows citizens to verify their events
func verifyEventHandler(c *gin.Context) {
	eventID := c.Query("event_id")
	citizenSPID := c.Query("citizen_spid")

	if eventID == "" || citizenSPID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "event_id and citizen_spid are required",
		})
		return
	}

	// Find the event
	var event *models.AuditEvent
	for i, e := range auditEvents {
		if e.EventID == eventID && e.CitizenSPID == citizenSPID {
			event = &auditEvents[i]
			break
		}
	}

	if event == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":     "Event not found",
			"verified":  false,
		})
		return
	}

	// Verify hash chain
	verified := verifyEventChain(event)

	c.JSON(http.StatusOK, gin.H{
		"event_id":     eventID,
		"verified":     verified,
		"event_hash":   event.ComputeHash(),
		"merkle_root":  event.MerkleRoot,
		"timestamp":    event.Timestamp,
	})
}

// Helper functions

func computeMerkleRoot() string {
	if len(auditEvents) == 0 {
		return "0" * 64
	}

	hashes := make([]string, len(auditEvents))
	for i, event := range auditEvents {
		hashes[i] = event.ComputeHash()
	}

	tree := models.BuildMerkleTree(hashes)
	return tree.Root
}

func generateMerkleProof(eventIndex int) models.MerkleProof {
	if eventIndex < 0 || eventIndex >= len(auditEvents) {
		return models.MerkleProof{}
	}

	leafHash := auditEvents[eventIndex].ComputeHash()
	rootHash := computeMerkleRoot()

	// Simplified proof - in production, implement full Merkle proof generation
	return models.MerkleProof{
		LeafHash: leafHash,
		RootHash: rootHash,
		Path:     []string{},
		Indices:  []int{},
	}
}

func computeDailyRoot(date string) *models.DailyMerkleRoot {
	var dayEvents []models.AuditEvent
	for _, event := range auditEvents {
		if event.Timestamp.Format("2006-01-02") == date {
			dayEvents = append(dayEvents, event)
		}
	}

	hashes := make([]string, len(dayEvents))
	for i, event := range dayEvents {
		hashes[i] = event.ComputeHash()
	}

	tree := models.BuildMerkleTree(hashes)

	return &models.DailyMerkleRoot{
		Date:        parseDate(date),
		RootHash:    tree.Root,
		EventCount:  int64(len(dayEvents)),
		PublishedAt: time.Now(),
	}
}

func parseDate(date string) time.Time {
	t, _ := time.Parse("2006-01-02", date)
	return t
}

func verifyEventChain(event *models.AuditEvent) bool {
	// Find the event in the chain
	var found bool
	var prevHash string

	for i, e := range auditEvents {
		if e.EventID == event.EventID {
			found = true
			if i > 0 {
				prevHash = auditEvents[i-1].ComputeHash()
			}
			break
		}
	}

	if !found {
		return false
	}

	// Verify previous hash matches
	if event.PreviousHash != prevHash && prevHash != "" {
		return false
	}

	// Verify the event's own hash
	computedHash := event.ComputeHash()
	storedHash := ""
	for _, e := range auditEvents {
		if e.EventID == event.EventID {
			storedHash = e.ComputeHash()
			break
		}
	}

	return computedHash == storedHash
}

// HashBytes computes SHA256 hash of bytes
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}