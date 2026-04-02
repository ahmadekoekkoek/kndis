// Package middleware provides common HTTP middleware
package middleware

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// LoggerConfig holds logger middleware configuration
type LoggerConfig struct {
	Logger *logrus.Logger
	// SkipPaths lists paths to skip logging
	SkipPaths []string
}

// DefaultLoggerConfig returns a default logger configuration
func DefaultLoggerConfig() *LoggerConfig {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	return &LoggerConfig{
		Logger:    logger,
		SkipPaths: []string{"/health", "/metrics"},
	}
}

// Logger returns a Gin middleware for structured logging
func Logger(config *LoggerConfig) gin.HandlerFunc {
	skipMap := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipMap[path] = true
	}

	return func(c *gin.Context) {
		// Skip logging for health checks
		if skipMap[c.Request.URL.Path] {
			c.Next()
			return
		}

		// Generate request ID if not present
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
			c.Header("X-Request-ID", requestID)
		}
		c.Set("request_id", requestID)

		// Capture request body for logging (if needed)
		var requestBody []byte
		if c.Request.Body != nil && c.Request.ContentLength < 1024*1024 { // 1MB limit
			requestBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log after request completes
		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		userAgent := c.Request.UserAgent()

		if raw != "" {
			path = path + "?" + raw
		}

		entry := config.Logger.WithFields(logrus.Fields{
			"request_id":     requestID,
			"client_ip":      clientIP,
			"method":         method,
			"path":           path,
			"status":         statusCode,
			"latency_ms":     float64(latency.Nanoseconds()) / 1e6,
			"user_agent":     userAgent,
			"correlation_id": c.GetHeader("X-Correlation-ID"),
		})

		// Add error information if present
		if len(c.Errors) > 0 {
			entry = entry.WithField("errors", c.Errors.String())
		}

		// Add user context if available
		if subject, exists := c.Get("subject"); exists {
			entry = entry.WithField("subject", subject)
		}
		if sector, exists := c.Get("sector"); exists {
			entry = entry.WithField("sector", sector)
		}

		// Log at appropriate level
		switch {
		case statusCode >= 500:
			entry.Error("Server error")
		case statusCode >= 400:
			entry.Warn("Client error")
		default:
			entry.Info("Request completed")
		}
	}
}

// Recovery returns a Gin recovery middleware with custom logging
func Recovery(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				requestID, _ := c.Get("request_id")
				logger.WithFields(logrus.Fields{
					"request_id": requestID,
					"error":      err,
					"stack":      string(stack(3)),
				}).Error("Panic recovered")

				c.AbortWithStatusJSON(500, gin.H{
					"error":             "server_error",
					"error_description": "Internal server error",
					"request_id":        requestID,
				})
			}
		}()
		c.Next()
	}
}

// stack returns the current stack trace
func stack(skip int) []byte {
	// Simplified stack trace - in production, use proper stack trace library
	return []byte("stack trace not implemented in demo")
}

// RequestIDMiddleware ensures every request has a request ID
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// CORSMiddleware configures CORS headers
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if origin is allowed
		allowed := false
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Request-ID, DPoP")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		c.Next()
	}
}

// TimingMiddleware adds timing information to responses
func TimingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)
		c.Header("X-Response-Time", duration.String())
	}
}

// VersionMiddleware adds API version header
func VersionMiddleware(version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-API-Version", version)
		c.Next()
	}
}