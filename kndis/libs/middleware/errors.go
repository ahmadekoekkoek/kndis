package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
}

// OAuth2 error codes as per RFC 6749
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorInvalidClient        = "invalid_client"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorUnauthorizedClient   = "unauthorized_client"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorInvalidScope         = "invalid_scope"
	ErrorAccessDenied         = "access_denied"
	ErrorServerError          = "server_error"
	ErrorTemporarilyUnavailable = "temporarily_unavailable"
)

// OIDC error codes
const (
	ErrorInteractionRequired     = "interaction_required"
	ErrorLoginRequired           = "login_required"
	ErrorAccountSelectionRequired = "account_selection_required"
	ErrorConsentRequired         = "consent_required"
	ErrorInvalidRequestURI       = "invalid_request_uri"
	ErrorInvalidRequestObject    = "invalid_request_object"
	ErrorRequestNotSupported     = "request_not_supported"
	ErrorRequestURINotSupported  = "request_uri_not_supported"
	ErrorRegistrationNotSupported = "registration_not_supported"
)

// Custom error codes for KNDIS
const (
	ErrorInvalidToken        = "invalid_token"
	ErrorInsufficientScope   = "insufficient_scope"
	ErrorInvalidDPoPProof    = "invalid_dpop_proof"
	ErrorInvalidSector       = "invalid_sector"
	ErrorConsentRequired     = "consent_required"
	ErrorRateLimitExceeded   = "rate_limit_exceeded"
	ErrorInvalidSPID         = "invalid_spid"
	ErrorSectorMismatch      = "sector_mismatch"
)

// ErrorHandler handles errors consistently across the API
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors
		if len(c.Errors) == 0 {
			return
		}

		// Get the last error
		lastError := c.Errors.Last()

		// Get request ID for error tracking
		requestID, _ := c.Get("request_id")
		requestIDStr, _ := requestID.(string)

		// Determine status code and error response
		statusCode, errorResp := mapError(lastError, requestIDStr)

		// Don't override if response already sent
		if c.Writer.Written() {
			return
		}

		c.JSON(statusCode, errorResp)
	}
}

// mapError maps internal errors to HTTP responses
func mapError(err *gin.Error, requestID string) (int, ErrorResponse) {
	errorResp := ErrorResponse{
		ErrorDescription: err.Err.Error(),
		RequestID:        requestID,
	}

	// Map error types to responses
	switch err.Type {
	case gin.ErrorTypeBind:
		errorResp.Error = ErrorInvalidRequest
		return http.StatusBadRequest, errorResp

	case gin.ErrorTypeRender:
		errorResp.Error = ErrorServerError
		return http.StatusInternalServerError, errorResp

	default:
		// Check for specific error messages
		errStr := err.Err.Error()

		switch {
		case contains(errStr, "unauthorized"):
			errorResp.Error = ErrorInvalidClient
			return http.StatusUnauthorized, errorResp

		case contains(errStr, "forbidden"), contains(errStr, "insufficient_scope"):
			errorResp.Error = ErrorInsufficientScope
			return http.StatusForbidden, errorResp

		case contains(errStr, "not found"):
			errorResp.Error = ErrorInvalidRequest
			return http.StatusNotFound, errorResp

		case contains(errStr, "rate limit"):
			errorResp.Error = ErrorRateLimitExceeded
			return http.StatusTooManyRequests, errorResp

		case contains(errStr, "invalid_token"):
			errorResp.Error = ErrorInvalidToken
			return http.StatusUnauthorized, errorResp

		case contains(errStr, "consent"):
			errorResp.Error = ErrorConsentRequired
			return http.StatusForbidden, errorResp

		default:
			errorResp.Error = ErrorServerError
			return http.StatusInternalServerError, errorResp
		}
	}
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) && (containsAt(s, substr, 0) ||
			containsAt(s, substr, 1)))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// AbortWithError aborts the request with a standard error response
func AbortWithError(c *gin.Context, status int, errCode, errDescription string) {
	requestID, _ := c.Get("request_id")
	requestIDStr, _ := requestID.(string)

	c.AbortWithStatusJSON(status, ErrorResponse{
		Error:            errCode,
		ErrorDescription: errDescription,
		RequestID:        requestIDStr,
	})
}

// OAuthError returns an OAuth2/OIDC compliant error response
func OAuthError(c *gin.Context, status int, errCode, errDescription, errURI string) {
	requestID, _ := c.Get("request_id")
	requestIDStr, _ := requestID.(string)

	c.JSON(status, ErrorResponse{
		Error:            errCode,
		ErrorDescription: errDescription,
		ErrorURI:         errURI,
		RequestID:        requestIDStr,
	})
}

// ValidationError returns a validation error response
func ValidationError(c *gin.Context, field, message string) {
	AbortWithError(c, http.StatusBadRequest, ErrorInvalidRequest,
		"Validation failed for field '"+field+"': "+message)
}

// NotFoundError returns a not found error
func NotFoundError(c *gin.Context, resource string) {
	AbortWithError(c, http.StatusNotFound, ErrorInvalidRequest,
		resource+" not found")
}

// UnauthorizedError returns an unauthorized error
func UnauthorizedError(c *gin.Context, message string) {
	if message == "" {
		message = "Authentication required"
	}
	AbortWithError(c, http.StatusUnauthorized, ErrorInvalidToken, message)
}

// ForbiddenError returns a forbidden error
func ForbiddenError(c *gin.Context, message string) {
	if message == "" {
		message = "Access denied"
	}
	AbortWithError(c, http.StatusForbidden, ErrorAccessDenied, message)
}

// RateLimitError returns a rate limit error
func RateLimitError(c *gin.Context, retryAfter int) {
	c.Header("Retry-After", string(rune(retryAfter)))
	AbortWithError(c, http.StatusTooManyRequests, ErrorRateLimitExceeded,
		"Rate limit exceeded. Retry after "+string(rune(retryAfter))+" seconds.")
}

// ServerError returns a server error
func ServerError(c *gin.Context, message string) {
	if message == "" {
		message = "Internal server error"
	}
	AbortWithError(c, http.StatusInternalServerError, ErrorServerError, message)
}