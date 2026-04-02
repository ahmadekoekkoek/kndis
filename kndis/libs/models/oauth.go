package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuth2 grant types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
)

// Response types
const (
	ResponseTypeCode  = "code"
	ResponseTypeToken = "token"
	ResponseTypeIDToken = "id_token"
)

// PKCE methods
const (
	PKCEMethodS256 = "S256"
	PKCEMethodPlain = "plain"
)

// Client represents an OAuth2/OIDC client
type Client struct {
	ID                      string    `json:"client_id" gorm:"primaryKey"`
	Secret                  string    `json:"-"` // Hashed secret
	Name                    string    `json:"client_name"`
	RedirectURIs            []string  `json:"redirect_uris" gorm:"serializer:json"`
	AllowedGrantTypes       []string  `json:"grant_types" gorm:"serializer:json"`
	AllowedResponseTypes    []string  `json:"response_types" gorm:"serializer:json"`
	AllowedScopes           []string  `json:"scopes" gorm:"serializer:json"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	Sector                  string    `json:"sector"`
	LogoURI                 string    `json:"logo_uri,omitempty"`
	PolicyURI               string    `json:"policy_uri,omitempty"`
	TOSURI                  string    `json:"tos_uri,omitempty"`
	Active                  bool      `json:"active" gorm:"default:true"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// ValidateRedirectURI checks if a redirect URI is registered for the client
func (c *Client) ValidateRedirectURI(uri string) bool {
	for _, registered := range c.RedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

// ValidateScope checks if all requested scopes are allowed for the client
func (c *Client) ValidateScope(scopes []string) bool {
	allowed := make(map[string]bool)
	for _, s := range c.AllowedScopes {
		allowed[s] = true
	}

	for _, s := range scopes {
		if !allowed[s] {
			return false
		}
	}
	return true
}

// ValidateGrantType checks if the grant type is allowed
func (c *Client) ValidateGrantType(grantType string) bool {
	for _, gt := range c.AllowedGrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ResponseType        string `form:"response_type" binding:"required,oneof=code"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required,url"`
	Scope               string `form:"scope" binding:"required"`
	State               string `form:"state" binding:"required,min=16"`
	CodeChallenge       string `form:"code_challenge" binding:"required"`
	CodeChallengeMethod string `form:"code_challenge_method" binding:"required,oneof=S256"`
	Nonce               string `form:"nonce" binding:"required,min=16"`
	Prompt              string `form:"prompt" binding:"omitempty,oneof=none login consent select_account"`
	LoginHint           string `form:"login_hint"`
}

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required,oneof=authorization_code refresh_token"`
	Code         string `form:"code"`          // For authorization_code grant
	RedirectURI  string `form:"redirect_uri"`  // For authorization_code grant
	CodeVerifier string `form:"code_verifier"` // For PKCE
	RefreshToken string `form:"refresh_token"` // For refresh_token grant
	Scope        string `form:"scope"`         // Optional scope for refresh
	ClientID     string `form:"client_id"`     // For client authentication
}

// AuthorizationCode represents a stored authorization code
type AuthorizationCode struct {
	Code                string    `json:"code" gorm:"primaryKey"`
	ClientID            string    `json:"client_id"`
	CitizenSPID         string    `json:"citizen_spid"`
	Sector              string    `json:"sector"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Nonce               string    `json:"nonce"`
	AuthTime            time.Time `json:"auth_time"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used" gorm:"default:false"`
	CreatedAt           time.Time `json:"created_at"`
}

// IsExpired checks if the authorization code has expired
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// ValidatePKCE validates the code verifier against the code challenge
func (ac *AuthorizationCode) ValidatePKCE(verifier string) bool {
	// In production, implement proper S256 validation
	// For demo, simplified validation
	return ac.CodeChallenge != "" && verifier != ""
}

// NewAuthorizationCode creates a new authorization code
func NewAuthorizationCode(clientID, citizenSPID, sector, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce string) *AuthorizationCode {
	return &AuthorizationCode{
		Code:                uuid.New().String(),
		ClientID:            clientID,
		CitizenSPID:         citizenSPID,
		Sector:              sector,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		AuthTime:            time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
		CreatedAt:           time.Now(),
	}
}

// RefreshToken represents a stored refresh token
type RefreshToken struct {
	Token       string    `json:"token" gorm:"primaryKey"`
	ClientID    string    `json:"client_id"`
	CitizenSPID string    `json:"citizen_spid"`
	Sector      string    `json:"sector"`
	Scope       string    `json:"scope"`
	AuthTime    time.Time `json:"auth_time"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revoked     bool      `json:"revoked" gorm:"default:false"`
	CreatedAt   time.Time `json:"created_at"`
}

// IsExpired checks if the refresh token has expired
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// NewRefreshToken creates a new refresh token
func NewRefreshToken(clientID, citizenSPID, sector, scope string, ttl time.Duration) *RefreshToken {
	return &RefreshToken{
		Token:       uuid.New().String(),
		ClientID:    clientID,
		CitizenSPID: citizenSPID,
		Sector:      sector,
		Scope:       scope,
		AuthTime:    time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
		Revoked:     false,
		CreatedAt:   time.Now(),
	}
}

// OIDCUserInfo represents OIDC user info claims
type OIDCUserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Website           string `json:"website,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
	PhoneNumber       string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`
	Address           *Address `json:"address,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	
	// KNDIS-specific claims
	Nationality string `json:"nationality,omitempty"`
	SectorSPID  string `json:"sector_spid,omitempty"`
}

// Address represents a physical address
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// JWKSResponse represents a JSON Web Key Set response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"` // RSA modulus
	E   string `json:"e,omitempty"` // RSA exponent
	X   string `json:"x,omitempty"` // EC x coordinate
	Y   string `json:"y,omitempty"` // EC y coordinate
	Crv string `json:"crv,omitempty"` // EC curve
}

// OpenIDConfiguration represents the OIDC discovery document
type OpenIDConfiguration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                    string   `json:"authorization_endpoint"`
	TokenEndpoint                            string   `json:"token_endpoint"`
	UserInfoEndpoint                         string   `json:"userinfo_endpoint"`
	JWKSURI                                  string   `json:"jwks_uri"`
	RegistrationEndpoint                     string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                          []string `json:"scopes_supported"`
	ResponseTypesSupported                   []string `json:"response_types_supported"`
	GrantTypesSupported                      []string `json:"grant_types_supported"`
	ACRValuesSupported                       []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                    []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported         []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported        []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                          []string `json:"claims_supported"`
	RequestURIParameterSupported             bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration            bool     `json:"require_request_uri_registration"`
	CodeChallengeMethodsSupported            []string `json:"code_challenge_methods_supported"`
}

// OAuth2Error represents an OAuth2 error response
type OAuth2Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// Error implements the error interface
func (e *OAuth2Error) Error() string {
	return e.ErrorDescription
}

// Session represents an authenticated user session
type Session struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	CitizenSPID string    `json:"citizen_spid"`
	Sector      string    `json:"sector"`
	AuthTime    time.Time `json:"auth_time"`
	AMR         []string  `json:"amr" gorm:"serializer:json"`
	ACR         string    `json:"acr"`
	Active      bool      `json:"active" gorm:"default:true"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// NewSession creates a new session
func NewSession(citizenSPID, sector, acr string, amr []string, ttl time.Duration) *Session {
	return &Session{
		ID:          uuid.New().String(),
		CitizenSPID: citizenSPID,
		Sector:      sector,
		AuthTime:    time.Now(),
		AMR:         amr,
		ACR:         acr,
		Active:      true,
		ExpiresAt:   time.Now().Add(ttl),
		CreatedAt:   time.Now(),
	}
}