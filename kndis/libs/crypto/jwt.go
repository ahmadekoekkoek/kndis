package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenTypeID      TokenType = "id"
)

// KeyPair holds a signing key pair
type KeyPair struct {
	PrivateKey interface{}
	PublicKey  interface{}
	KeyID      string
	Algorithm  string
}

// JWTManager handles JWT signing and validation
type JWTManager struct {
	signingKeys map[string]*KeyPair // kid -> keypair
	activeKeyID string
}

// NewJWTManager creates a new JWT manager
func NewJWTManager() *JWTManager {
	return &JWTManager{
		signingKeys: make(map[string]*KeyPair),
	}
}

// GenerateSigningKey generates a new Ed25519 signing key pair
// In production, keys would be generated in HSM
func (jm *JWTManager) GenerateSigningKey(algorithm string) (*KeyPair, error) {
	kid := uuid.New().String()

	switch algorithm {
	case "RS256":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		jm.signingKeys[kid] = &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			KeyID:      kid,
			Algorithm:  algorithm,
		}

	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		jm.signingKeys[kid] = &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			KeyID:      kid,
			Algorithm:  algorithm,
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	jm.activeKeyID = kid
	return jm.signingKeys[kid], nil
}

// KNDISClaims represents the custom claims for KNDIS tokens
type KNDISClaims struct {
	jwt.RegisteredClaims
	Scope         string                 `json:"scope,omitempty"`
	Sector        string                 `json:"sector,omitempty"`
	AuthTime      int64                  `json:"auth_time,omitempty"`
	ACR           string                 `json:"acr,omitempty"`
	AMR           []string               `json:"amr,omitempty"`
	CNF           map[string]interface{} `json:"cnf,omitempty"` // DPoP confirmation
	ClientID      string                 `json:"client_id,omitempty"`
	TokenType     TokenType              `json:"token_type,omitempty"`
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// GenerateAccessToken creates a new access token
func (jm *JWTManager) GenerateAccessToken(sub, aud, scope, sector string, cnf map[string]interface{}, ttl time.Duration) (*TokenResponse, error) {
	keyPair, ok := jm.signingKeys[jm.activeKeyID]
	if !ok {
		return nil, fmt.Errorf("no active signing key")
	}

	now := time.Now()
	claims := KNDISClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			Issuer:    "https://idp.konoha.gov",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.New().String(),
		},
		Scope:     scope,
		Sector:    sector,
		AuthTime:  now.Unix(),
		ACR:       "urn:mace:incommon:iap:silver",
		AMR:       []string{"hwk"}, // FIDO2
		CNF:       cnf,
		TokenType: TokenTypeAccess,
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(keyPair.Algorithm), claims)
	token.Header["kid"] = keyPair.KeyID
	token.Header["typ"] = "at+JWT"

	tokenString, err := token.SignedString(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	return &TokenResponse{
		AccessToken: tokenString,
		TokenType:   "DPoP",
		ExpiresIn:   int(ttl.Seconds()),
		Scope:       scope,
	}, nil
}

// GenerateIDToken creates an OpenID Connect ID token
func (jm *JWTManager) GenerateIDToken(sub, aud, name, givenName, familyName, birthdate, nationality, sectorSPID string, nonce string, ttl time.Duration) (string, error) {
	keyPair, ok := jm.signingKeys[jm.activeKeyID]
	if !ok {
		return "", fmt.Errorf("no active signing key")
	}

	now := time.Now()
	claims := KNDISClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			Issuer:    "https://idp.konoha.gov",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		AuthTime: now.Unix(),
	}

	// Add OIDC claims
	token := jwt.NewWithClaims(jwt.GetSigningMethod(keyPair.Algorithm), claims)
	token.Header["kid"] = keyPair.KeyID

	// Add custom claims for OIDC
	token.Claims = &struct {
		jwt.RegisteredClaims
		Name         string `json:"name,omitempty"`
		GivenName    string `json:"given_name,omitempty"`
		FamilyName   string `json:"family_name,omitempty"`
		Birthdate    string `json:"birthdate,omitempty"`
		Nationality  string `json:"nationality,omitempty"`
		SectorSPID   string `json:"sector_spid,omitempty"`
		Nonce        string `json:"nonce,omitempty"`
	}{
		RegisteredClaims: claims.RegisteredClaims,
		Name:             name,
		GivenName:        givenName,
		FamilyName:       familyName,
		Birthdate:        birthdate,
		Nationality:      nationality,
		SectorSPID:       sectorSPID,
		Nonce:            nonce,
	}

	return token.SignedString(keyPair.PrivateKey)
}

// GenerateRefreshToken creates an opaque refresh token
// In production, this would be stored in a database with rotation
func GenerateRefreshToken() string {
	return uuid.New().String()
}

// ValidateToken validates a JWT token
func (jm *JWTManager) ValidateToken(tokenString string) (*KNDISClaims, error) {
	// Parse without validation first to get the key ID
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &KNDISClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing key ID")
	}

	keyPair, ok := jm.signingKeys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown key ID: %s", kid)
	}

	// Now validate with the correct key
	validatedToken, err := jwt.ParseWithClaims(tokenString, &KNDISClaims{}, func(token *jwt.Token) (interface{}, error) {
		return keyPair.PublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if claims, ok := validatedToken.Claims.(*KNDISClaims); ok && validatedToken.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// GetPublicKeyJWK returns the public key in JWK format
func (jm *JWTManager) GetPublicKeyJWK(kid string) (map[string]interface{}, error) {
	keyPair, ok := jm.signingKeys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown key ID: %s", kid)
	}

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": keyPair.Algorithm,
	}

	switch key := keyPair.PublicKey.(type) {
	case *rsa.PublicKey:
		jwk["n"] = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		jwk["e"] = base64.RawURLEncoding.EncodeToString(encodeInt(key.E))
	case *ecdsa.PublicKey:
		jwk["kty"] = "EC"
		jwk["crv"] = "P-256"
		jwk["x"] = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwk["y"] = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	return jwk, nil
}

// encodeInt encodes an integer to bytes
func encodeInt(n int) []byte {
	if n == 65537 {
		return []byte{0x01, 0x00, 0x01}
	}
	return []byte{byte(n)}
}

// JWKSResponse represents a JWKS (JSON Web Key Set) response
type JWKSResponse struct {
	Keys []map[string]interface{} `json:"keys"`
}

// GetJWKS returns all public keys in JWKS format
func (jm *JWTManager) GetJWKS() *JWKSResponse {
	keys := make([]map[string]interface{}, 0, len(jm.signingKeys))
	for kid := range jm.signingKeys {
		jwk, err := jm.GetPublicKeyJWK(kid)
		if err == nil {
			keys = append(keys, jwk)
		}
	}
	return &JWKSResponse{Keys: keys}
}

// ExportPublicKeyPEM exports the public key in PEM format
func (jm *JWTManager) ExportPublicKeyPEM(kid string) (string, error) {
	keyPair, ok := jm.signingKeys[kid]
	if !ok {
		return "", fmt.Errorf("unknown key ID: %s", kid)
	}

	var pubKeyBytes []byte
	var err error

	switch key := keyPair.PublicKey.(type) {
	case *rsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(key)
	case *ecdsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(key)
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// ParseTokenWithoutValidation parses a token without validating the signature
// Useful for debugging and extracting claims
func ParseTokenWithoutValidation(tokenString string) (*KNDISClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &KNDISClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*KNDISClaims); ok {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// TokenInfo returns human-readable token information
type TokenInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Audience    []string  `json:"audience"`
	ExpiresAt   time.Time `json:"expires_at"`
	IssuedAt    time.Time `json:"issued_at"`
	Scope       string    `json:"scope"`
	Sector      string    `json:"sector"`
	TokenType   string    `json:"token_type"`
	IsExpired   bool      `json:"is_expired"`
	TimeToExpiry string   `json:"time_to_expiry"`
}

// GetTokenInfo extracts readable information from a token
func GetTokenInfo(tokenString string) (*TokenInfo, error) {
	claims, err := ParseTokenWithoutValidation(tokenString)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := claims.ExpiresAt.Time
	isExpired := now.After(expiresAt)

	timeToExpiry := expiresAt.Sub(now)
	if isExpired {
		timeToExpiry = 0
	}

	return &TokenInfo{
		Subject:      claims.Subject,
		Issuer:       claims.Issuer,
		Audience:     claims.Audience,
		ExpiresAt:    expiresAt,
		IssuedAt:     claims.IssuedAt.Time,
		Scope:        claims.Scope,
		Sector:       claims.Sector,
		TokenType:    string(claims.TokenType),
		IsExpired:    isExpired,
		TimeToExpiry: timeToExpiry.String(),
	}, nil
}

// PrettyPrint returns a JSON representation of token info
func (ti *TokenInfo) PrettyPrint() string {
	data, _ := json.MarshalIndent(ti, "", "  ")
	return string(data)
}