// Package auth contains password hashing and opaque token helpers.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// RandomToken returns a URL-safe random token with n bytes of entropy.
func RandomToken(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("token entropy must be positive")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the SHA-256 hex digest used for server-side token storage.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewCSRFToken returns a double-submit CSRF token.
func NewCSRFToken() (string, error) { return RandomToken(32) }
