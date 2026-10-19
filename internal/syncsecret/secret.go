// Package syncsecret encrypts edge sync tokens at rest with a local AES-GCM key.
package syncsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const keySize = 32

// KeyPath returns the local sync key path for a data directory.
func KeyPath(dataDir string) string {
	return filepath.Join(dataDir, "sync.key")
}

// LoadOrCreateKey loads the local 32-byte key, creating it with 0600 permissions
// on first use.
func LoadOrCreateKey(dataDir string) ([]byte, error) {
	path := KeyPath(dataDir)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		return key, nil
	}
	if !os.IsExist(err) {
		return nil, err
	}
	// Another process/goroutine created the key first; use that key. Retry
	// briefly because it may still be writing the file.
	deadline := time.Now().Add(time.Second)
	for {
		data, readErr := os.ReadFile(path)
		if readErr == nil {
			if len(data) == keySize {
				return data, nil
			}
			if len(data) > keySize {
				return nil, fmt.Errorf("sync key has invalid length %d", len(data))
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out reading sync key")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Encrypt returns a base64 nonce+ciphertext string.
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt.
func Decrypt(key []byte, encoded string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("sync token ciphertext is too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
