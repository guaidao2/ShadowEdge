package syncsecret

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := LoadOrCreateKey(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if len(key) != keySize {
		t.Fatalf("key length = %d", len(key))
	}
	encoded, err := Encrypt(key, "project-token-123")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encoded == "project-token-123" {
		t.Fatal("token was not encrypted")
	}
	plain, err := Decrypt(key, encoded)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "project-token-123" {
		t.Fatalf("plaintext = %q", plain)
	}
}

func TestKeyPersists(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("key changed between loads")
	}
	if _, err := os.Stat(filepath.Join(dir, "sync.key")); err != nil {
		t.Fatalf("key file: %v", err)
	}
}

func TestConcurrentKeyCreation(t *testing.T) {
	dir := t.TempDir()
	const workers = 16
	keys := make([][]byte, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = LoadOrCreateKey(dir)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	for i := 1; i < workers; i++ {
		if string(keys[0]) != string(keys[i]) {
			t.Fatalf("worker %d got a different key", i)
		}
	}
}
