package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("unexpected hash format: %q", hash)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("not-a-hash", "whatever") {
		t.Fatal("malformed hash accepted")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := ValidatePassword(strings.Repeat("x", 129)); err == nil {
		t.Fatal("oversized password accepted")
	}
	if err := ValidatePassword("long-enough"); err != nil {
		t.Fatalf("valid password rejected: %v", err)
	}
}

func TestTokensAreOpaqueAndStableHashes(t *testing.T) {
	tok, err := RandomToken(32)
	if err != nil {
		t.Fatalf("RandomToken: %v", err)
	}
	if len(tok) < 32 {
		t.Fatalf("token too short: %q", tok)
	}
	if HashToken(tok) != HashToken(tok) {
		t.Fatal("hash is not stable")
	}
	if HashToken(tok) == tok {
		t.Fatal("token hash equals token")
	}
	other, _ := RandomToken(32)
	if tok == other {
		t.Fatal("two random tokens are equal")
	}
}
