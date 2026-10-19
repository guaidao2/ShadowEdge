package version

import (
	"strings"
	"testing"
)

func TestStringIncludesVersionAndCommit(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	if Commit == "" {
		t.Fatal("Commit must not be empty")
	}

	got := String()
	if !strings.Contains(got, Version) {
		t.Fatalf("String() = %q, want it to contain Version %q", got, Version)
	}
	if !strings.Contains(got, Commit) {
		t.Fatalf("String() = %q, want it to contain Commit %q", got, Commit)
	}
}
