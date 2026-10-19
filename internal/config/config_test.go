package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHADOWEDGE_DATA_DIR", dir)
	t.Setenv("SHADOWEDGE_LISTEN", "")
	t.Setenv("SHADOWEDGE_SESSION_TTL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Listen != "0.0.0.0:5000" {
		t.Fatalf("Listen = %q, want default", cfg.Listen)
	}
	if cfg.DBPath != filepath.Join(dir, "shadowedge.db") {
		t.Fatalf("DBPath = %q", cfg.DBPath)
	}
	if cfg.SessionTTL != 7*24*time.Hour {
		t.Fatalf("SessionTTL = %v", cfg.SessionTTL)
	}
	if cfg.MaxUploadBytes != 10*1024*1024 {
		t.Fatalf("MaxUploadBytes = %d", cfg.MaxUploadBytes)
	}
}

func TestLoadOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHADOWEDGE_DATA_DIR", dir)
	t.Setenv("SHADOWEDGE_LISTEN", "127.0.0.1:9443")
	t.Setenv("SHADOWEDGE_SECURE_COOKIES", "true")
	t.Setenv("SHADOWEDGE_SESSION_TTL", "2h")
	t.Setenv("SHADOWEDGE_MAX_UPLOAD_MB", "2")
	t.Setenv("SHADOWEDGE_ADMIN_USERNAME", "root")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Listen != "127.0.0.1:9443" || !cfg.SecureCookies {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
	if cfg.SessionTTL != 2*time.Hour || cfg.MaxUploadBytes != 2*1024*1024 {
		t.Fatalf("unexpected limits: %+v", cfg)
	}
	if cfg.AdminUsername != "root" {
		t.Fatalf("AdminUsername = %q", cfg.AdminUsername)
	}
}
