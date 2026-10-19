// Package config loads ShadowEdge runtime configuration from environment
// variables. The default listener is reachable on all interfaces for a
// self-hosted team instance; set SHADOWEDGE_LISTEN=127.0.0.1:5000 for a
// local-only instance.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the runtime configuration shared by all deployment modes.
type Config struct {
	DataDir        string
	DBPath         string
	Listen         string
	SecureCookies  bool
	SessionTTL     time.Duration
	AdminUsername  string
	AdminPassword  string
	Debug          bool
	MaxUploadBytes int64
}

// Load reads configuration from the environment and validates it.
func Load() (Config, error) {
	cfg := Config{
		DataDir:        env("SHADOWEDGE_DATA_DIR", "data"),
		Listen:         env("SHADOWEDGE_LISTEN", "0.0.0.0:5000"),
		SessionTTL:     durationEnv("SHADOWEDGE_SESSION_TTL", 7*24*time.Hour),
		AdminUsername:  env("SHADOWEDGE_ADMIN_USERNAME", "admin"),
		AdminPassword:  os.Getenv("SHADOWEDGE_ADMIN_PASSWORD"),
		Debug:          boolEnv("SHADOWEDGE_DEBUG", false),
		MaxUploadBytes: int64Env("SHADOWEDGE_MAX_UPLOAD_MB", 10) * 1024 * 1024,
	}

	secure, err := strconv.ParseBool(env("SHADOWEDGE_SECURE_COOKIES", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("SHADOWEDGE_SECURE_COOKIES: %w", err)
	}
	cfg.SecureCookies = secure

	absData, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return Config{}, fmt.Errorf("resolve data dir: %w", err)
	}
	cfg.DataDir = absData
	cfg.DBPath = filepath.Join(absData, "shadowedge.db")

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return Config{}, fmt.Errorf("create data dir: %w", err)
	}

	if strings.TrimSpace(cfg.Listen) == "" {
		return Config{}, errors.New("SHADOWEDGE_LISTEN must not be empty")
	}
	if cfg.SessionTTL <= 0 {
		return Config{}, errors.New("SHADOWEDGE_SESSION_TTL must be positive")
	}
	if cfg.MaxUploadBytes <= 0 {
		return Config{}, errors.New("SHADOWEDGE_MAX_UPLOAD_MB must be positive")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}

func int64Env(key string, fallback int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
