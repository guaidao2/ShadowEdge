// Command shadowedge is the single entry point for all deployment modes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"shadowedge/internal/auth"
	"shadowedge/internal/config"
	"shadowedge/internal/domain"
	"shadowedge/internal/edgesync"
	"shadowedge/internal/httpapi"
	"shadowedge/internal/store"
	"shadowedge/internal/syncsecret"
	"shadowedge/internal/version"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Println(version.String())
		fmt.Println("ShadowEdge is in early development; see README.md.")
		fmt.Println("Run 'shadowedge help' for usage.")
		return
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println(version.String())
	case "help", "--help", "-h":
		usage(os.Stdout)
	case "serve":
		runServe(os.Args[2:])
	case "migrate":
		runMigrate(os.Args[2:])
	case "join":
		runJoin(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `ShadowEdge - collaborative red team operations platform

Usage:
  shadowedge version          print version
  shadowedge help             print this help
  shadowedge serve            start a local/master instance
  shadowedge migrate          run database migrations
  shadowedge join             join a remote project master as an edge

Join flags:
  --master URL                master base URL, e.g. https://master:5000
  --project ID                remote project ID
  --token TOKEN               project API token (or SHADOWEDGE_SYNC_TOKEN)
  --listen ADDR               local edge listen address (default 127.0.0.1:5001)
  --data DIR                  edge data directory (default edge-data)
  --interval DURATION         sync interval (default 1s)

Environment:
  SHADOWEDGE_DATA_DIR              data directory (default: data)
  SHADOWEDGE_LISTEN                listen address (default: 0.0.0.0:5000)
  SHADOWEDGE_ADMIN_USERNAME        bootstrap admin username (default: admin)
  SHADOWEDGE_ADMIN_PASSWORD        bootstrap admin password (generated if empty)
  SHADOWEDGE_SECURE_COOKIES        true when serving over HTTPS
  SHADOWEDGE_SESSION_TTL           session lifetime (default: 168h)`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	master := fs.Bool("master", false, "run as a project master node")
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fatal("load config", err)
	}
	warnIfExposed(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		fatal("open database", err)
	}
	defer st.Close()

	if err := bootstrapAdmin(ctx, st, cfg); err != nil {
		fatal("bootstrap administrator", err)
	}

	handler, err := httpapi.New(cfg, st)
	if err != nil {
		fatal("build HTTP server", err)
	}
	manager := edgesync.NewManager(st, cfg.DataDir, time.Second)
	handler.SetSyncRunner(manager)
	manager.SetNotifier(handler.NotifyProject)
	go manager.Run(ctx)

	mode := "standalone"
	if *master {
		mode = "master"
	}
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("ShadowEdge listening", "addr", cfg.Listen, "mode", mode, "data", cfg.DataDir)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		fatal("serve", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown", "error", err)
	}
}

func warnIfExposed(cfg config.Config) {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		host = cfg.Listen
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if cfg.SecureCookies || host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return
	}
	slog.Warn("listening on a non-loopback address without secure cookies; terminate TLS and set SHADOWEDGE_SECURE_COOKIES=true", "addr", cfg.Listen)
}

func runJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	master := fs.String("master", "", "master base URL")
	project := fs.String("project", "", "remote project ID")
	token := fs.String("token", envOr("SHADOWEDGE_SYNC_TOKEN", ""), "project API token")
	listen := fs.String("listen", envOr("SHADOWEDGE_EDGE_LISTEN", "127.0.0.1:5001"), "edge listen address")
	dataDir := fs.String("data", envOr("SHADOWEDGE_EDGE_DATA_DIR", "edge-data"), "edge data directory")
	adminUser := fs.String("admin-username", envOr("SHADOWEDGE_ADMIN_USERNAME", "admin"), "local admin username")
	adminPass := fs.String("admin-password", os.Getenv("SHADOWEDGE_ADMIN_PASSWORD"), "local admin password")
	interval := fs.Duration("interval", time.Second, "sync interval")
	_ = fs.Parse(args)

	if *master == "" || *project == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "join requires --master, --project and --token")
		os.Exit(2)
	}
	if *interval <= 0 {
		*interval = time.Second
	}

	absData, err := filepath.Abs(*dataDir)
	if err != nil {
		fatal("resolve edge data dir", err)
	}
	if err := os.MkdirAll(absData, 0o750); err != nil {
		fatal("create edge data dir", err)
	}
	cfg := config.Config{
		DataDir: absData, DBPath: filepath.Join(absData, "shadowedge.db"),
		Listen: *listen, SessionTTL: 7 * 24 * time.Hour,
		AdminUsername: *adminUser, AdminPassword: *adminPass,
		MaxUploadBytes: 10 << 20,
	}
	warnIfExposed(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		fatal("open edge database", err)
	}
	defer st.Close()

	nodeID := "edge-" + uuid.NewString()[:8]
	if err := bootstrapAdmin(ctx, st, cfg); err != nil {
		fatal("bootstrap local administrator", err)
	}
	admin, err := st.GetUserByUsername(ctx, cfg.AdminUsername)
	if err != nil {
		fatal("load local administrator", err)
	}
	key, err := syncsecret.LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		fatal("load sync key", err)
	}
	tokenCipher, err := syncsecret.Encrypt(key, *token)
	if err != nil {
		fatal("encrypt sync token", err)
	}

	var existingSync *domain.SyncState
	localProjectID := ""
	if state, err := st.FindSyncStateByRemote(ctx, *master, *project); err == nil {
		existingSync = state
		localProjectID = state.LocalProjectID
		if _, err := st.GetProject(ctx, localProjectID); err != nil {
			existingSync = nil
			localProjectID = ""
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		fatal("load edge sync state", err)
	}

	if localProjectID == "" {
		snapshot, err := edgesync.FetchSnapshot(ctx, *master, *project, *token)
		if err != nil {
			fatal("fetch master snapshot", err)
		}
		local, err := st.CreateProject(ctx, admin.ID, snapshot.Project.Name, snapshot.Project.Description)
		if err != nil {
			fatal("create local edge project", err)
		}
		localProjectID = local.ID
		if err := st.ApplySnapshot(ctx, localProjectID, admin.ID, snapshot); err != nil {
			fatal("apply master snapshot", err)
		}
		if err := st.SetSyncState(ctx, domain.SyncState{
			LocalProjectID: localProjectID, RemoteProjectID: *project,
			MasterURL: *master, NodeID: nodeID, Role: "edge", LastSeq: snapshot.LastSeq,
			TokenCipher: tokenCipher,
		}); err != nil {
			fatal("save edge sync state", err)
		}
	} else {
		// Existing edge: start the local UI without requiring master contact.
		existingSync.NodeID = nodeID
		existingSync.Role = "edge"
		existingSync.MasterURL = *master
		existingSync.RemoteProjectID = *project
		existingSync.TokenCipher = tokenCipher
		if err := st.SetSyncState(ctx, *existingSync); err != nil {
			fatal("update edge sync state", err)
		}
		slog.Info("edge project already initialized; starting without master contact",
			"local_project", localProjectID)
	}

	handler, err := httpapi.New(cfg, st)
	if err != nil {
		fatal("build edge HTTP server", err)
	}
	manager := edgesync.NewManager(st, cfg.DataDir, *interval)
	handler.SetSyncRunner(manager)
	manager.SetNotifier(handler.NotifyProject)
	go manager.Run(ctx)
	slog.Info("ShadowEdge edge sync started", "interval", interval.String())
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("ShadowEdge edge listening",
			"addr", cfg.Listen, "master", *master,
			"remote_project", *project, "local_project", localProjectID, "node", nodeID)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		fatal("join", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("edge shutdown", "error", err)
	}
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fatal("load config", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		fatal("migrate database", err)
	}
	defer st.Close()
	fmt.Printf("migrations applied: %s\n", cfg.DBPath)
}

func bootstrapAdmin(ctx context.Context, st *store.Store, cfg config.Config) error {
	n, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	password := cfg.AdminPassword
	generated := password == ""
	if generated {
		password, err = auth.RandomToken(18)
		if err != nil {
			return err
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	created, err := st.EnsureBootstrapAdmin(ctx, cfg.AdminUsername, hash)
	if err != nil {
		return err
	}
	if !created {
		return nil
	}

	if generated {
		fmt.Fprintf(os.Stderr, "\n[bootstrap] administrator created\n  username: %s\n  password: %s\n", cfg.AdminUsername, password)
		fmt.Fprintln(os.Stderr, "  change this password after the first login; it will not be shown again.")
		fmt.Fprintln(os.Stderr)
	} else {
		fmt.Fprintf(os.Stderr, "[bootstrap] administrator created: %s (password from SHADOWEDGE_ADMIN_PASSWORD)\n", cfg.AdminUsername)
	}
	return nil
}

func fatal(action string, err error) {
	slog.Error(action, "error", err)
	os.Exit(1)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
