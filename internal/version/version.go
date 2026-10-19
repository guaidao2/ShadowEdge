// Package version holds build-time version metadata for ShadowEdge.
package version

// Version is the current development version. Release builds override it
// through -ldflags "-X shadowedge/internal/version.Version=..."
var Version = "0.1.0-dev"

// Commit is the git revision injected at build time.
var Commit = "unknown"

// String returns a human-readable version string.
func String() string {
	return "ShadowEdge " + Version + " (" + Commit + ")"
}
