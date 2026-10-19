// Package web embeds the single-file SPA and its vendored assets.
package web

import "embed"

//go:embed index.html vendor/*
var FS embed.FS
