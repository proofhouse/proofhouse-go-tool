// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

// Package buildmeta carries build-time information injected via ldflags, with
// a fallback that consults the runtime/debug build info when no ldflags apply
// (such as go install directly from source).
package buildmeta

import "runtime/debug"

// Build-time variables. The Justfile and goreleaser config both set these via
// -ldflags "-X github.com/proofhouse/proofhouse-go/internal/buildmeta.<Var>=<value>".
// The defaults below apply when the build passes no ldflags.
//
//nolint:gochecknoglobals // ldflags -X can only patch package-level vars
var (
	// Version holds the semantic version of the build. Set via ldflags, or
	// resolved from the runtime/debug build info at init time.
	Version = "DEV"

	// Commit holds the short git SHA of the build.
	Commit = ""

	// Date holds the build date in calendar form, like 2026-05-26.
	Date = ""
)

// Info bundles build metadata for callers that want a struct rather than
// the package-level vars.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Get returns the current build metadata.
func Get() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}

//nolint:gochecknoinits // runtime/debug fallback runs once at process start
func init() {
	if Version != "DEV" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "(devel)" {
		return
	}
	Version = info.Main.Version
}
