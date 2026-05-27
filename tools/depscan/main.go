// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

// Command depscan walks the module set this binary depends on and
// reports any vendored module that pkg.go.dev marks as retracted at
// the pinned version or as deprecated at its latest version. The
// tool covers S2C2F SCA-3 ("Inventory all dependencies" + "Verify
// the support state") as a local recipe. A later phase 5 workflow
// re-runs the same scan on every PR.
//
// Usage: depscan [-modroot dir]
//
// depscan reads vendor/modules.txt under -modroot (defaults to the
// current working directory). Vendor-first matches the project's
// supply chain posture. Vendored dependencies form the audit
// surface, and the file's format stays stable and offline-parseable.
// Modules replaced to a local path fall outside pkg.go.dev's
// coverage and get skipped.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/proofhouse/proofhouse-go/tools/depscan/pkgsite"
	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
)

const (
	exitOK          = 0
	exitFindings    = 1
	exitToolFailure = 2
)

// findingKind enumerates the issue classes the tool reports.
type findingKind string

const (
	kindRetracted  findingKind = "retracted"
	kindDeprecated findingKind = "deprecated"
)

// finding describes a single deprecation or retraction hit.
type finding struct {
	kind    findingKind
	module  string
	version string
	latest  string
	reason  string
}

func (f finding) String() string {
	reason := displayReason(f.reason)
	switch f.kind {
	case kindRetracted:
		return fmt.Sprintf("RETRACTED  %s@%s — %s", f.module, f.version, reason)
	case kindDeprecated:
		return fmt.Sprintf(
			"DEPRECATED %s (using %s, latest %s) — %s",
			f.module, f.version, f.latest, reason,
		)
	default:
		return fmt.Sprintf("UNKNOWN    %s@%s", f.module, f.version)
	}
}

func displayReason(r string) string {
	if r == "" {
		return "no reason recorded"
	}
	return strings.TrimSpace(r)
}

func main() {
	modroot := flag.String("modroot", "", "module root to scan (defaults to cwd)")
	flag.Parse()

	rc, err := run(context.Background(), *modroot, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "depscan: %v\n", err)
	}
	os.Exit(rc)
}

func run(ctx context.Context, modroot string, out, errOut io.Writer) (int, error) {
	mods, err := vendormod.Read(modroot)
	if err != nil {
		return exitToolFailure, fmt.Errorf("read vendored modules: %w", err)
	}

	client := &pkgsite.Client{}
	var findings []finding
	for _, mod := range mods {
		hits, lookupErr := evaluateModule(ctx, client, mod)
		if lookupErr != nil {
			fmt.Fprintf(errOut, "depscan: %s: %v\n", mod.Path, lookupErr)
			continue
		}
		findings = append(findings, hits...)
	}

	for _, f := range findings {
		fmt.Fprintln(out, f.String())
	}

	if len(findings) > 0 {
		fmt.Fprintf(errOut, "depscan: %d finding(s) across %d module(s)\n", len(findings), len(mods))
		return exitFindings, nil
	}
	fmt.Fprintf(errOut, "depscan: scanned %d module(s), no findings\n", len(mods))
	return exitOK, nil
}

func evaluateModule(ctx context.Context, client *pkgsite.Client, mod vendormod.Module) ([]finding, error) {
	versions, err := client.Versions(ctx, mod.Path)
	if err != nil {
		if errors.Is(err, pkgsite.ErrNotFound) {
			return nil, nil // private, replaced, or not indexed: skip
		}
		return nil, fmt.Errorf("lookup versions: %w", err)
	}
	return collectFindings(mod, versions), nil
}

// collectFindings walks the version records once and emits one
// hit per concern. Retraction looks at the entry whose version
// matches the vendored pin; deprecation looks at the entry the API
// names as latest. The Go module system stores deprecation on the
// most recent version's go.mod, so any older deprecation flags
// stay informational rather than authoritative.
func collectFindings(mod vendormod.Module, versions []pkgsite.ModuleVersion) []finding {
	if len(versions) == 0 {
		return nil
	}
	latest := versions[0].LatestVersion
	var hits []finding
	for _, v := range versions {
		if v.Version == mod.Version && v.Retracted {
			hits = append(hits, finding{
				kind:    kindRetracted,
				module:  mod.Path,
				version: mod.Version,
				reason:  v.RetractionReason,
			})
		}
		if v.Version == latest && v.Deprecated {
			hits = append(hits, finding{
				kind:    kindDeprecated,
				module:  mod.Path,
				version: mod.Version,
				latest:  latest,
				reason:  v.DeprecationReason,
			})
		}
	}
	return hits
}
