// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

// Command malscan walks the module set this binary depends on and
// reports any vendored module flagged in the OSV malicious-package
// registry. The tool covers S2C2F ING-3 as a local recipe. A later
// workflow under .github/workflows/ re-runs the same scan on every
// PR.
//
// Usage: malscan [-modroot dir]
//
// malscan reads vendor/modules.txt under -modroot (defaults to the
// current working directory), queries the OSV /v1/query endpoint for
// each vendored module at its pinned version, and reports any
// vulnerability whose ID starts with MAL-. The [OSSF malicious-packages]
// dataset reserves that prefix for advisories that flag a release as
// malware rather than as a known vulnerability. Modules replaced to
// a local path fall outside the OSV registry and get skipped.
//
// [OSSF malicious-packages]: https://github.com/ossf/malicious-packages
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
	"github.com/proofhouse/proofhouse-go/tools/malscan/osv"
)

const (
	exitOK          = 0
	exitFindings    = 1
	exitToolFailure = 2

	// goEcosystem names the Go ecosystem in OSV requests.
	goEcosystem = "Go"

	// maliciousIDPrefix marks advisories that flag a release as
	// malware rather than as a known vulnerability. The OSSF
	// malicious-packages dataset reserves this prefix.
	maliciousIDPrefix = "MAL-"
)

// finding describes a single malicious-package hit. malscan only
// reports advisories whose IDs use the MAL- prefix; vulnerability
// IDs under other prefixes belong to govulncheck's reachability-aware
// scan.
type finding struct {
	module  string
	version string
	id      string
	summary string
}

func (f finding) String() string {
	return fmt.Sprintf("MALICIOUS %s@%s (%s) — %s", f.module, f.version, f.id, displaySummary(f.summary))
}

func displaySummary(s string) string {
	if s == "" {
		return "no summary recorded"
	}
	return strings.TrimSpace(s)
}

func main() {
	modroot := flag.String("modroot", "", "module root to scan (defaults to cwd)")
	flag.Parse()

	rc, err := run(context.Background(), *modroot, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "malscan: %v\n", err)
	}
	os.Exit(rc)
}

func run(ctx context.Context, modroot string, out, errOut io.Writer) (int, error) {
	mods, err := vendormod.Read(modroot)
	if err != nil {
		return exitToolFailure, fmt.Errorf("read vendored modules: %w", err)
	}

	client := &osv.Client{}
	var findings []finding
	for _, mod := range mods {
		hits, lookupErr := evaluateModule(ctx, client, mod)
		if lookupErr != nil {
			fmt.Fprintf(errOut, "malscan: %s: %v\n", mod.Path, lookupErr)
			continue
		}
		findings = append(findings, hits...)
	}

	for _, f := range findings {
		fmt.Fprintln(out, f.String())
	}

	if len(findings) > 0 {
		fmt.Fprintf(errOut, "malscan: %d finding(s) across %d module(s)\n", len(findings), len(mods))
		return exitFindings, nil
	}
	fmt.Fprintf(errOut, "malscan: scanned %d module(s), no findings\n", len(mods))
	return exitOK, nil
}

func evaluateModule(ctx context.Context, client *osv.Client, mod vendormod.Module) ([]finding, error) {
	vulns, err := client.Query(ctx, osv.Package{Name: mod.Path, Ecosystem: goEcosystem}, mod.Version)
	if err != nil {
		return nil, fmt.Errorf("lookup vulns: %w", err)
	}
	return collectFindings(mod, vulns), nil
}

// collectFindings walks the OSV response and emits one finding per
// advisory whose ID uses the MAL- prefix. Other advisory prefixes
// (GO-, GHSA-, CVE-) describe regular vulnerabilities rather than
// malware reports and belong to the govulncheck recipe.
func collectFindings(mod vendormod.Module, vulns []osv.Vulnerability) []finding {
	var hits []finding
	for _, v := range vulns {
		if !strings.HasPrefix(v.ID, maliciousIDPrefix) {
			continue
		}
		hits = append(hits, finding{
			module:  mod.Path,
			version: mod.Version,
			id:      v.ID,
			summary: v.Summary,
		})
	}
	return hits
}
