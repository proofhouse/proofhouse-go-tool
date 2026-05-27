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
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/proofhouse/proofhouse-go/tools/malscan/osv"
)

const (
	exitOK          = 0
	exitFindings    = 1
	exitToolFailure = 2

	// scannerInitialBufSize sizes the bufio.Scanner buffer for one
	// vendor/modules.txt line. Lines almost never exceed 256 bytes;
	// 64 KiB leaves comfortable headroom without over-allocating.
	scannerInitialBufSize = 64 * 1024

	// scannerMaxBufSize caps the buffer at 1 MiB so a malformed
	// line can't make the scanner grow without bound.
	scannerMaxBufSize = 1 << 20

	// plainModuleFields names the two-field form "<path> <version>"
	// that vendor/modules.txt uses for modules without a replace
	// directive.
	plainModuleFields = 2

	// goEcosystem names the Go ecosystem in OSV requests.
	goEcosystem = "Go"

	// maliciousIDPrefix marks advisories that flag a release as
	// malware rather than as a known vulnerability. The OSSF
	// malicious-packages dataset reserves this prefix.
	maliciousIDPrefix = "MAL-"
)

// vendoredModule names one entry in vendor/modules.txt after the
// parser resolves any replace directives. The struct keeps only the
// fields the OSV lookup needs.
type vendoredModule struct {
	Path    string
	Version string
}

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
	mods, err := enumerateModules(modroot)
	if err != nil {
		return exitToolFailure, err
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

func enumerateModules(modroot string) ([]vendoredModule, error) {
	path := filepath.Join(modroot, "vendor", "modules.txt")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	mods, err := parseModulesTxt(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return mods, nil
}

// parseModulesTxt reads the well-defined vendor/modules.txt format
// described in the [Go vendoring reference]. Lines that begin with
// "# " declare a module and its version, optionally followed by a
// replace directive ("=> path" or "=> path version"). Lines starting
// with "## " carry sub-metadata that the tool ignores. Other lines
// list package paths inside the most recent module and don't affect
// enumeration.
//
// [Go vendoring reference]: https://go.dev/ref/mod#vendoring
func parseModulesTxt(r io.Reader) ([]vendoredModule, error) {
	var mods []vendoredModule
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, scannerInitialBufSize), scannerMaxBufSize)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "## ") {
			continue
		}
		mod, ok := parseModuleLine(strings.TrimPrefix(line, "# "))
		if !ok {
			continue
		}
		mods = append(mods, mod)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return mods, nil
}

// parseModuleLine parses one declaration after the caller strips
// the "# " prefix. Returns a false second return for replaced-to-local
// modules and other shapes the parser can't handle. The caller drops
// them.
//
// Recognized forms:
//
//	<path> <version>
//	<path> <version> => <replacement-path>
//	<path> <version> => <replacement-path> <replacement-version>
//	<path> => <replacement-path> <replacement-version>
func parseModuleLine(line string) (vendoredModule, bool) {
	fields := strings.Fields(line)
	switch {
	case len(fields) >= 4 && fields[len(fields)-3] == "=>":
		// Path replaced to module path + version.
		return vendoredModule{Path: fields[len(fields)-2], Version: fields[len(fields)-1]}, true
	case len(fields) >= 3 && fields[len(fields)-2] == "=>":
		// Path replaced to a local directory (no version follows).
		return vendoredModule{}, false
	case len(fields) == plainModuleFields:
		return vendoredModule{Path: fields[0], Version: fields[1]}, true
	default:
		return vendoredModule{}, false
	}
}

func evaluateModule(ctx context.Context, client *osv.Client, mod vendoredModule) ([]finding, error) {
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
func collectFindings(mod vendoredModule, vulns []osv.Vulnerability) []finding {
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
