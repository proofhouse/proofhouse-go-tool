// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

// Command malscan walks the module set this binary depends on and
// reports any vendored module flagged in the OSV malicious-package
// registry. The tool covers S2C2F ING-3 as a local recipe. A later
// workflow under .github/workflows/ re-runs the same scan on every
// PR.
//
// Usage: malscan [-modroot dir] [-format text|sarif]
//
// malscan reads vendor/modules.txt under -modroot (defaults to the
// current working directory), queries the OSV /v1/query endpoint for
// each vendored module at its pinned version, and reports any
// vulnerability whose ID starts with MAL-. The [OSSF malicious-packages]
// dataset reserves that prefix for advisories that flag a release as
// malware rather than as a known vulnerability. Modules replaced to
// a local path fall outside the OSV registry and get skipped.
//
// The -format flag selects the finding emitter. Text output (the
// default) follows the unified shape documented in the [findings]
// package. SARIF output emits a v2.1.0 report suitable for
// ingestion by GitHub Code Scanning.
//
// [OSSF malicious-packages]: https://github.com/ossf/malicious-packages
// [findings]: https://pkg.go.dev/github.com/proofhouse/proofhouse-go/tools/internal/findings
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/proofhouse/proofhouse-go/tools/internal/exitcode"
	"github.com/proofhouse/proofhouse-go/tools/internal/findings"
	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
	"github.com/proofhouse/proofhouse-go/tools/malscan/osv"
)

// errUnknownFormat reports that the -format flag carried a value
// outside the {text, sarif} allowlist. The sentinel form supports
// programmatic matching and keeps wrapcheck and err113 quiet.
var errUnknownFormat = errors.New("unknown -format (want text or sarif)")

const (
	toolName = "malscan"
	ruleID   = "malicious-package"

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

// props returns the property bag for this finding in the shape
// shared by the text and SARIF emitters. Keys match SARIF property
// names so consumers reading either output channel see the same
// vocabulary.
func (f finding) props() map[string]string {
	p := map[string]string{"id": f.id}
	if f.summary != "" {
		p["summary"] = strings.TrimSpace(f.summary)
	}
	return p
}

// message returns the prose used as the SARIF result message. The
// text emitter doesn't use it; the unified text format encodes the
// same information through level/rule/properties.
func (f finding) message() string {
	if f.summary == "" {
		return fmt.Sprintf("OSV malicious-package advisory %s.", f.id)
	}
	return fmt.Sprintf("OSV malicious-package advisory %s: %s.", f.id, strings.TrimSpace(f.summary))
}

func main() {
	modroot := flag.String("modroot", "", "module root to scan (defaults to cwd)")
	format := flag.String("format", "text", "output format: text or sarif")
	flag.Parse()

	rc, err := run(context.Background(), *modroot, *format, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "malscan: %v\n", err)
	}
	os.Exit(rc)
}

func run(ctx context.Context, modroot, format string, out, errOut io.Writer) (int, error) {
	mods, err := vendormod.Read(modroot)
	if err != nil {
		return exitcode.ToolFailure, fmt.Errorf("read vendored modules: %w", err)
	}

	client := &osv.Client{}
	var hits []finding
	for _, mod := range mods {
		got, lookupErr := evaluateModule(ctx, client, mod)
		if lookupErr != nil {
			fmt.Fprintf(errOut, "malscan: %s: %v\n", mod.Path, lookupErr)
			continue
		}
		hits = append(hits, got...)
	}

	if emitErr := emitFindings(out, format, hits); emitErr != nil {
		return exitcode.ToolFailure, fmt.Errorf("emit findings: %w", emitErr)
	}

	if len(hits) > 0 {
		fmt.Fprintf(errOut, "malscan: %d finding(s) across %d module(s)\n", len(hits), len(mods))
		return exitcode.Findings, nil
	}
	fmt.Fprintf(errOut, "malscan: scanned %d module(s), no findings\n", len(mods))
	return exitcode.OK, nil
}

func emitFindings(out io.Writer, format string, hits []finding) error {
	switch format {
	case "text":
		return emitText(out, hits)
	case "sarif":
		return emitSARIF(out, hits)
	default:
		return fmt.Errorf("%w: %q", errUnknownFormat, format)
	}
}

func emitText(out io.Writer, hits []finding) error {
	for _, f := range hits {
		if err := findings.WriteText(
			out,
			findings.LevelError,
			toolName,
			ruleID,
			f.module,
			f.version,
			f.props(),
		); err != nil {
			return fmt.Errorf("emit text finding for %s: %w", f.module, err)
		}
	}
	return nil
}

func emitSARIF(out io.Writer, hits []finding) error {
	run := findings.NewRun(toolName)
	run.AddRule(ruleID).
		WithDescription("Module appears in the OSV malicious-package registry").
		WithHelpURI("https://github.com/ossf/malicious-packages")
	for _, f := range hits {
		findings.AddResult(run, ruleID, findings.LevelError, f.message(), f.module, f.version, f.props())
	}
	if err := findings.WriteSARIF(out, run); err != nil {
		return fmt.Errorf("emit sarif: %w", err)
	}
	return nil
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
