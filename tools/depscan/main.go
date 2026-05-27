// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

// Command depscan walks the module set this binary depends on and
// reports any vendored module that pkg.go.dev marks as retracted at
// the pinned version or as deprecated at its latest version. The
// tool covers S2C2F SCA-3 ("Inventory all dependencies" + "Verify
// the support state") as a local recipe. A later workflow under
// .github/workflows/ re-runs the same scan on every PR.
//
// Usage: depscan [-modroot dir] [-format text|sarif]
//
// depscan reads vendor/modules.txt under -modroot (defaults to the
// current working directory). Vendor-first matches the project's
// supply chain posture. Vendored dependencies form the audit
// surface, and the file's format stays stable and offline-parseable.
// Modules replaced to a local path fall outside pkg.go.dev's
// coverage and get skipped.
//
// The -format flag selects the finding emitter. Text output (the
// default) follows the unified shape documented in the [findings]
// package. SARIF output emits a v2.1.0 report suitable for
// ingestion by GitHub Code Scanning.
//
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

	"github.com/proofhouse/proofhouse-go/tools/depscan/pkgsite"
	"github.com/proofhouse/proofhouse-go/tools/internal/exitcode"
	"github.com/proofhouse/proofhouse-go/tools/internal/findings"
	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
)

const toolName = "depscan"

// errUnknownFormat reports that the -format flag carried a value
// outside the {text, sarif} allowlist. The sentinel form supports
// programmatic matching and keeps wrapcheck and err113 quiet.
var errUnknownFormat = errors.New("unknown -format (want text or sarif)")

// versionsClient abstracts the slice of [pkgsite.Client] that the
// scanner needs. The interface keeps run injectable from tests, so
// the table-driven cases that mutation testing relies on don't have
// to stand up a real HTTP transport for every branch.
type versionsClient interface {
	Versions(ctx context.Context, module string) ([]pkgsite.ModuleVersion, error)
}

// findingKind enumerates the issue classes the tool reports. The
// string value doubles as the SARIF ruleId.
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

// props returns the property bag for this finding in the shape
// shared by the text and SARIF emitters. Keys match SARIF property
// names so consumers reading either output channel see the same
// vocabulary.
func (f finding) props() map[string]string {
	p := make(map[string]string)
	if f.reason != "" {
		p["reason"] = strings.TrimSpace(f.reason)
	}
	if f.kind == kindDeprecated && f.latest != "" {
		p["latest"] = f.latest
	}
	return p
}

// message returns the prose used as the SARIF result message. The
// text emitter doesn't use it; the unified text format encodes the
// same information through level/rule/properties.
func (f finding) message() string {
	switch f.kind {
	case kindRetracted:
		return fmt.Sprintf("Module retracted at %s. %s", f.version, reasonSentence(f.reason))
	case kindDeprecated:
		return fmt.Sprintf("Module deprecated at latest version %s. %s", f.latest, reasonSentence(f.reason))
	default:
		return "Unknown finding."
	}
}

func reasonSentence(r string) string {
	if r == "" {
		return "No reason recorded."
	}
	return "Reason: " + strings.TrimSpace(r) + "."
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

// realMain wraps the imperative flag-parsing and exit-code wiring
// in a function that the test harness can drive. The split keeps
// main itself trivial enough to verify by inspection and lets
// mutation testing exercise the error-log branch via real arguments
// and writers rather than os.Exit.
func realMain(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("depscan", flag.ContinueOnError)
	fs.SetOutput(errOut)
	modroot := fs.String("modroot", "", "module root to scan (defaults to cwd)")
	format := fs.String("format", "text", "output format: text or sarif")
	if err := fs.Parse(args); err != nil {
		return exitcode.ToolFailure
	}

	rc, err := run(context.Background(), *modroot, *format, &pkgsite.Client{}, out, errOut)
	if err != nil {
		fmt.Fprintf(errOut, "depscan: %v\n", err)
	}
	return rc
}

func run(ctx context.Context, modroot, format string, client versionsClient, out, errOut io.Writer) (int, error) {
	mods, err := vendormod.Read(modroot)
	if err != nil {
		return exitcode.ToolFailure, fmt.Errorf("read vendored modules: %w", err)
	}

	var hits []finding
	for _, mod := range mods {
		got, lookupErr := evaluateModule(ctx, client, mod)
		if lookupErr != nil {
			fmt.Fprintf(errOut, "depscan: %s: %v\n", mod.Path, lookupErr)
			continue
		}
		hits = append(hits, got...)
	}

	if emitErr := emitFindings(out, format, hits); emitErr != nil {
		return exitcode.ToolFailure, fmt.Errorf("emit findings: %w", emitErr)
	}

	if len(hits) > 0 {
		fmt.Fprintf(errOut, "depscan: %d finding(s) across %d module(s)\n", len(hits), len(mods))
		return exitcode.Findings, nil
	}
	fmt.Fprintf(errOut, "depscan: scanned %d module(s), no findings\n", len(mods))
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
			findings.LevelWarning,
			toolName,
			string(f.kind),
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
	run.AddRule(string(kindRetracted)).
		WithDescription("Module is retracted at the pinned version").
		WithHelpURI("https://go.dev/ref/mod#go-mod-file-retract")
	run.AddRule(string(kindDeprecated)).
		WithDescription("Module is deprecated at its latest version").
		WithHelpURI("https://go.dev/ref/mod#go-mod-file-module-deprecation")
	for _, f := range hits {
		findings.AddResult(run, string(f.kind), findings.LevelWarning, f.message(), f.module, f.version, f.props())
	}
	if err := findings.WriteSARIF(out, run); err != nil {
		return fmt.Errorf("emit sarif: %w", err)
	}
	return nil
}

func evaluateModule(ctx context.Context, client versionsClient, mod vendormod.Module) ([]finding, error) {
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
