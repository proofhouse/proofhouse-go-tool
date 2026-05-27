// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/proofhouse/proofhouse-go/tools/internal/exitcode"
	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
	"github.com/proofhouse/proofhouse-go/tools/malscan/osv"
)

// errQueryFailure stands in for any OSV-side error the stub
// surfaces back to the scanner.
var errQueryFailure = errors.New("network failure")

// fakeVulnsClient drives evaluateModule and run from tests. Each
// entry maps "module@version" to a canned response or error.
type fakeVulnsClient struct {
	responses map[string][]osv.Vulnerability
	errors    map[string]error
}

func (f *fakeVulnsClient) Query(_ context.Context, pkg osv.Package, version string) ([]osv.Vulnerability, error) {
	key := pkg.Name + "@" + version
	if err, ok := f.errors[key]; ok {
		return nil, err
	}
	return f.responses[key], nil
}

func TestFindingProps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		f    finding
		want map[string]string
	}{
		{
			name: "id only when summary missing",
			f: finding{
				module: "example.com/a", version: "v1.0.0", id: "MAL-2025-0001",
			},
			want: map[string]string{"id": "MAL-2025-0001"},
		},
		{
			name: "id plus trimmed summary",
			f: finding{
				module: "example.com/a", version: "v1.0.0", id: "MAL-2025-0001",
				summary: "  Backdoor introduced  ",
			},
			want: map[string]string{"id": "MAL-2025-0001", "summary": "Backdoor introduced"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.f.props())
		})
	}
}

func TestFindingMessage(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"OSV malicious-package advisory MAL-2025-0001.",
		finding{id: "MAL-2025-0001"}.message(),
	)
	assert.Equal(t,
		"OSV malicious-package advisory MAL-2025-0001: Backdoor introduced.",
		finding{id: "MAL-2025-0001", summary: "Backdoor introduced"}.message(),
	)
}

func TestCollectFindings(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/mixed", Version: "v0.5.0"}
	cases := []struct {
		name    string
		vulns   []osv.Vulnerability
		wantIDs []string
	}{
		{
			name:    "empty vuln list yields no findings",
			vulns:   nil,
			wantIDs: nil,
		},
		{
			name: "only non-MAL advisories yields no findings",
			vulns: []osv.Vulnerability{
				{ID: "GO-2025-0042", Summary: "Generic vuln"},
				{ID: "GHSA-aaaa-bbbb-cccc"},
				{ID: "CVE-2025-12345"},
			},
			wantIDs: nil,
		},
		{
			name: "MAL-prefixed advisories surface; siblings drop out",
			vulns: []osv.Vulnerability{
				{ID: "GO-2025-0042"},
				{ID: "MAL-2025-0007", Summary: "Backdoor introduced upstream"},
				{ID: "MAL-2025-0008"},
			},
			wantIDs: []string{"MAL-2025-0007", "MAL-2025-0008"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := collectFindings(mod, tc.vulns)
			require.Len(t, got, len(tc.wantIDs))
			for i, want := range tc.wantIDs {
				assert.Equal(t, want, got[i].id)
				assert.Equal(t, mod.Path, got[i].module)
				assert.Equal(t, mod.Version, got[i].version)
			}
		})
	}
}

func TestEmitText_UnifiedFormat(t *testing.T) {
	t.Parallel()

	hits := []finding{
		{module: "example.com/a", version: "v1.0.0", id: "MAL-2025-0001", summary: "Backdoor introduced"},
		{module: "example.com/b", version: "v2.0.0", id: "MAL-2025-0002"},
	}

	var buf bytes.Buffer
	require.NoError(t, emitText(&buf, hits))
	assert.Equal(t,
		"error: malscan/malicious-package: example.com/a@v1.0.0 id=MAL-2025-0001 summary=\"Backdoor introduced\"\n"+
			"error: malscan/malicious-package: example.com/b@v2.0.0 id=MAL-2025-0002\n",
		buf.String(),
	)
}

func TestEmitSARIF_EmitsMaliciousRuleAndResults(t *testing.T) {
	t.Parallel()

	hits := []finding{
		{module: "example.com/a", version: "v1.0.0", id: "MAL-2025-0001", summary: "Backdoor introduced"},
	}

	var buf bytes.Buffer
	require.NoError(t, emitSARIF(&buf, hits))
	out := buf.String()
	assert.Contains(t, out, `"name": "malscan"`)
	assert.Contains(t, out, `"id": "malicious-package"`)
	assert.Contains(t, out, `"ruleId": "malicious-package"`)
	assert.Contains(t, out, `"level": "error"`)
	assert.Contains(t, out, `"name": "example.com/a@v1.0.0"`)
	assert.Contains(t, out, `"id": "MAL-2025-0001"`)
}

func TestEmitFindings_UnknownFormatErrors(t *testing.T) {
	t.Parallel()
	err := emitFindings(&bytes.Buffer{}, "json", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown -format")
}

func TestEvaluateModule(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/m", Version: "v1.0.0"}
	key := mod.Path + "@" + mod.Version

	t.Run("network errors propagate wrapped", func(t *testing.T) {
		t.Parallel()
		client := &fakeVulnsClient{errors: map[string]error{key: errQueryFailure}}
		got, err := evaluateModule(context.Background(), client, mod)
		require.Error(t, err)
		require.ErrorIs(t, err, errQueryFailure)
		assert.Contains(t, err.Error(), "lookup vulns")
		assert.Nil(t, got)
	})

	t.Run("happy path forwards to collectFindings", func(t *testing.T) {
		t.Parallel()
		client := &fakeVulnsClient{responses: map[string][]osv.Vulnerability{
			key: {{ID: "MAL-2025-0001", Summary: "Backdoor"}},
		}}
		got, err := evaluateModule(context.Background(), client, mod)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "MAL-2025-0001", got[0].id)
	})

	t.Run("empty response yields no findings", func(t *testing.T) {
		t.Parallel()
		client := &fakeVulnsClient{} // any key returns nil, nil from the fake
		got, err := evaluateModule(context.Background(), client, mod)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

// writeVendorModulesTxt drops a minimal vendor/modules.txt under
// dir so the run-level tests can drive vendormod.Read without
// spinning up a full go module.
func writeVendorModulesTxt(t *testing.T, dir, body string) {
	t.Helper()
	vendorDir := filepath.Join(dir, "vendor")
	require.NoError(t, os.MkdirAll(vendorDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "modules.txt"), []byte(body), 0o600))
}

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("returns ToolFailure when modroot lacks vendor/modules.txt", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		client := &fakeVulnsClient{}
		rc, err := run(context.Background(), t.TempDir(), "text", client, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, err.Error(), "read vendored modules")
	})

	t.Run("returns ToolFailure on an unknown -format", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/m v1.0.0\n## explicit\nexample.com/m\n")
		client := &fakeVulnsClient{}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "json", client, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, err.Error(), "emit findings")
	})

	t.Run("returns OK with the no-findings banner when nothing matches", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/clean v1.0.0\n## explicit\nexample.com/clean\n")
		client := &fakeVulnsClient{responses: map[string][]osv.Vulnerability{
			"example.com/clean@v1.0.0": {{ID: "GO-2025-0001"}},
		}}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "text", client, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.Empty(t, out.String())
		assert.Contains(t, errOut.String(), "scanned 1 module(s), no findings")
	})

	t.Run("returns Findings with the summary banner when a malicious hit lands", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/bad v1.0.0\n## explicit\nexample.com/bad\n")
		client := &fakeVulnsClient{responses: map[string][]osv.Vulnerability{
			"example.com/bad@v1.0.0": {{ID: "MAL-2025-0001", Summary: "Backdoor"}},
		}}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "text", client, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.Findings, rc)
		assert.Contains(t, out.String(), "error: malscan/malicious-package: example.com/bad@v1.0.0")
		assert.Contains(t, errOut.String(), "1 finding(s) across 1 module(s)")
	})

	t.Run("logs and skips lookup errors", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir,
			"# example.com/ok v1.0.0\n## explicit\nexample.com/ok\n"+
				"# example.com/explode v2.0.0\n## explicit\nexample.com/explode\n",
		)
		client := &fakeVulnsClient{
			errors: map[string]error{"example.com/explode@v2.0.0": errQueryFailure},
		}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "text", client, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.Contains(t, errOut.String(), "malscan: example.com/explode: lookup vulns: network failure")
		assert.Contains(t, errOut.String(), "scanned 2 module(s), no findings")
	})
}

func TestRealMain(t *testing.T) {
	t.Parallel()

	t.Run("unknown flag returns ToolFailure", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		rc := realMain([]string{"--nonsense"}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, rc)
	})

	t.Run("missing vendor tree prints the error line and returns ToolFailure", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		rc := realMain([]string{"-modroot", t.TempDir()}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, errOut.String(), "malscan: read vendored modules:")
	})
}
