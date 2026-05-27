// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
	"github.com/proofhouse/proofhouse-go/tools/malscan/osv"
)

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
