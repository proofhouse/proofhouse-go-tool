// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
	"github.com/proofhouse/proofhouse-go/tools/malscan/osv"
)

func TestFindingString(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"MALICIOUS example.com/a@v1.0.0 (MAL-2025-0001) — Backdoor introduced in v1.0.0",
		finding{
			module:  "example.com/a",
			version: "v1.0.0",
			id:      "MAL-2025-0001",
			summary: "Backdoor introduced in v1.0.0",
		}.String(),
	)
	assert.Equal(t,
		"MALICIOUS example.com/a@v1.0.0 (MAL-2025-0001) — no summary recorded",
		finding{
			module:  "example.com/a",
			version: "v1.0.0",
			id:      "MAL-2025-0001",
		}.String(),
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
