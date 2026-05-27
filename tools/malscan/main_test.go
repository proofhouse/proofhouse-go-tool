// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/proofhouse/proofhouse-go/tools/malscan/osv"
)

func TestParseModulesTxt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []vendoredModule
	}{
		{
			name: "plain module declarations",
			in: `# github.com/spf13/cobra v1.10.2
## explicit; go 1.23
github.com/spf13/cobra
# github.com/stretchr/testify v1.11.1
## explicit; go 1.17
github.com/stretchr/testify/assert
github.com/stretchr/testify/require
`,
			want: []vendoredModule{
				{Path: "github.com/spf13/cobra", Version: "v1.10.2"},
				{Path: "github.com/stretchr/testify", Version: "v1.11.1"},
			},
		},
		{
			name: "replaced to another module",
			in: `# example.com/old v0.0.0 => example.com/new v1.2.3
## explicit
example.com/old
`,
			want: []vendoredModule{
				{Path: "example.com/new", Version: "v1.2.3"},
			},
		},
		{
			name: "replaced to local path is dropped",
			in: `# example.com/local v0.0.0 => ../local
## explicit
example.com/local
# github.com/keep/me v1.0.0
github.com/keep/me
`,
			want: []vendoredModule{
				{Path: "github.com/keep/me", Version: "v1.0.0"},
			},
		},
		{
			name: "blank input yields no modules",
			in:   "",
			want: nil,
		},
		{
			name: "package paths and sub-metadata are ignored",
			in: `# github.com/a/b v0.1.0
## explicit; go 1.21
github.com/a/b
github.com/a/b/sub
random non-header line
`,
			want: []vendoredModule{{Path: "github.com/a/b", Version: "v0.1.0"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseModulesTxt(strings.NewReader(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

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

	mod := vendoredModule{Path: "example.com/mixed", Version: "v0.5.0"}
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
