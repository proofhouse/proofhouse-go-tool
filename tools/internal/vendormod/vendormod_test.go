// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package vendormod_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
)

func TestParse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []vendormod.Module
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
			want: []vendormod.Module{
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
			want: []vendormod.Module{
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
			want: []vendormod.Module{
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
			want: []vendormod.Module{{Path: "github.com/a/b", Version: "v0.1.0"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := vendormod.Parse(strings.NewReader(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
