// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindingProps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		f    finding
		want map[string]string
	}{
		{
			name: "retracted with reason",
			f: finding{
				kind: kindRetracted, module: "example.com/a", version: "v1.0.0",
				reason: "checksum",
			},
			want: map[string]string{"reason": "checksum"},
		},
		{
			name: "retracted without reason",
			f: finding{
				kind: kindRetracted, module: "example.com/a", version: "v1.0.0",
			},
			want: map[string]string{},
		},
		{
			name: "deprecated emits latest and reason",
			f: finding{
				kind: kindDeprecated, module: "example.com/b", version: "v0.1.0",
				latest: "v0.2.0", reason: "use v0.2.0",
			},
			want: map[string]string{"latest": "v0.2.0", "reason": "use v0.2.0"},
		},
		{
			name: "reason whitespace trimmed",
			f: finding{
				kind: kindRetracted, module: "example.com/a", version: "v1.0.0",
				reason: "  checksum  \n",
			},
			want: map[string]string{"reason": "checksum"},
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
		"Module retracted at v1.0.0. Reason: checksum.",
		finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "checksum"}.message(),
	)
	assert.Equal(t,
		"Module retracted at v1.0.0. No reason recorded.",
		finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0"}.message(),
	)
	assert.Equal(t,
		"Module deprecated at latest version v0.2.0. Reason: use v0.2.0.",
		finding{
			kind: kindDeprecated, module: "example.com/b", version: "v0.1.0",
			latest: "v0.2.0", reason: "use v0.2.0",
		}.message(),
	)
}

func TestEmitText_UnifiedFormat(t *testing.T) {
	t.Parallel()

	hits := []finding{
		{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "checksum"},
		{
			kind: kindDeprecated, module: "example.com/b", version: "v0.1.0",
			latest: "v0.2.0", reason: "use v0.2.0",
		},
	}

	var buf bytes.Buffer
	require.NoError(t, emitText(&buf, hits))
	assert.Equal(t,
		"warning: depscan/retracted: example.com/a@v1.0.0 reason=checksum\n"+
			"warning: depscan/deprecated: example.com/b@v0.1.0 latest=v0.2.0 reason=\"use v0.2.0\"\n",
		buf.String(),
	)
}

func TestEmitSARIF_RegistersBothRulesAndEmitsResults(t *testing.T) {
	t.Parallel()

	hits := []finding{
		{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "checksum"},
		{
			kind: kindDeprecated, module: "example.com/b", version: "v0.1.0",
			latest: "v0.2.0", reason: "use v0.2.0",
		},
	}

	var buf bytes.Buffer
	require.NoError(t, emitSARIF(&buf, hits))
	out := buf.String()
	assert.Contains(t, out, `"name": "depscan"`)
	assert.Contains(t, out, `"id": "retracted"`)
	assert.Contains(t, out, `"id": "deprecated"`)
	assert.Contains(t, out, `"ruleId": "retracted"`)
	assert.Contains(t, out, `"ruleId": "deprecated"`)
	assert.Contains(t, out, `"name": "example.com/a@v1.0.0"`)
	assert.Contains(t, out, `"name": "example.com/b@v0.1.0"`)
	assert.Contains(t, out, `"latest": "v0.2.0"`)
}

func TestEmitFindings_UnknownFormatErrors(t *testing.T) {
	t.Parallel()
	err := emitFindings(&bytes.Buffer{}, "json", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown -format")
}
