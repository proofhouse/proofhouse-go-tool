// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindingString(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"RETRACTED  example.com/a@v1.0.0 — checksum",
		finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "checksum"}.String(),
	)
	assert.Equal(t,
		"RETRACTED  example.com/a@v1.0.0 — no reason recorded",
		finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0"}.String(),
	)
	assert.Equal(t,
		"DEPRECATED example.com/b (using v0.1.0, latest v0.2.0) — use v0.2.0",
		finding{
			kind:    kindDeprecated,
			module:  "example.com/b",
			version: "v0.1.0",
			latest:  "v0.2.0",
			reason:  "use v0.2.0",
		}.String(),
	)
}
