// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package trailers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/proofhouse/proofhouse-go/tools/commit-trailers/trailers"
)

func TestCheck(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		msg       string
		wantErrIs []error
	}{
		{
			name: "valid: both trailers in order, kernel format",
			msg: `feat: add thing

Body line.

Assisted-by: claude-code:opus-4.7
Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
		},
		{
			name: "valid: kernel format with optional tool list",
			msg: `feat: add thing

Assisted-by: claude-code:opus-4.7 coccinelle sparse
Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
		},
		{
			name: "valid: only Signed-off-by (hand-written, no LLM)",
			msg: `feat: add thing

Hand-written body.

Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
		},
		{
			name: "valid: human Co-authored-by passes",
			msg: `feat: add thing

Co-authored-by: Alice Example <alice@example.com>
Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
		},
		{
			name: "invalid: order rule fires when Signed-off-by precedes Assisted-by",
			msg: `feat: add thing

Signed-off-by: Tony Burns <tony@tonyburns.net>
Assisted-by: claude-code:opus-4.7
`,
			wantErrIs: []error{trailers.ErrTrailerOrder},
		},
		{
			name: "invalid: slash format (pre-kernel-policy) is rejected",
			msg: `feat: add thing

Assisted-by: claude-code/opus-4.7
Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
			wantErrIs: []error{trailers.ErrAssistedByFormat},
		},
		{
			name: "invalid: Assisted-by missing model version",
			msg: `feat: add thing

Assisted-by: claude-code
Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
			wantErrIs: []error{trailers.ErrAssistedByFormat},
		},
		{
			name: "invalid: Co-authored-by attributing to Claude",
			msg: `fix: tweak something

Co-authored-by: Claude <noreply@anthropic.com>
Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
			wantErrIs: []error{trailers.ErrCoAuthoredByForbiddenLLM},
		},
		{
			name: "invalid: Co-authored-by attributing to GitHub Copilot",
			msg: `docs: update readme

Co-authored-by: GitHub Copilot <copilot@github.com>
Signed-off-by: Tony Burns <tony@tonyburns.net>
`,
			wantErrIs: []error{trailers.ErrCoAuthoredByForbiddenLLM},
		},
		{
			name: "invalid: multiple rule failures combine",
			msg: `feat: add thing

Co-authored-by: ChatGPT <ai@example.com>
Signed-off-by: Tony Burns <tony@tonyburns.net>
Assisted-by: claude-code/opus-4.7
`,
			wantErrIs: []error{
				trailers.ErrCoAuthoredByForbiddenLLM,
				trailers.ErrAssistedByFormat,
				trailers.ErrTrailerOrder,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := trailers.Check(tc.msg)
			if len(tc.wantErrIs) == 0 {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, want := range tc.wantErrIs {
				assert.ErrorIs(t, err, want)
			}
		})
	}
}
