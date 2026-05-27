// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/proofhouse/proofhouse-go/tools/depscan/pkgsite"
	"github.com/proofhouse/proofhouse-go/tools/internal/exitcode"
	"github.com/proofhouse/proofhouse-go/tools/internal/vendormod"
)

// errLookupFailure stands in for any non-not-found lookup error
// the fake client surfaces. Declared once so err113 stays quiet.
var errLookupFailure = errors.New("network failure")

// fakeVersionsClient drives evaluateModule and run from tests by
// returning a canned response (or error) per module path. The
// interface keeps run injectable so the table-driven cases below
// don't need to stand up an httptest server for every branch.
type fakeVersionsClient struct {
	responses map[string][]pkgsite.ModuleVersion
	errors    map[string]error
}

func (f *fakeVersionsClient) Versions(_ context.Context, module string) ([]pkgsite.ModuleVersion, error) {
	if err, ok := f.errors[module]; ok {
		return nil, err
	}
	if vs, ok := f.responses[module]; ok {
		return vs, nil
	}
	return nil, fmt.Errorf("%w: %s", pkgsite.ErrNotFound, module)
}

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

func TestCollectFindings(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/m", Version: "v1.2.3"}

	t.Run("empty version list yields no hits", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, collectFindings(mod, nil))
	})

	t.Run("non-matching versions yield no hits", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v1.2.3", LatestVersion: "v2.0.0", Retracted: false, Deprecated: false},
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Retracted: false, Deprecated: false},
		}
		assert.Nil(t, collectFindings(mod, versions))
	})

	t.Run("matching retracted version emits a retracted finding", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Retracted: false, Deprecated: false},
			{Version: "v1.2.3", LatestVersion: "v2.0.0", Retracted: true, RetractionReason: "checksum"},
		}
		got := collectFindings(mod, versions)
		require.Len(t, got, 1)
		assert.Equal(t, kindRetracted, got[0].kind)
		assert.Equal(t, "v1.2.3", got[0].version)
		assert.Equal(t, "checksum", got[0].reason)
	})

	t.Run("retracted at a different version is ignored", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Retracted: false},
			{Version: "v1.0.0", LatestVersion: "v2.0.0", Retracted: true, RetractionReason: "checksum"},
		}
		assert.Nil(t, collectFindings(mod, versions))
	})

	t.Run("latest version deprecated emits a deprecated finding", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v3.0.0", LatestVersion: "v3.0.0", Deprecated: true, DeprecationReason: "use v4"},
			{Version: "v1.2.3", LatestVersion: "v3.0.0", Deprecated: false},
		}
		got := collectFindings(mod, versions)
		require.Len(t, got, 1)
		assert.Equal(t, kindDeprecated, got[0].kind)
		assert.Equal(t, "v3.0.0", got[0].latest)
		assert.Equal(t, "use v4", got[0].reason)
	})

	t.Run("deprecation on a non-latest version is ignored", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v3.0.0", LatestVersion: "v3.0.0", Deprecated: false},
			{Version: "v1.2.3", LatestVersion: "v3.0.0", Deprecated: true, DeprecationReason: "use v3"},
		}
		assert.Nil(t, collectFindings(mod, versions))
	})

	t.Run("matching retraction and latest deprecation emit both findings", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Deprecated: true, DeprecationReason: "use v3"},
			{Version: "v1.2.3", LatestVersion: "v2.0.0", Retracted: true, RetractionReason: "checksum"},
		}
		got := collectFindings(mod, versions)
		require.Len(t, got, 2)
		// Order tracks the version slice: deprecated entry comes first.
		assert.Equal(t, kindDeprecated, got[0].kind)
		assert.Equal(t, kindRetracted, got[1].kind)
	})
}

func TestEvaluateModule(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/m", Version: "v1.0.0"}

	t.Run("not-found error is swallowed as a skip", func(t *testing.T) {
		t.Parallel()
		client := &fakeVersionsClient{errors: map[string]error{
			mod.Path: fmt.Errorf("%w: %s", pkgsite.ErrNotFound, mod.Path),
		}}
		got, err := evaluateModule(context.Background(), client, mod)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("other errors propagate wrapped", func(t *testing.T) {
		t.Parallel()
		client := &fakeVersionsClient{errors: map[string]error{mod.Path: errLookupFailure}}
		got, err := evaluateModule(context.Background(), client, mod)
		require.Error(t, err)
		require.ErrorIs(t, err, errLookupFailure)
		assert.Contains(t, err.Error(), "lookup versions")
		assert.Nil(t, got)
	})

	t.Run("happy path forwards to collectFindings", func(t *testing.T) {
		t.Parallel()
		client := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			mod.Path: {{Version: "v1.0.0", LatestVersion: "v1.0.0", Retracted: true, RetractionReason: "bad"}},
		}}
		got, err := evaluateModule(context.Background(), client, mod)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, kindRetracted, got[0].kind)
	})
}

// writeVendorModulesTxt drops a minimal vendor/modules.txt under dir
// so the run-level tests can drive vendormod.Read without spinning
// up a full go module.
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
		client := &fakeVersionsClient{}
		rc, err := run(context.Background(), t.TempDir(), "text", client, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, err.Error(), "read vendored modules")
	})

	t.Run("returns ToolFailure on an unknown -format", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/m v1.0.0\n## explicit\nexample.com/m\n")
		client := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/m": {{Version: "v1.0.0", LatestVersion: "v1.0.0"}},
		}}
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
		client := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/clean": {{Version: "v1.0.0", LatestVersion: "v1.0.0"}},
		}}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "text", client, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.Empty(t, out.String())
		assert.Contains(t, errOut.String(), "scanned 1 module(s), no findings")
	})

	t.Run("returns Findings with the summary banner when a hit lands", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/bad v1.0.0\n## explicit\nexample.com/bad\n")
		client := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/bad": {
				{Version: "v1.0.0", LatestVersion: "v1.0.0", Retracted: true, RetractionReason: "checksum"},
			},
		}}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "text", client, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.Findings, rc)
		assert.Contains(t, out.String(), "warning: depscan/retracted: example.com/bad@v1.0.0")
		assert.Contains(t, errOut.String(), "1 finding(s) across 1 module(s)")
	})

	t.Run("logs and skips lookup errors that aren't not-found", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir,
			"# example.com/ok v1.0.0\n## explicit\nexample.com/ok\n"+
				"# example.com/explode v2.0.0\n## explicit\nexample.com/explode\n",
		)
		client := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				"example.com/ok": {{Version: "v1.0.0", LatestVersion: "v1.0.0"}},
			},
			errors: map[string]error{
				"example.com/explode": errLookupFailure,
			},
		}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "text", client, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.Contains(t, errOut.String(), "depscan: example.com/explode: lookup versions: network failure")
		assert.Contains(t, errOut.String(), "scanned 2 module(s), no findings")
	})

	t.Run("not-found errors stay silent in errOut", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/private v1.0.0\n## explicit\nexample.com/private\n")
		client := &fakeVersionsClient{} // any module path returns ErrNotFound from the fake
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), dir, "text", client, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.NotContains(t, errOut.String(), "lookup versions")
		assert.Contains(t, errOut.String(), "scanned 1 module(s), no findings")
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
		// The error-log branch only fires when run returns a non-nil
		// error. Asserting the prefix confirms that branch executed.
		assert.Contains(t, errOut.String(), "depscan: read vendored modules:")
	})
}
