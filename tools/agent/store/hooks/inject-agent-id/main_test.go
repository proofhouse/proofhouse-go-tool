// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRun_RewritesBashWithAgentID(t *testing.T) {
	t.Parallel()

	in := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "echo hi", "description": "say hi"},
		"agent_id": "abc-123",
		"agent_type": "Explore"
	}`
	var out bytes.Buffer
	run(strings.NewReader(in), &out)

	var got hookOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v\nraw: %s", err, out.String())
	}
	if got.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("event = %q, want PreToolUse", got.HookSpecificOutput.HookEventName)
	}
	if got.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("decision = %q, want allow", got.HookSpecificOutput.PermissionDecision)
	}
	gotCmd, ok := got.HookSpecificOutput.UpdatedInput["command"].(string)
	if !ok {
		t.Fatalf("updatedInput.command missing or not a string: %#v", got.HookSpecificOutput.UpdatedInput["command"])
	}
	wantCmd := "export CLAUDE_CODE_AGENT_ID='abc-123' CLAUDE_CODE_AGENT_TYPE='Explore'; echo hi"
	if gotCmd != wantCmd {
		t.Errorf("command = %q\nwant     = %q", gotCmd, wantCmd)
	}
	desc, ok := got.HookSpecificOutput.UpdatedInput["description"].(string)
	if !ok {
		t.Fatalf(
			"updatedInput.description missing or not a string: %#v",
			got.HookSpecificOutput.UpdatedInput["description"],
		)
	}
	if desc != "say hi" {
		t.Errorf("description not preserved through rewrite: %q", desc)
	}
}

func TestRun_PreservesEmptyAgentType(t *testing.T) {
	t.Parallel()

	in := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "true"},
		"agent_id": "abc-123"
	}`
	var out bytes.Buffer
	run(strings.NewReader(in), &out)

	var got hookOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v\nraw: %s", err, out.String())
	}
	gotCmd, ok := got.HookSpecificOutput.UpdatedInput["command"].(string)
	if !ok {
		t.Fatalf("updatedInput.command missing or not a string: %#v", got.HookSpecificOutput.UpdatedInput["command"])
	}
	wantCmd := "export CLAUDE_CODE_AGENT_ID='abc-123' CLAUDE_CODE_AGENT_TYPE=''; true"
	if gotCmd != wantCmd {
		t.Errorf("command = %q\nwant     = %q", gotCmd, wantCmd)
	}
}

func TestRun_SilentSkip(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"no agent_id (main agent)": `{
			"hook_event_name": "PreToolUse",
			"tool_name": "Bash",
			"tool_input": {"command": "echo hi"}
		}`,
		"non-Bash tool": `{
			"hook_event_name": "PreToolUse",
			"tool_name": "Read",
			"tool_input": {"file_path": "/tmp/x"},
			"agent_id": "abc-123"
		}`,
		"non-PreToolUse event": `{
			"hook_event_name": "PostToolUse",
			"tool_name": "Bash",
			"tool_input": {"command": "echo hi"},
			"agent_id": "abc-123"
		}`,
		"malformed JSON": `{not valid json`,
		"empty input":    ``,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			run(strings.NewReader(in), &out)
			if out.Len() != 0 {
				t.Errorf("expected empty stdout, got %q", out.String())
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want string
	}{
		{"abc", "'abc'"},
		{"", "''"},
		{"with space", "'with space'"},
		{"with'quote", `'with'\''quote'`},
		{`a'b'c`, `'a'\''b'\''c'`},
	}
	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
