#!/usr/bin/env bash
#
# SessionStart hook for Claude Code.
#
# Persists session metadata as environment variables so subsequent Bash
# tool calls can read them (notably CLAUDE_SESSION_ID), and injects the
# same metadata into Claude's context via additionalContext. Empty
# fields are skipped in both outputs.
#
# Docs: https://code.claude.com/docs/en/hooks

set -euo pipefail

input=$(cat)

read_field() {
  jq -r --arg key "$1" '.[$key] // ""' <<<"$input"
}

session_id=$(read_field session_id)
transcript_path=$(read_field transcript_path)
session_cwd=$(read_field cwd)
session_source=$(read_field source)
session_model=$(read_field model)
agent_type=$(read_field agent_type)
project_dir=${CLAUDE_PROJECT_DIR:-}
remote=${CLAUDE_CODE_REMOTE:-}

emit_export() {
  local name=$1 value=$2
  [[ -n $value ]] || return 0
  printf 'export %s=%q\n' "$name" "$value"
}

emit_line() {
  local name=$1 value=$2
  [[ -n $value ]] || return 0
  printf -- '- %s=%s\n' "$name" "$value"
}

if [[ -n ${CLAUDE_ENV_FILE:-} ]]; then
  {
    emit_export CLAUDE_SESSION_ID "$session_id"
    emit_export CLAUDE_TRANSCRIPT_PATH "$transcript_path"
    emit_export CLAUDE_SESSION_CWD "$session_cwd"
    emit_export CLAUDE_SESSION_SOURCE "$session_source"
    emit_export CLAUDE_SESSION_MODEL "$session_model"
    emit_export CLAUDE_PROJECT_DIR "$project_dir"
    emit_export CLAUDE_AGENT_TYPE "$agent_type"
    emit_export CLAUDE_CODE_REMOTE "$remote"
  } >>"$CLAUDE_ENV_FILE"
fi

context="Session metadata (also exported as env vars to subsequent Bash tool calls):
$(
  emit_line CLAUDE_SESSION_ID "$session_id"
  emit_line CLAUDE_TRANSCRIPT_PATH "$transcript_path"
  emit_line CLAUDE_SESSION_CWD "$session_cwd"
  emit_line CLAUDE_SESSION_SOURCE "$session_source"
  emit_line CLAUDE_SESSION_MODEL "$session_model"
  emit_line CLAUDE_PROJECT_DIR "$project_dir"
  emit_line CLAUDE_AGENT_TYPE "$agent_type"
  emit_line CLAUDE_CODE_REMOTE "$remote"
)"

jq -n --arg ctx "$context" \
  '{hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: $ctx}}'
