# `tools/internal/findings`

Emits scanner findings in two formats: a human-readable text shape that agents can parse, and SARIF 2.1.0 for GitHub Code Scanning and other downstream consumers. The text format mirrors SARIF semantics so a reader who knows one understands the other.

## Purpose

Every scanner under `tools/` produces structured findings about Go modules in the dependency tree. Each finding carries a severity level, an owning tool name and rule identifier, the affected module path and version, plus a free-form property bag for extra detail. Without a shared package, each scanner shapes its output slightly differently and the agent reading the output has to learn each shape.

This package gives every scanner the same two emitters. Text output goes to stdout in a deterministic, parseable line shape. SARIF output goes through `owenrumney/go-sarif/v3` against the v2.1.0 schema for upload to Code Scanning.

## API

```go
// Level names the SARIF result severity vocabulary.
type Level string

const (
    LevelNote    Level = "note"
    LevelWarning Level = "warning"
    LevelError   Level = "error"
)

// NewRun returns a fresh SARIF run for the named tool, ready for
// AddResult calls. The run's tool driver records this package's
// information URI for upstream consumers that want to follow up.
func NewRun(toolName string) *sarif.Run

// AddResult attaches one finding to the run. The result's logical
// location carries the module path; the result's properties map
// receives the supplied key-value pairs.
func AddResult(run *sarif.Run, ruleID string, level Level, message, module, version string, props map[string]string)

// WriteSARIF marshals the SARIF run to w as JSON.
func WriteSARIF(w io.Writer, run *sarif.Run) error

// WriteText emits one finding to w in the canonical text shape:
//   <level>: <tool>/<rule>: <module>@<version> [<key>=<value> pairs]
// Properties sort alphabetically. Values containing whitespace, an
// equals sign, or a literal quote get double-quoted.
func WriteText(w io.Writer, level Level, tool, rule, module, version string, props map[string]string) error
```

## Text format

Each text line follows this shape:

```text
<level>: <tool>/<rule>: <module>@<version> [<key>=<value> pairs]
```

The level matches SARIF: `error`, `warning`, or `note`. Tool and rule come from the emitting scanner and map to the corresponding SARIF `ruleId`. Each trailing `key=value` pair lands in the SARIF property bag, alphabetized for deterministic output.

Quoting handles edge cases in value text. A value that contains whitespace, an equals sign, a literal quote, or any other character with parse-time meaning gets double-quoted on the way out.

## Consumers

- `tools/depscan`
- `tools/malscan`
- Future scanners that report findings against the dependency tree.

## Out of scope

- **Source-file locations.** Findings target Go module paths rather than source files. SARIF's logical location carries the module path; physical locations don't apply.
- **Findings stored to disk.** Each emit call writes to the supplied writer. Aggregation across runs falls to the caller.
- **Suppression handling.** Suppressing or grouping findings happens in the consuming scanner before the findings reach this package.
