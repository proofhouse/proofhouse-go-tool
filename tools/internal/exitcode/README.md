# `tools/internal/exitcode`

The exit-code convention every findings-reporting scanner under `tools/` follows. Three named integers wrapped in a package so the contract sits in one place and stays consistent across tools.

## Purpose

Scanners that emit findings need a stable way to signal their outcome to a caller. The contract has four parts:

- A clean run with no findings exits with `OK`.
- A run that completed but produced findings exits with `Findings`.
- A tool-level failure that prevented findings from materializing exits with `ToolFailure`.
- No code outside this range. Custom signals belong in stderr text, not in the exit number.

Without a shared convention, each scanner drifts toward its own numbering. This package pins the contract.

## API

```go
const (
    // OK signals that no findings surfaced and the tool ran to completion.
    OK = 0

    // Findings signals that at least one finding surfaced. The tool itself
    // ran to completion; the non-zero exit tells the caller to review the
    // output before proceeding.
    Findings = 1

    // ToolFailure signals that the tool itself failed (network error,
    // parse error, missing inputs, etc.) and couldn't list findings.
    // Callers should retry or escalate.
    ToolFailure = 2
)
```

Three integers. No types beyond `int`, no helper functions. Callers do `os.Exit(exitcode.Findings)` directly.

## Consumers

- `tools/depscan`
- `tools/malscan`
- `tools/validate-pr`
- Future scanners that follow the same findings-emit-and-exit pattern.

## Out of scope

- **Severity-aware exit codes.** The contract has one bucket for "any finding at all." A consumer that wants to exit differently for `error` versus `warning` findings does the bucketing itself and still maps to one of the three codes here.
- **Helper functions.** Naming each code suffices. Wrapping `os.Exit` would hide control flow that callers want to see.
