# `tools/internal/vendormod`

Parses `vendor/modules.txt` into a typed list of modules. Resolves replace directives so downstream scanners see one canonical record per dependency without each one re-writing the parser.

## Purpose

Two scanners under `tools/` audit the Go modules a project vendors, and more land over time. Each needs the same shape of data: the list of module paths and versions after replace directives apply. Without a shared parser, each scanner carries its own copy of the `vendor/modules.txt` reader and the parsers drift apart over time.

This package owns the parser. Scanners call `Read` (or `Parse` with an existing reader) and operate on the returned slice.

## API

```go
// Module names one entry in vendor/modules.txt after the parser
// resolves any replace directives. Only the fields downstream lookups
// need stay on the struct.
type Module struct {
    Path    string
    Version string
}

// Read returns the modules declared in modroot/vendor/modules.txt.
// Pass an empty modroot to read from the current working directory.
func Read(modroot string) ([]Module, error)

// Parse reads modules from an open reader. Read calls Parse internally;
// most consumers want Read.
func Parse(r io.Reader) ([]Module, error)
```

`Read` opens the file under `modroot/vendor/modules.txt` and delegates to `Parse`. Callers that already have an open reader (such as a test fixture) skip `Read` and call `Parse` directly.

## Format handling

`vendor/modules.txt` uses two relevant line shapes:

- `# <module-path> <version>` for modules without a replace directive.
- `# <original-path> <original-version> => <replacement-path> <replacement-version>` for modules with a replace directive.

The parser resolves the replace and emits the replacement path and version on the returned `Module`. Downstream scanners look up the real dependency without re-applying replace logic themselves.

Buffer sizing handles realistic line lengths. The scanner starts at 64 KiB per line and grows up to 1 MiB before failing, so a malformed line can't make the parser grow its buffer without bound.

## Consumers

- `tools/depscan`
- `tools/malscan`
- Future scanners that audit vendored dependencies.

## Out of scope

- **Module graph reasoning.** The parser returns the flat list of direct and transitive dependencies as `vendor/modules.txt` records them. Consumers that care about which module pulls in which other module read `go.mod` and `go.sum` themselves.
- **Replace-directive provenance.** The parser keeps the resolved replacement but drops the original path and version. A consumer that needs the original entry parses `vendor/modules.txt` itself.
- **Non-vendored layouts.** This package targets `vendor/modules.txt`. Projects without a vendor directory need a different code path.
