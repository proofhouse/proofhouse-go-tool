set unstable := true
set positional-arguments := true

# Go project metadata

module := "github.com/proofhouse/proofhouse-go"
bin_name := "proofhouse-go"
bin_dir := "bin"

# golangci-lint version pin. golangci-lint is distributed as pre-built
# binaries with linter versions baked in, so we pin a Docker image by
# digest rather than `go install` it. Renovate's customManager
# (.github/renovate.json5, landing in a later commit) tracks the
# version + digest pair below via the comment marker.
#
# renovate: datasource=docker depName=golangci/golangci-lint
golangci_lint_version := "v2.12.2"
golangci_lint_image := "docker.io/golangci/golangci-lint:v2.12.2@sha256:5cceeef04e53efe1470638d4b4b4f5ceefd574955ab3941b2d9a68a8c9ad5240"

# Locate a Docker-compatible container runtime. Probe PATH first, then
# well-known install locations so the recipe still works inside agentic
# harnesses or sandboxes that strip /usr/local/bin from PATH. Override by
# setting CONTAINER_RUNTIME in the environment.
container_runtime := env("CONTAINER_RUNTIME", `bash -c '
    docker_path=$(command -v docker 2>/dev/null || true)
    podman_path=$(command -v podman 2>/dev/null || true)
    for p in "$docker_path" \
             /usr/local/bin/docker \
             /opt/homebrew/bin/docker \
             /Applications/Docker.app/Contents/Resources/bin/docker \
             "$HOME/.orbstack/bin/docker" \
             "$HOME/.rd/bin/docker" \
             "$podman_path" \
             /opt/podman/bin/podman; do
        if [ -n "$p" ] && [ -x "$p" ]; then echo "$p"; exit 0; fi
    done
    echo docker
'`)

# Container invocation prefix for golangci-lint. Mounts the working dir at
# /data and the host Go module cache so first-run resolution stays cheap.
# Shell substitutions evaluate at recipe-run time, not Justfile-parse time.
#
# DOCKER_CONFIG points at a fresh empty directory so docker skips the
# osxkeychain credential helper (public Docker Hub pulls don't need it,
# and sandboxed environments can't always reach the helper binary).
# PATH gets the runtime's directory prepended for cases where docker
# itself isn't on the calling shell's PATH.
golangci_lint := 'DOCKER_CONFIG="$(mktemp -d)" PATH="$(dirname ' + container_runtime + '):$PATH" ' + container_runtime + ' run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOLANGCI_LINT_CACHE=/tmp/golangci-lint-cache -v "$(go env GOMODCACHE):/go/pkg/mod" -v "$(pwd):/data" -w /data ' + golangci_lint_image + ' golangci-lint'

# go-arch-lint version pin. Same Docker-pin pattern as golangci-lint:
# the upstream image bundles the linter at a known version, and Renovate
# tracks the version + digest pair via the customManager in renovate.json5.
# Image is amd64-only; arm64 dev hosts run it via emulation.
#
# renovate: datasource=docker depName=fe3dback/go-arch-lint
go_arch_lint_version := "release-v1.15.0"
go_arch_lint_image := "docker.io/fe3dback/go-arch-lint:release-v1.15.0@sha256:5af4ee8cb2ea9b251b44a24e0df5f99bd4dd1005a2c4eb0fa0bc3e7d3fab9a9a"

# go-arch-lint invocation. Mounts project read-only since the linter only
# reads source. Does not set --user: the upstream image is built for root,
# and a read-only mount means root inside can't write to the host anyway.
go_arch_lint := 'DOCKER_CONFIG="$(mktemp -d)" PATH="$(dirname ' + container_runtime + '):$PATH" ' + container_runtime + ' run --rm -v "$(pwd):/app:ro" ' + go_arch_lint_image

# Build metadata. `date` is the *commit author date* (UTC, ISO-8601),
# not build invocation time, so two builds of the same commit produce
# identical binaries. `source_date_epoch` exports the same instant as
# a unix timestamp for downstream tooling (BuildKit, archive tooling)
# that honors SOURCE_DATE_EPOCH for reproducibility.
#
# `--abbrev=7` / `--short=7` pin the abbreviated hash length so two
# checkouts of the same commit produce the same string. Without this,
# git uses `core.abbrev=auto`, whose length depends on object count
# (shallow clones, freshly-packed repos, and aged working copies all
# differ). 7 matches goreleaser's `.ShortCommit`.

version := `git describe --tags --abbrev=7 2>/dev/null || git rev-parse --short=7 HEAD 2>/dev/null || echo "DEV"`
commit := `git rev-parse --short=7 HEAD 2>/dev/null || echo ""`
date := `TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown"`
source_date_epoch := `git log -1 --format=%ct 2>/dev/null || echo "0"`

# ldflags for build. -buildid= clears the build ID for bit-for-bit
# reproducibility across toolchains; -s -w strips the symbol table and
# DWARF info; -X injects the buildmeta package vars.

ldflags := "-s -w -buildid=" + " -X " + module + "/internal/buildmeta.Version=" + version + " -X " + module + "/internal/buildmeta.Commit=" + commit + " -X " + module + "/internal/buildmeta.Date=" + date

# Add GOPATH/bin to PATH for installed tools

export PATH := `go env GOPATH` + "/bin:" + env("PATH")

# Default recipe
default: lint-go test

# --- Setup ---

# Set up development environment. New contributors run this once after
# cloning. Idempotent: re-running upgrades dependencies and refreshes
# Vale's synced style packages.
setup:
    just install-brew
    just install-tools

# Install Homebrew dependencies from Brewfile.
install-brew:
    brew bundle check || brew bundle install

# Refresh non-brew tooling. Today that means Vale's synced style
# packages; grows as new sync-style tools land.
install-tools:
    vale sync

# --- Build ---

# CGO_ENABLED=0 removes the host C toolchain as a build input. -buildvcs=false
# avoids stamping VCS state, relevant when building from a dirty tree or a
# tarball, and required for bit-for-bit matches against CI builds.

# Build the binary
build:
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "{{ ldflags }}" -o {{ bin_dir }}/{{ bin_name }} ./cmd/proofhouse-go

# Install the binary to GOPATH/bin
install:
    CGO_ENABLED=0 go install -trimpath -buildvcs=false -ldflags "{{ ldflags }}" ./cmd/proofhouse-go

# Run the binary
run *args:
    go run -ldflags "{{ ldflags }}" ./cmd/proofhouse-go "$@"

# Clean build artifacts
clean:
    rm -rf {{ bin_dir }} dist coverage.out coverage.html coverage.txt

# --- Format ---

# Format Go code (uses golangci-lint formatters via the pinned Docker image)
format-go *args:
    {{ golangci_lint }} fmt {{ args }}

# Format Markdown files (whitespace, list markers, code fence styles).
# Rewrites in place. Pair with `fix-markdown` for semantic lint fixes.
format-markdown *args:
    rumdl fmt {{ if args == "" { "." } else { args } }}

# Format JSON / JS / TS files in place via biome's formatter.
format-config *args:
    biome format --write {{ if args == "" { "." } else { args } }}

# --- Fix ---

# Fix Go linting issues. `go fix` (Go 1.26+) runs the modernizer analyzers;
# the blog post (https://go.dev/blog/gofix) recommends running it to a fixed
# point — usually one extra pass picks up fixes that became valid after the
# first round. golangci-lint fmt + --fix run afterward.
fix-go *args:
    go fix {{ if args == "" { "./..." } else { args } }}
    go fix {{ if args == "" { "./..." } else { args } }}
    {{ golangci_lint }} fmt {{ args }}
    {{ golangci_lint }} run --fix --modules-download-mode=vendor {{ args }}

# Apply rumdl's auto-fixable rules to Markdown files. Complement to
# `format-markdown` (which only rewrites whitespace and ordering, not
# semantic lints).
fix-markdown *args:
    rumdl check --fix {{ if args == "" { "." } else { args } }}

# --- Lint ---

# Run every linter that operates on the source tree. Aggregator.
# Config, spelling, and workflow linters land on their own dedicated
# targets and join this recipe as they arrive.
lint: lint-go lint-go-modernize lint-go-deadcode lint-go-arch lint-prose lint-spelling lint-markdown lint-config lint-yaml

# Run Go linters (golangci-lint via the pinned Docker image, vendor-mode).
# --modules-download-mode=vendor matches `just build`, so the linter sees
# exactly the dependency set the compiler does and never falls back to
# the module proxy.
lint-go *args:
    {{ golangci_lint }} run --modules-download-mode=vendor {{ args }}

# Fail if `go fix` would modernize anything. Mirrors the vendor-drift check:
# contributors must run `just fix-go` before pushing.
[script]
lint-go-modernize:
    diff_output=$(go fix -diff ./... 2>&1)
    if [[ -n "$diff_output" ]]; then
        echo "go fix would modernize the tree — run 'just fix-go' and commit:" >&2
        echo "$diff_output" >&2
        exit 1
    fi

# Fail if `deadcode` finds unreachable functions starting from the binary
# entry points. Whole-program reachability complements the package-scoped
# `unused` linter in golangci-lint. The tool prints findings but exits 0,
# so any output is treated as failure.
[script]
lint-go-deadcode:
    output=$(go tool deadcode ./cmd/... 2>&1)
    if [[ -n "$output" ]]; then
        echo "deadcode found unreachable code — remove or justify:" >&2
        echo "$output" >&2
        exit 1
    fi

# Same as lint-go-deadcode but roots reachability at every test binary too.
# Noisier; intentionally not part of the default `lint` gate. Run before
# wholesale refactors to surface code only kept alive by tests.
[script]
lint-go-deadcode-tests:
    output=$(go tool deadcode -test ./... 2>&1)
    if [[ -n "$output" ]]; then
        echo "deadcode (with -test) found unreachable code:" >&2
        echo "$output" >&2
        exit 1
    fi

# Enforce intra-project layering rules from .go-arch-lint.yml. The
# compiler covers cycles and outside-org visibility; this catches the
# layer rules it can't (e.g., "cmd may depend on internal but not the
# reverse"). Pinned Docker image, same pattern as golangci-lint.
lint-go-arch:
    {{ go_arch_lint }} check --project-path /app

# Lint prose in Markdown files and source comments via vale. Glob
# excludes the LICENSE (canonical Apache 2.0 text), the auto-generated
# changelog, vale's own style packages, scratch dirs, and vendored
# code; the per-file-type rules in .vale.ini decide what else gets
# inspected.
lint-prose *args:
    vale --glob='!{LICENSE,CHANGELOG.md,.vale/*,tmp/*,vendor/*}' {{ if args == "" { "." } else { args } }}

# Check spelling across the tree against the project dictionary at
# .cspell-words.txt. cspell ignores binaries, generated files, and the
# vendor/ tree via the ignorePaths block in .cspell.jsonc.
lint-spelling *args:
    cspell --config .cspell.jsonc --no-summary --no-progress --no-must-find-files {{ if args == "" { "." } else { args } }}

# Lint Markdown files against the project's .rumdl.toml ruleset.
# rumdl handles structural lints (heading style, list marker style,
# code fence style); vale handles prose.
lint-markdown *args:
    rumdl check {{ if args == "" { "." } else { args } }}

# Lint JSON / JS / TS files via biome. Recommended ruleset, biome's
# own formatter; covers config files (biome.json, package.json, tsconfig)
# and any future scripts under .github/actions/ or tools/.
lint-config *args:
    biome check --files-ignore-unknown=true {{ if args == "" { "." } else { args } }}

# Lint YAML files (config, workflows, action definitions). --strict
# treats warnings as errors so the gate matches CI behavior; per-rule
# tuning lives in .yamllint.yaml.
lint-yaml *args:
    yamllint --strict {{ if args == "" { "." } else { args } }}

# --- Test ---

# Run tests
test *args:
    go test ./... "$@"

# Run tests with race detector. Slower than plain `just test`; pairs
# with goroutine-bearing code as it lands. Native fuzz targets discovered
# by the nightly workflow rerun under `-race` automatically when their
# function-under-test is reached from `-race` builds; for ad-hoc local
# runs use this recipe.
test-race:
    go test -race ./...

# --- Dependencies ---

# Tidy go.mod
tidy:
    go mod tidy

# Verify dependencies
verify:
    go mod verify

# Vendor dependencies into ./vendor. Vendoring makes new transitive
# dependencies show up as a visible diff at PR review time, turning the
# trust decision on each addition into a human one. The same pattern
# Cilium uses for its open-source CI.
vendor:
    go mod tidy
    go mod vendor

# Check that vendor/, go.mod, and go.sum are in sync. CI runs this on
# every PR; contributors run `just vendor` and commit the result.
vendor-check:
    #!/usr/bin/env bash
    set -euo pipefail
    go mod tidy
    go mod vendor
    if ! git diff --exit-code -- go.mod go.sum vendor/; then
        echo "vendor drift detected — run 'just vendor' and commit" >&2
        exit 1
    fi

# --- Utilities ---

# Print version information
version:
    @echo "Version: {{ version }}"
    @echo "Commit:  {{ commit }}"
    @echo "Date:    {{ date }}"

# Sync Vale styles and dictionaries. Run once after cloning the repo,
# and whenever .vale.ini's Packages list changes. CI runs this before
# `just lint-prose`.
vale-sync:
    vale sync
