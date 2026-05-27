set unstable := true
set positional-arguments := true

# Go project metadata

module := "github.com/proofhouse/proofhouse-go"
bin_name := "proofhouse-go"
bin_dir := "bin"

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
default: build

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

# --- Test ---

# Run tests
test *args:
    go test ./... "$@"

# --- Utilities ---

# Print version information
version:
    @echo "Version: {{ version }}"
    @echo "Commit:  {{ commit }}"
    @echo "Date:    {{ date }}"
