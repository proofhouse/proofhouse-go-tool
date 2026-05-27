set unstable := true
set positional-arguments := true

# Go project metadata

module := "github.com/proofhouse/proofhouse-go"
bin_name := "proofhouse-go"
bin_dir := "bin"

# Add GOPATH/bin to PATH for installed tools

export PATH := `go env GOPATH` + "/bin:" + env("PATH")

# Default recipe
default: build

# --- Build ---

# Build the binary
build:
    go build -o {{ bin_dir }}/{{ bin_name }} ./cmd/proofhouse-go

# Install the binary to GOPATH/bin
install:
    go install ./cmd/proofhouse-go

# Run the binary
run *args:
    go run ./cmd/proofhouse-go "$@"

# Clean build artifacts
clean:
    rm -rf {{ bin_dir }} dist coverage.out coverage.html coverage.txt

# --- Test ---

# Run tests
test *args:
    go test ./... "$@"
