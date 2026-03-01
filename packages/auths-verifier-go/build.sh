#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTHS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building auths-verifier for Go CGo ==="
echo ""

# Build the Rust library
echo "Building Rust library..."
cd "$AUTHS_ROOT"
cargo build --release -p auths_verifier

# Check library output
LIB_PATH="$AUTHS_ROOT/target/release"
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_FILE="libauths_verifier.dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_FILE="libauths_verifier.so"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

if [ ! -f "$LIB_PATH/$LIB_FILE" ]; then
    echo "Error: Library not found at $LIB_PATH/$LIB_FILE"
    exit 1
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "Library built at: $LIB_PATH/$LIB_FILE"
echo ""
echo "To use the Go package, set CGO environment variables:"
echo ""
echo "  export CGO_LDFLAGS=\"-L$LIB_PATH -lauths_verifier\""
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "  export DYLD_LIBRARY_PATH=\"$LIB_PATH:\$DYLD_LIBRARY_PATH\""
else
    echo "  export LD_LIBRARY_PATH=\"$LIB_PATH:\$LD_LIBRARY_PATH\""
fi
echo ""
echo "Then run your Go code:"
echo ""
echo "  cd $SCRIPT_DIR"
echo "  go test -v"
echo ""
echo "Or import in your Go project:"
echo ""
echo "  import verifier \"github.com/auths/auths/packages/auths-verifier-go\""
