#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building auths-verifier-uniffi..."

# Build for the current platform (for development)
cargo build --release

# Generate Swift bindings
echo "Generating Swift bindings..."
cargo run --bin uniffi-bindgen generate \
    --library target/release/libauths_verifier_uniffi.dylib \
    --language swift \
    --out-dir generated

echo "Swift bindings generated in 'generated/' directory"
echo ""
echo "To use in your Swift project:"
echo "1. Copy the generated Swift file to your project"
echo "2. Copy libauths_verifier_uniffi.dylib to your project"
echo "3. Configure your Xcode project to link the library"
echo ""
echo "For a proper Swift Package, run: ./build-xcframework.sh"
