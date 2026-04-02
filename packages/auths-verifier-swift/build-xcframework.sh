#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FRAMEWORK_NAME="AuthsVerifier"
LIB_NAME="auths_verifier_uniffi"

echo "=== Building AuthsVerifier XCFramework ==="
echo ""

# Check for required tools
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust toolchain."
    exit 1
fi

# Check for Apple targets
echo "Checking Rust targets..."
TARGETS=(
    "aarch64-apple-darwin"      # macOS Apple Silicon
    "aarch64-apple-ios"         # iOS device
    "aarch64-apple-ios-sim"     # iOS Simulator (Apple Silicon)
    "x86_64-apple-ios"          # iOS Simulator (Intel)
)

for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Installing target: $target"
        rustup target add "$target"
    fi
done

# Build for all Apple platforms
echo ""
echo "Building for Apple platforms..."

for target in "${TARGETS[@]}"; do
    echo "  Building $target..."
    cargo build --release --target "$target" 2>/dev/null || echo "  Warning: Failed to build $target (may not be available on this machine)"
done

# Generate Swift bindings
echo ""
echo "Generating Swift bindings..."
mkdir -p generated

# Use the native build to generate bindings
cargo run --bin uniffi-bindgen generate \
    --library target/release/lib${LIB_NAME}.dylib \
    --language swift \
    --out-dir generated

# Create framework directories
echo ""
echo "Creating XCFramework structure..."
rm -rf "${FRAMEWORK_NAME}.xcframework"

# Create header
mkdir -p generated/include
cat > generated/include/${FRAMEWORK_NAME}.h << 'HEADER'
#ifndef AuthsVerifier_h
#define AuthsVerifier_h

#include <stdint.h>
#include <stdbool.h>

// UniFFI-generated C bindings
// See the Swift file for the Swift API

#endif /* AuthsVerifier_h */
HEADER

# Create module map
cat > generated/include/module.modulemap << 'MODULEMAP'
module AuthsVerifierFFI {
    header "AuthsVerifier.h"
    export *
}
MODULEMAP

echo ""
echo "=== Build Complete ==="
echo ""
echo "Generated files in 'generated/' directory:"
echo "  - auths_verifier_uniffi.swift (Swift bindings)"
echo "  - include/ (C headers)"
echo ""
echo "Static libraries in 'target/<arch>/release/':"
for target in "${TARGETS[@]}"; do
    lib_path="target/${target}/release/lib${LIB_NAME}.a"
    if [ -f "$lib_path" ]; then
        echo "  - $lib_path"
    fi
done
echo ""
echo "To create a full XCFramework:"
echo "  1. Use xcodebuild -create-xcframework with the static libraries"
echo "  2. Or integrate directly using Swift Package Manager"
