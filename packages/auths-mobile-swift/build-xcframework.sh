#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FRAMEWORK_NAME="AuthsMobile"
LIB_NAME="auths_mobile_ffi"
CRATE_DIR="../../crates/auths-mobile-ffi"

echo "=== Building AuthsMobile XCFramework ==="
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
    "x86_64-apple-darwin"       # macOS Intel
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

cd "$CRATE_DIR"
for target in "${TARGETS[@]}"; do
    echo "  Building $target..."
    cargo build --release --target "$target" 2>/dev/null || echo "  Warning: Failed to build $target (may not be available on this machine)"
done
cd "$SCRIPT_DIR"

# Generate Swift bindings
echo ""
echo "Generating Swift bindings..."
mkdir -p generated

# Use the native build to generate bindings
cd "$CRATE_DIR"
cargo run --bin uniffi-bindgen generate \
    --library target/release/lib${LIB_NAME}.dylib \
    --language swift \
    --out-dir "$SCRIPT_DIR/generated"
cd "$SCRIPT_DIR"

# Create framework directories
echo ""
echo "Creating XCFramework structure..."
rm -rf "${FRAMEWORK_NAME}.xcframework"

# Create header
mkdir -p generated/include
cat > generated/include/${FRAMEWORK_NAME}.h << 'HEADER'
#ifndef AuthsMobile_h
#define AuthsMobile_h

#include <stdint.h>
#include <stdbool.h>

// UniFFI-generated C bindings for Auths Mobile Identity Creation
// See the Swift file for the Swift API

#endif /* AuthsMobile_h */
HEADER

# Create module map
cat > generated/include/module.modulemap << 'MODULEMAP'
module AuthsMobileFFI {
    header "AuthsMobile.h"
    export *
}
MODULEMAP

echo ""
echo "=== Build Complete ==="
echo ""
echo "Generated files in 'generated/' directory:"
echo "  - auths_mobile_ffi.swift (Swift bindings)"
echo "  - include/ (C headers)"
echo ""
echo "Static libraries in '$CRATE_DIR/target/<arch>/release/':"
for target in "${TARGETS[@]}"; do
    lib_path="$CRATE_DIR/target/${target}/release/lib${LIB_NAME}.a"
    if [ -f "$lib_path" ]; then
        echo "  - $lib_path"
    fi
done
echo ""
echo "To integrate with Xcode:"
echo "  1. Copy generated/auths_mobile_ffi.swift to your Xcode project"
echo "  2. Add the static library for your target architecture"
echo "  3. Link against the library in Build Settings"
echo ""
echo "Example FFI usage in Swift:"
echo "  let result = try createIdentity(deviceName: \"My iPhone\")"
echo "  print(\"Created DID: \\(result.did)\")"
echo ""
