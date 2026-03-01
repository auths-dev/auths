#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building auths-verifier-uniffi for Kotlin..."

# Build for the current platform (for development)
cargo build --release

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
mkdir -p generated/kotlin

cargo run --bin uniffi-bindgen generate \
    --library target/release/libauths_verifier_uniffi.dylib \
    --language kotlin \
    --out-dir generated/kotlin

echo ""
echo "Kotlin bindings generated in 'generated/kotlin/' directory"
echo ""
echo "Generated files:"
ls -la generated/kotlin/
echo ""
echo "To use in your Android project:"
echo "1. Copy the generated Kotlin file to your Android project's source directory"
echo "2. Copy the native library to jniLibs/<arch>/"
echo "3. Configure your build.gradle to load the native library"
echo ""
echo "For a proper Android library, run: ./build-android.sh"
