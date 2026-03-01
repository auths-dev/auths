#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ANDROID_OUTPUT_DIR="android-lib"
LIB_NAME="auths_verifier_uniffi"

echo "=== Building AuthsVerifier for Android ==="
echo ""

# Check for required tools
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust toolchain."
    exit 1
fi

# Check for Android NDK
if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
    echo "Warning: ANDROID_NDK_HOME or NDK_HOME not set."
    echo "Attempting to find NDK in common locations..."

    # Common Android SDK/NDK paths
    POSSIBLE_PATHS=(
        "$HOME/Android/Sdk/ndk"
        "$HOME/Library/Android/sdk/ndk"
        "/usr/local/android-sdk/ndk"
    )

    for path in "${POSSIBLE_PATHS[@]}"; do
        if [ -d "$path" ]; then
            # Find the highest version NDK
            ANDROID_NDK_HOME=$(ls -d "$path"/*/ 2>/dev/null | sort -V | tail -n1 | sed 's:/$::')
            if [ -n "$ANDROID_NDK_HOME" ]; then
                echo "Found NDK at: $ANDROID_NDK_HOME"
                break
            fi
        fi
    done
fi

if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
    echo "Error: Could not find Android NDK. Please set ANDROID_NDK_HOME."
    echo ""
    echo "Install NDK via Android Studio: SDK Manager > SDK Tools > NDK"
    echo "Or via command line: sdkmanager 'ndk;25.2.9519653'"
    exit 1
fi

NDK_PATH="${ANDROID_NDK_HOME:-$NDK_HOME}"
echo "Using NDK at: $NDK_PATH"

# Check for Android targets
echo ""
echo "Checking Rust targets..."
ANDROID_TARGETS=(
    "aarch64-linux-android"    # ARM64
    "armv7-linux-androideabi"  # ARM32
    "x86_64-linux-android"     # x86_64 (emulator)
    "i686-linux-android"       # x86 (older emulators)
)

for target in "${ANDROID_TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Installing target: $target"
        rustup target add "$target"
    fi
done

# Configure cargo for Android cross-compilation
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/*/bin/armv7a-linux-androideabi21-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/*/bin/x86_64-linux-android21-clang"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/*/bin/i686-linux-android21-clang"

# Build for all Android targets
echo ""
echo "Building for Android targets..."

for target in "${ANDROID_TARGETS[@]}"; do
    echo "  Building $target..."
    cargo build --release --target "$target" 2>&1 | grep -E "(Compiling|Finished|error)" || true
done

# Generate Kotlin bindings
echo ""
echo "Generating Kotlin bindings..."
mkdir -p "$ANDROID_OUTPUT_DIR/src/main/kotlin"
mkdir -p "$ANDROID_OUTPUT_DIR/src/main/jniLibs"

# Build for host to generate bindings
cargo build --release
cargo run --bin uniffi-bindgen generate \
    --library target/release/libauths_verifier_uniffi.dylib \
    --language kotlin \
    --out-dir "$ANDROID_OUTPUT_DIR/src/main/kotlin"

# Copy native libraries to jniLibs
echo ""
echo "Copying native libraries..."

declare -A ABI_MAP
ABI_MAP["aarch64-linux-android"]="arm64-v8a"
ABI_MAP["armv7-linux-androideabi"]="armeabi-v7a"
ABI_MAP["x86_64-linux-android"]="x86_64"
ABI_MAP["i686-linux-android"]="x86"

for target in "${ANDROID_TARGETS[@]}"; do
    abi="${ABI_MAP[$target]}"
    lib_path="target/${target}/release/lib${LIB_NAME}.so"

    if [ -f "$lib_path" ]; then
        mkdir -p "$ANDROID_OUTPUT_DIR/src/main/jniLibs/$abi"
        cp "$lib_path" "$ANDROID_OUTPUT_DIR/src/main/jniLibs/$abi/"
        echo "  Copied lib${LIB_NAME}.so to jniLibs/$abi/"
    else
        echo "  Warning: $lib_path not found (cross-compilation may have failed)"
    fi
done

# Create build.gradle.kts for the Android library
cat > "$ANDROID_OUTPUT_DIR/build.gradle.kts" << 'GRADLE'
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.auths.verifier"
    compileSdk = 34

    defaultConfig {
        minSdk = 21

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("androidx.annotation:annotation:1.7.1")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
}
GRADLE

# Create AndroidManifest.xml
cat > "$ANDROID_OUTPUT_DIR/src/main/AndroidManifest.xml" << 'MANIFEST'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
</manifest>
MANIFEST

# Create proguard rules
cat > "$ANDROID_OUTPUT_DIR/proguard-rules.pro" << 'PROGUARD'
# UniFFI generated code
-keep class uniffi.** { *; }
-keep class com.auths.verifier.** { *; }
PROGUARD

cat > "$ANDROID_OUTPUT_DIR/consumer-rules.pro" << 'CONSUMER'
# UniFFI generated code
-keep class uniffi.** { *; }
-keep class com.auths.verifier.** { *; }
CONSUMER

echo ""
echo "=== Build Complete ==="
echo ""
echo "Android library generated in '$ANDROID_OUTPUT_DIR/' directory"
echo ""
echo "Structure:"
find "$ANDROID_OUTPUT_DIR" -type f | head -20
echo ""
echo "To use this library:"
echo "1. Copy '$ANDROID_OUTPUT_DIR/' to your Android project"
echo "2. Add it as a module in settings.gradle.kts: include(\":auths-verifier\")"
echo "3. Add the dependency: implementation(project(\":auths-verifier\"))"
