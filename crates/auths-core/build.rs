//! Build script for auths-core.
//!
//! On macOS with the `keychain-secure-enclave` feature, compiles the Swift
//! CryptoKit bridge library and links it. No-op on other platforms.

// Build scripts legitimately need env vars, process commands, and unwrap —
// they run at compile time, not in production.
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::unwrap_used,
    clippy::expect_used
)]

fn main() {
    #[cfg(target_os = "macos")]
    if std::env::var("CARGO_FEATURE_KEYCHAIN_SECURE_ENCLAVE").is_ok() {
        build_swift_bridge();
    }
}

#[cfg(target_os = "macos")]
fn build_swift_bridge() {
    use std::process::Command;

    let swift_src = format!(
        "{}/swift/SecureEnclaveBridge.swift",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let lib_path = format!("{out_dir}/libauths_se.a");

    // Get macOS SDK path
    let sdk_output = Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .expect("xcrun not found — Xcode Command Line Tools required");
    let sdk_path = String::from_utf8(sdk_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Compile Swift to static library
    let status = Command::new("swiftc")
        .args([
            &swift_src,
            "-emit-library",
            "-static",
            "-parse-as-library",
            "-module-name",
            "auths_se",
            "-sdk",
            &sdk_path,
            "-O",
            "-o",
            &lib_path,
        ])
        .status()
        .expect("swiftc not found — Swift toolchain required for Secure Enclave support");

    assert!(
        status.success(),
        "Swift compilation failed for SecureEnclaveBridge.swift"
    );

    // Find Swift runtime library paths for linking.
    // Parse the JSON output manually to avoid a serde_json build-dependency.
    let target_info = Command::new("swift")
        .args(["-print-target-info"])
        .output()
        .expect("swift -print-target-info failed");
    let info_str = String::from_utf8_lossy(&target_info.stdout);
    if let Some(start) = info_str.find("\"runtimeLibraryPaths\"") {
        let after = &info_str[start..];
        if let Some(bracket_start) = after.find('[')
            && let Some(bracket_end) = after[bracket_start..].find(']')
        {
            let array_str = &after[bracket_start + 1..bracket_start + bracket_end];
            for part in array_str.split(',') {
                let path = part.trim().trim_matches('"').trim();
                if !path.is_empty() {
                    println!("cargo:rustc-link-search=native={path}");
                }
            }
        }
    }

    // Link our static library
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=auths_se");

    // Link Apple frameworks used by Swift code
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    println!("cargo:rustc-link-lib=framework=Security");

    // Rerun if Swift source changes
    println!("cargo:rerun-if-changed=swift/SecureEnclaveBridge.swift");
}
