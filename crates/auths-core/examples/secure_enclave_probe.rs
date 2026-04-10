#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]
//! Secure Enclave day-1 viability probe for P-256 key operations.
//!
//! Run: cargo run --example secure_enclave_probe -p auths-core
//!
//! Tests whether a Rust CLI binary can create a P-256 key in the Secure
//! Enclave, sign with it, convert the DER signature to raw r||s, and
//! verify with the p256 crate.

#[cfg(target_os = "macos")]
fn main() {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::kCFBooleanTrue;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework::key::{Algorithm, SecKey};
    use security_framework_sys::item::{
        kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave, kSecPrivateKeyAttrs,
    };
    use std::os::raw::c_void;
    use std::ptr;

    println!("=== Secure Enclave P-256 Viability Probe ===\n");

    // Report hardware
    let chip = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    println!("Hardware: {}\n", chip);

    // Step 1: Create P-256 key in Secure Enclave using high-level API
    println!("Step 1: Creating P-256 key in Secure Enclave...");

    // Build the attributes dictionary using raw CFDictionaryCreate
    // (the high-level SecKey::generate API doesn't expose Token::SecureEnclave
    // in all versions, so we build the dict manually)
    let key_result = unsafe {
        let label = CFString::new("com.auths.probe.secure-enclave-test");
        let key_size = CFNumber::from(256i32);

        // Private key attributes sub-dict
        let priv_keys = [
            kSecAttrIsPermanent as *const c_void,
            kSecAttrLabel as *const c_void,
        ];
        let priv_vals = [
            kCFBooleanTrue as *const c_void,
            label.as_CFTypeRef() as *const c_void,
        ];
        let priv_dict = core_foundation::dictionary::CFDictionaryCreate(
            ptr::null(),
            priv_keys.as_ptr(),
            priv_vals.as_ptr(),
            2,
            &core_foundation::dictionary::kCFTypeDictionaryKeyCallBacks,
            &core_foundation::dictionary::kCFTypeDictionaryValueCallBacks,
        );

        // Main params dict
        let param_keys = [
            kSecAttrKeyType as *const c_void,
            kSecAttrKeySizeInBits as *const c_void,
            kSecAttrTokenID as *const c_void,
            kSecPrivateKeyAttrs as *const c_void,
        ];
        let param_vals = [
            kSecAttrKeyTypeECSECPrimeRandom as *const c_void,
            key_size.as_CFTypeRef() as *const c_void,
            kSecAttrTokenIDSecureEnclave as *const c_void,
            priv_dict as *const c_void,
        ];
        let params = core_foundation::dictionary::CFDictionaryCreate(
            ptr::null(),
            param_keys.as_ptr(),
            param_vals.as_ptr(),
            4,
            &core_foundation::dictionary::kCFTypeDictionaryKeyCallBacks,
            &core_foundation::dictionary::kCFTypeDictionaryValueCallBacks,
        );

        // Wrap as CFDictionary for the high-level API
        let cf_params = CFDictionary::wrap_under_create_rule(params);
        core_foundation::base::CFRelease(priv_dict as _);

        SecKey::generate(cf_params)
    };

    match key_result {
        Ok(private_key) => {
            println!("  PASS: Key created successfully");

            // Step 2: Export public key
            println!("\nStep 2: Exporting public key...");
            match private_key.public_key() {
                Some(pub_key) => {
                    match pub_key.external_representation() {
                        Some(data) => {
                            let uncompressed = data.to_vec();
                            println!("  Uncompressed: {} bytes (expected 65)", uncompressed.len());

                            if uncompressed.len() == 65 && uncompressed[0] == 0x04 {
                                let mut compressed = vec![0u8; 33];
                                compressed[0] = if uncompressed[64] & 1 == 0 {
                                    0x02
                                } else {
                                    0x03
                                };
                                compressed[1..33].copy_from_slice(&uncompressed[1..33]);
                                println!(
                                    "  Compressed:   {} bytes, prefix 0x{:02x}",
                                    compressed.len(),
                                    compressed[0]
                                );
                                println!("  PASS: Public key exported and compressed");

                                // Step 3: Sign
                                println!("\nStep 3: Signing (may prompt for Touch ID)...");
                                let message = b"auths secure enclave probe test message";
                                match private_key.create_signature(
                                    Algorithm::ECDSASignatureMessageX962SHA256,
                                    message,
                                ) {
                                    Ok(der_sig) => {
                                        println!("  PASS: Signature ({} bytes DER)", der_sig.len());

                                        // Step 4: DER to raw r||s
                                        println!("\nStep 4: DER to raw r||s...");
                                        match der_to_raw_rs(&der_sig) {
                                            Ok(raw) => {
                                                println!("  PASS: {} bytes", raw.len());

                                                // Step 5: Verify with p256
                                                println!("\nStep 5: Verifying with p256 crate...");
                                                match verify_with_p256(&compressed, message, &raw) {
                                                    Ok(()) => {
                                                        println!("  PASS: Verified!");
                                                        println!("\n=== RESULT: WORKS ===");
                                                        println!(
                                                            "Secure Enclave P-256 viable for KERI."
                                                        );
                                                    }
                                                    Err(e) => {
                                                        println!("  FAIL: {e}");
                                                        println!(
                                                            "\n=== RESULT: WORKS WITH CAVEATS ==="
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("  FAIL: {e}");
                                                println!("\n=== RESULT: WORKS WITH CAVEATS ===");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        println!("  FAIL: {e}");
                                        println!("\n=== RESULT: WORKS WITH CAVEATS ===");
                                    }
                                }
                            } else {
                                println!("  FAIL: unexpected format");
                                println!("\n=== RESULT: WORKS WITH CAVEATS ===");
                            }
                        }
                        None => {
                            println!("  FAIL: no external representation");
                            println!("\n=== RESULT: WORKS WITH CAVEATS ===");
                        }
                    }
                }
                None => {
                    println!("  FAIL: no public key");
                    println!("\n=== RESULT: WORKS WITH CAVEATS ===");
                }
            }
        }
        Err(e) => {
            println!("  FAIL: {e}");
            let msg = format!("{e}");
            if msg.contains("-34018") {
                println!("\n  Error -34018 = errSecMissingEntitlement");
                println!("  Binary needs code signing for Secure Enclave.");
                println!("  Try: codesign -s - target/debug/examples/secure_enclave_probe");
            }
            println!("\n=== RESULT: FAILS ===");
            println!("Defer Secure Enclave. Ship software-only P-256.");
        }
    }
}

#[cfg(target_os = "macos")]
fn der_to_raw_rs(der: &[u8]) -> Result<Vec<u8>, String> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err("not DER SEQUENCE".into());
    }
    let mut p = 2;
    if der[p] != 0x02 {
        return Err("expected INTEGER for r".into());
    }
    p += 1;
    let rl = der[p] as usize;
    p += 1;
    let r = &der[p..p + rl];
    p += rl;
    if der[p] != 0x02 {
        return Err("expected INTEGER for s".into());
    }
    p += 1;
    let sl = der[p] as usize;
    p += 1;
    let s = &der[p..p + sl];
    let r = strip_zeros(r);
    let s = strip_zeros(s);
    if r.len() > 32 || s.len() > 32 {
        return Err("r or s too large".into());
    }
    let mut out = vec![0u8; 64];
    out[32 - r.len()..32].copy_from_slice(r);
    out[64 - s.len()..64].copy_from_slice(s);
    Ok(out)
}

#[cfg(target_os = "macos")]
fn strip_zeros(b: &[u8]) -> &[u8] {
    &b[b.iter().position(|&x| x != 0).unwrap_or(b.len())..]
}

#[cfg(target_os = "macos")]
fn verify_with_p256(compressed: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let vk = VerifyingKey::from_sec1_bytes(compressed).map_err(|e| format!("{e}"))?;
    let s = Signature::from_slice(sig).map_err(|e| format!("{e}"))?;
    vk.verify(msg, &s).map_err(|e| format!("{e}"))
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("This probe only runs on macOS.");
    println!("\n=== RESULT: NOT APPLICABLE ===");
}
