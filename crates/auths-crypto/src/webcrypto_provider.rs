use async_trait::async_trait;

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, SecureSeed};

/// WASM Ed25519 provider backed by the Web Crypto API.
///
/// Verification delegates to `SubtleCrypto.verify()` via `wasm-bindgen-futures`.
/// Signing and key generation are not available on WASM targets and return
/// [`CryptoError::UnsupportedTarget`] — callers can pattern-match on this
/// variant to implement fallback strategies (e.g., remote signing service).
///
/// Usage:
/// ```ignore
/// use auths_crypto::{CryptoProvider, WebCryptoProvider};
///
/// let provider = WebCryptoProvider;
/// provider.verify_ed25519(&pubkey, b"msg", &sig).await.unwrap();
/// ```
pub struct WebCryptoProvider;

#[cfg(target_arch = "wasm32")]
fn get_subtle_crypto() -> Result<web_sys::SubtleCrypto, CryptoError> {
    use wasm_bindgen::JsCast;

    let global = js_sys::global();
    let crypto: web_sys::Crypto = js_sys::Reflect::get(&global, &"crypto".into())
        .map_err(|_| CryptoError::OperationFailed("no crypto API available".into()))?
        .dyn_into()
        .map_err(|_| CryptoError::OperationFailed("crypto is not a Crypto object".into()))?;
    Ok(crypto.subtle())
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl CryptoProvider for WebCryptoProvider {
    async fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: pubkey.len(),
            });
        }

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::JsCast;
            use wasm_bindgen_futures::JsFuture;

            let subtle = get_subtle_crypto()?;

            let key_data = js_sys::Uint8Array::from(pubkey);
            let usages = js_sys::Array::of1(&wasm_bindgen::JsValue::from_str("verify"));

            let import_promise = subtle
                .import_key_with_str("raw", &key_data, "Ed25519", false, &usages)
                .map_err(|e| CryptoError::OperationFailed(format!("importKey failed: {e:?}")))?;

            let crypto_key: web_sys::CryptoKey = JsFuture::from(import_promise)
                .await
                .map_err(|e| CryptoError::OperationFailed(format!("importKey rejected: {e:?}")))?
                .unchecked_into();

            let verify_promise = subtle
                .verify_with_str_and_u8_array_and_u8_array(
                    "Ed25519",
                    &crypto_key,
                    signature,
                    message,
                )
                .map_err(|e| CryptoError::OperationFailed(format!("verify call failed: {e:?}")))?;

            let result = JsFuture::from(verify_promise)
                .await
                .map_err(|e| CryptoError::OperationFailed(format!("verify rejected: {e:?}")))?;

            if result.as_bool().unwrap_or(false) {
                Ok(())
            } else {
                Err(CryptoError::InvalidSignature)
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (message, signature);
            Err(CryptoError::OperationFailed(
                "WebCrypto only available on WASM targets".into(),
            ))
        }
    }

    async fn verify_p256(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::JsCast;
            use wasm_bindgen_futures::JsFuture;

            // WebCrypto P-256 wants an uncompressed SEC1 (65-byte) or a JWK.
            // If caller supplied compressed SEC1 (33 bytes), decompress first.
            // The decompressed buffer must outlive `pubkey_bytes`, so it's declared
            // in the feature-gated branch that actually populates it.
            #[cfg(feature = "native")]
            let uncompressed_owned: Vec<u8>;
            let pubkey_bytes: &[u8] = match pubkey.len() {
                65 => pubkey,
                33 => {
                    // Best-effort decompression via the p256 crate (compiled into wasm
                    // only if the p256 feature is pulled in — in pure-wasm builds
                    // without native we fall back to a clear error.)
                    #[cfg(feature = "native")]
                    {
                        use p256::ecdsa::VerifyingKey;
                        let vk = VerifyingKey::from_sec1_bytes(pubkey)
                            .map_err(|e| CryptoError::InvalidPrivateKey(format!("{e}")))?;
                        uncompressed_owned = vk.to_encoded_point(false).as_bytes().to_vec();
                        uncompressed_owned.as_slice()
                    }
                    #[cfg(not(feature = "native"))]
                    {
                        return Err(CryptoError::OperationFailed(
                            "WebCrypto P-256 requires uncompressed SEC1 (65 bytes); \
                             compressed->uncompressed conversion not wired in pure-wasm \
                             build. Supply 65-byte key."
                                .into(),
                        ));
                    }
                }
                other => {
                    return Err(CryptoError::InvalidKeyLength {
                        expected: crate::provider::P256_PUBLIC_KEY_LEN,
                        actual: other,
                    });
                }
            };

            let subtle = get_subtle_crypto()?;
            let key_data = js_sys::Uint8Array::from(pubkey_bytes);
            let algorithm = js_sys::Object::new();
            js_sys::Reflect::set(&algorithm, &"name".into(), &"ECDSA".into()).ok();
            js_sys::Reflect::set(&algorithm, &"namedCurve".into(), &"P-256".into()).ok();
            let usages = js_sys::Array::of1(&wasm_bindgen::JsValue::from_str("verify"));

            let import_promise = subtle
                .import_key_with_object("raw", &key_data, &algorithm, false, &usages)
                .map_err(|e| CryptoError::OperationFailed(format!("import_key: {e:?}")))?;
            let crypto_key: web_sys::CryptoKey = JsFuture::from(import_promise)
                .await
                .map_err(|e| CryptoError::OperationFailed(format!("import_key reject: {e:?}")))?
                .unchecked_into();

            let verify_algorithm = js_sys::Object::new();
            js_sys::Reflect::set(&verify_algorithm, &"name".into(), &"ECDSA".into()).ok();
            js_sys::Reflect::set(&verify_algorithm, &"hash".into(), &"SHA-256".into()).ok();

            let verify_promise = subtle
                .verify_with_object_and_u8_array_and_u8_array(
                    &verify_algorithm,
                    &crypto_key,
                    signature,
                    message,
                )
                .map_err(|e| CryptoError::OperationFailed(format!("verify: {e:?}")))?;

            let result = JsFuture::from(verify_promise)
                .await
                .map_err(|e| CryptoError::OperationFailed(format!("verify reject: {e:?}")))?;

            if result.as_bool().unwrap_or(false) {
                Ok(())
            } else {
                Err(CryptoError::InvalidSignature)
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (pubkey, message, signature);
            Err(CryptoError::OperationFailed(
                "WebCrypto only available on WASM targets".into(),
            ))
        }
    }

    async fn sign_ed25519(
        &self,
        _seed: &SecureSeed,
        _message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    async fn ed25519_public_key_from_seed(
        &self,
        _seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }
}
