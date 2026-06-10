//! Tests for the FFI configuration context (`ffi_context_new` / `ffi_context_free`)
//! and null-context rejection by keychain-backed FFI functions.

use auths_core::api::ffi::{
    FFI_ERR_NULL_CONTEXT, ffi_context_free, ffi_context_new, ffi_export_encrypted_key,
    ffi_export_public_key_openssh, ffi_key_exists, ffi_rotate_key,
};
use std::ffi::CString;
use std::ptr;

#[test]
fn context_new_with_null_config_falls_back_to_environment() {
    let ctx = unsafe { ffi_context_new(ptr::null()) };
    assert!(!ctx.is_null());
    unsafe { ffi_context_free(ctx) };
}

#[test]
fn context_new_with_valid_config_json_succeeds() {
    let json =
        CString::new(r#"{"keychain_backend":"memory","auths_home":"/tmp/auths-ffi-context-test"}"#)
            .unwrap();
    let ctx = unsafe { ffi_context_new(json.as_ptr()) };
    assert!(!ctx.is_null());

    let alias = CString::new("no-such-alias").unwrap();
    assert!(!unsafe { ffi_key_exists(ctx, alias.as_ptr()) });

    unsafe { ffi_context_free(ctx) };
}

#[test]
fn context_new_with_invalid_json_returns_null() {
    let json = CString::new("{not valid json").unwrap();
    assert!(unsafe { ffi_context_new(json.as_ptr()) }.is_null());
}

#[test]
fn context_new_with_unknown_fields_returns_null() {
    let json = CString::new(r#"{"keychain_backend":"memory","bogus_field":1}"#).unwrap();
    assert!(unsafe { ffi_context_new(json.as_ptr()) }.is_null());
}

#[test]
fn context_new_with_oversize_json_returns_null() {
    let oversize = format!(r#"{{"keychain_backend":"{}"}}"#, "x".repeat(70 * 1024));
    let json = CString::new(oversize).unwrap();
    assert!(unsafe { ffi_context_new(json.as_ptr()) }.is_null());
}

#[test]
fn context_free_tolerates_null() {
    unsafe { ffi_context_free(ptr::null_mut()) };
}

#[test]
fn key_exists_rejects_null_context() {
    let alias = CString::new("some-alias").unwrap();
    assert!(!unsafe { ffi_key_exists(ptr::null(), alias.as_ptr()) });
}

#[test]
fn rotate_key_rejects_null_context() {
    let alias = CString::new("some-alias").unwrap();
    let passphrase = CString::new("hunter2").unwrap();
    let code = unsafe { ffi_rotate_key(ptr::null(), alias.as_ptr(), passphrase.as_ptr()) };
    assert_eq!(code, FFI_ERR_NULL_CONTEXT);
}

#[test]
fn export_encrypted_key_rejects_null_context() {
    let alias = CString::new("some-alias").unwrap();
    let mut out_len: usize = 1;
    let buf = unsafe { ffi_export_encrypted_key(ptr::null(), alias.as_ptr(), &mut out_len) };
    assert!(buf.is_null());
    assert_eq!(out_len, 0);
}

#[test]
fn export_public_key_openssh_rejects_null_context() {
    let alias = CString::new("some-alias").unwrap();
    let passphrase = CString::new("hunter2").unwrap();
    let s =
        unsafe { ffi_export_public_key_openssh(ptr::null(), alias.as_ptr(), passphrase.as_ptr()) };
    assert!(s.is_null());
}

#[test]
fn valid_context_reaches_keychain_for_missing_key() {
    let json = CString::new(r#"{"keychain_backend":"memory"}"#).unwrap();
    let ctx = unsafe { ffi_context_new(json.as_ptr()) };
    assert!(!ctx.is_null());

    let alias = CString::new("missing-key").unwrap();
    let mut out_len: usize = 1;
    let buf = unsafe { ffi_export_encrypted_key(ctx, alias.as_ptr(), &mut out_len) };
    assert!(buf.is_null());
    assert_eq!(out_len, 0);

    unsafe { ffi_context_free(ctx) };
}
