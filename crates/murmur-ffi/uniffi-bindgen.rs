// The UniFFI bindgen entrypoint (mirrors auths-mobile-ffi/uniffi-bindgen.rs).
// `cargo run --bin uniffi-bindgen -- generate ...` emits the Swift bindings the
// native shells import.
fn main() {
    uniffi::uniffi_bindgen_main()
}
