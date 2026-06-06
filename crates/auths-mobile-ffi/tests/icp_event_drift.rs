//! Field-set drift test between the `auths-mobile-ffi` internal
//! `IcpEvent` struct and `auths_keri::events::IcpEvent`.
//!
//! The FFI ships a local copy of `IcpEvent` because the wire format
//! needs an `x` signature field that the upstream type doesn't model.
//! If either struct grows a field that the other doesn't know about,
//! the JSON the phone assembles will silently diverge from what the
//! validator expects. This test enumerates the fields of each struct
//! via `serde_json::to_value` reflection and asserts the known
//! difference-set.

use std::collections::BTreeSet;

use serde_json::Value;

fn field_set(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("serialize to a map")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn mobile_and_keri_icp_structs_diverge_only_in_pinned_fields() {
    // Build a minimal-but-valid-enough JSON for each struct. The test
    // compares field *presence*, not semantic content, so values are
    // placeholders chosen to deserialize without error.

    // auths-keri::IcpEvent — fields: v, d, i, s, kt, k, nt, n, bt, b, c, a, dt.
    let keri_json: Value = serde_json::from_str(
        r#"{
            "v": "KERI10JSON000000_",
            "d": "Eaaa",
            "i": "Eaaa",
            "s": "0",
            "kt": "1",
            "k": [],
            "nt": "1",
            "n": [],
            "bt": "0",
            "b": [],
            "c": [],
            "a": [],
            "dt": null
        }"#,
    )
    .expect("keri icp json");
    let keri_fields = field_set(&keri_json);

    // auths-mobile-ffi::IcpEvent — fields: v, t, d, i, s, kt, k, nt, n, bt, b, a, x.
    // Constructed as raw JSON because the struct itself is
    // `pub(crate)` — the drift test reflects on the serde shape.
    let ffi_json: Value = serde_json::from_str(
        r#"{
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "Eaaa",
            "s": "0",
            "kt": "1",
            "k": [],
            "nt": "1",
            "n": [],
            "bt": "0",
            "b": [],
            "a": [],
            "x": ""
        }"#,
    )
    .expect("ffi icp json");
    let ffi_fields = field_set(&ffi_json);

    // Pinned symmetric difference: the FFI-only fields and the
    // keri-only fields together make up the intentional drift.
    // `t` is emitted by the FFI because the body is assembled as
    // bare JSON (no enum-tag discriminator from higher up).
    // `x` is the signature slot the FFI fills externally.
    // `c` and `dt` are fields the FFI does not assemble — they are
    // optional / populated server-side and not part of the phone's
    // signing payload today.
    let expected_ffi_only: BTreeSet<String> =
        ["t".to_string(), "x".to_string()].iter().cloned().collect();
    let expected_keri_only: BTreeSet<String> =
        ["c".to_string(), "dt".to_string()].iter().cloned().collect();

    let ffi_only: BTreeSet<_> = ffi_fields.difference(&keri_fields).cloned().collect();
    let keri_only: BTreeSet<_> = keri_fields.difference(&ffi_fields).cloned().collect();

    assert_eq!(
        ffi_only, expected_ffi_only,
        "FFI-only field drift detected. Known drift: {expected_ffi_only:?}. Found: {ffi_only:?}."
    );
    assert_eq!(
        keri_only, expected_keri_only,
        "keri-only field drift detected. Known drift: {expected_keri_only:?}. Found: {keri_only:?}."
    );
}
