//! Domain-separation registry byte-value pin (fn-129.T3).
//!
//! Asserts every label constant in `auths_pairing_protocol::domain_separation`
//! matches its expected byte string. A rename or edit is a protocol-level
//! break (derived keys change); CI must fail before the change can merge.

use auths_pairing_protocol::domain_separation::{ENVELOPE_INFO, SAS_INFO, TRANSPORT_INFO};

#[test]
fn sas_info_label_is_stable() {
    assert_eq!(SAS_INFO, b"auths-pairing-sas-v1");
    assert_eq!(SAS_INFO.len(), 20);
}

#[test]
fn transport_info_label_is_stable() {
    assert_eq!(TRANSPORT_INFO, b"auths-pairing-transport-v1");
    assert_eq!(TRANSPORT_INFO.len(), 26);
}

#[test]
fn envelope_info_label_is_stable() {
    assert_eq!(ENVELOPE_INFO, b"auths-pairing-envelope-v1");
    assert_eq!(ENVELOPE_INFO.len(), 25);
}

/// Cross-check: all three labels are unique (preventing accidental
/// collision that would cause two derivations to produce the same output).
#[test]
fn all_labels_are_unique() {
    assert_ne!(SAS_INFO, TRANSPORT_INFO);
    assert_ne!(SAS_INFO, ENVELOPE_INFO);
    assert_ne!(TRANSPORT_INFO, ENVELOPE_INFO);
}

/// Cross-check: all labels share the `auths-pairing-` prefix (confirms
/// none drifted to a different crate's namespace).
#[test]
fn all_labels_share_prefix() {
    const PREFIX: &[u8] = b"auths-pairing-";
    for label in [SAS_INFO, TRANSPORT_INFO, ENVELOPE_INFO] {
        assert!(
            label.starts_with(PREFIX),
            "label {:?} missing prefix auths-pairing-",
            std::str::from_utf8(label).unwrap_or("<invalid utf8>")
        );
    }
}
