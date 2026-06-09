# Programmatic Provisioning (SDK, no CLI subprocess)

The deployment kit provisions and off-boards orgs through the **`auths-sdk` workflows**
— the same domain logic the CLI calls. Agents, servers, and provisioning scripts use
these directly; they do **not** shell out to the `auths` binary. (Per the project's
domain-boundary rule, business logic lives in the SDK, never the presentation layer.)

All workflows take an `AuthsContext` (registry, key storage, clock, passphrase
provider) — build it once with `AuthsContext::builder()` and reuse it.

## The workflow surface

```rust
use auths_sdk::workflows::org::{
    // lifecycle
    create_org,            // (&ctx, name, &admin_alias, curve, metadata) -> OrgCreated
    add_member,            // mint a fresh member key (quick demos)
    add_existing_member,   // delegate to a member's OWN did:keri (off-boarding-grade)
    revoke_member,         // (&ctx, &org, &org_alias, member_did, reason) -> Option<SignedOffboardingRecord>
    list_members,          // KEL-authoritative roster (incl. revoked)

    // evidence + audit
    classify_authority_at_signing,  // -> AuthorityAtSigning (by KEL position)
    list_offboarding_records,       // the durable off-boarding log
    load_offboarding_record,        // one member's record
    verify_offboarding_record,      // signature + seal-binding check

    // air-gapped
    build_org_bundle,      // (&ctx, &org) -> AirGappedOrgBundle (URL-free, self-contained)
    verify_org_bundle,     // (&bundle, &pinned_roots, query) -> OfflineVerifyReport (zero network)
};
```

## Provisioning an org

```rust
use std::sync::Arc;
use auths_core::storage::keychain::KeyAlias;
use auths_crypto::CurveType;

let created = create_org(
    &ctx,
    "Acme Security",
    &KeyAlias::new_unchecked("org-acme"),
    CurveType::default(),     // P-256
    None,                      // optional extra metadata
)?;
let org_prefix = auths_id::keri::types::Prefix::new_unchecked(created.org_prefix.clone());
```

## Off-boarding and producing evidence

```rust
// Revoke a member's authority and capture the signed, seal-bound record.
let record = revoke_member(
    &ctx,
    &org_prefix,
    &KeyAlias::new_unchecked("org-acme"),
    "did:keri:EAlice...",
    Some("left the company".to_string()),
)?;
// `None` means the member was already off-boarded (idempotent — no duplicate record).
if let Some(signed) = record {
    println!("provably dead as-of KEL seq {}", signed.record.revoked_at_seq);
}
```

## Air-gapped packaging + offline verification

```rust
let bundle = build_org_bundle(&ctx, &org_prefix)?;
std::fs::write("acme.auths-offline", bundle.to_canonical_json()?)?;

// On the air-gapped side (no ctx, no network) — pure function of the bundle:
use auths_sdk::workflows::roots::parse_roots_typed;
let bundle = auths_sdk::workflows::org::AirGappedOrgBundle::from_json(&json)?;
let roots = parse_roots_typed(&std::fs::read_to_string(".auths/roots")?)?;
let member = auths_id::keri::types::Prefix::new_unchecked("EAlice...".to_string());
let report = verify_org_bundle(&bundle, &roots, Some((&member, Some(41))))?;
assert!(report.root_pinned);
// report.authority is AuthorizedBeforeRevocation | RejectedAfterRevocation { .. } | ...
```

## Notes

- **Curves are tagged in-band.** Pass a `CurveType`; never infer a curve from byte
  length.
- **Clock is injected.** `create_org` / `revoke_member` read `ctx.clock`; tests inject a
  `MockClock`. No workflow calls `Utc::now()` directly.
- **Typed identifiers.** Pinned roots are `Vec<IdentityDID>` and bundle identifiers are
  `IdentityDID` / `Prefix`, so a malformed identity fails closed at parse — not as an
  opaque string deep in verification.
- **Fail-closed.** `verify_org_bundle` returns a named error (`BundleIntegrity`,
  `BundleMissingMemberKel`, `BundleMissingDelegatorSeal`) on any incomplete/tampered
  bundle, and `root_pinned = false` for an untrusted org — never a silent "valid."
