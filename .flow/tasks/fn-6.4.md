# fn-6.4 Add roundtrip test for Did string bridge

## Description

Add tests in `radicle-httpd/src/api/v1/delegates.rs` `mod routes` verifying:
- `did:key:z6Mk...` round-trips through both Did types with identical `to_string()` output
- `did:keri:E...` parses via `auths_radicle::Did`

### Key files
- `radicle-httpd/src/api/v1/delegates.rs` — test module

## Acceptance
- [x] `test_did_string_bridge_roundtrip` passes
- [x] `test_did_keri_parse` passes
