// Tests for workflows that moved to auths-api are commented out
// to avoid violating the one-way dependency rule (auths-api imports from auths-sdk, never reverse).
// These tests are now in auths-api/tests/ where the workflows live.
// mod allowed_signers;
// mod artifact;
// mod audit;
// mod ci_setup;  // imports deleted SDK services
// mod device;
// mod diagnostics;
// pub mod helpers;  // imports deleted SDK services
// mod org;
mod pairing;
// mod rotation;
// mod setup;  // imports deleted SDK services
mod ssh_key_upload;
