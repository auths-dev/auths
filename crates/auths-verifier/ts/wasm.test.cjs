// End-to-end test of the WASM verify exports against the committed cross-language fixtures.
//
// Build first:  cd crates/auths-verifier && wasm-pack build --target nodejs --no-default-features --features wasm
// Run:          node crates/auths-verifier/ts/wasm.test.cjs
//
// Proves the wasm-bindgen glue end-to-end: a valid presentation/credential bundle returns
// `{kind:"valid"}`, a revoked credential returns `{kind:"credentialRevoked"}`, and malformed
// input returns a typed `{kind:"malformedRequest"}` rather than throwing.

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const { verifyPresentationJson, verifyCredentialJson } = require("../pkg/auths_verifier.js");

const fixtures = path.join(__dirname, "..", "tests", "fixtures");
const read = (name) => readFileSync(path.join(fixtures, name), "utf8");

const presentation = JSON.parse(verifyPresentationJson(read("presentation_valid.json")));
assert.equal(presentation.schemaVersion, 1);
assert.equal(presentation.kind, "valid", `presentation: ${JSON.stringify(presentation)}`);

const credentialValid = JSON.parse(verifyCredentialJson(read("credential_valid.json")));
assert.equal(credentialValid.kind, "valid", `credential valid: ${JSON.stringify(credentialValid)}`);

const credentialRevoked = JSON.parse(verifyCredentialJson(read("credential_revoked.json")));
assert.equal(
  credentialRevoked.kind,
  "credentialRevoked",
  `credential revoked: ${JSON.stringify(credentialRevoked)}`,
);

// Malformed input must return a typed verdict, never throw.
const malformed = JSON.parse(verifyPresentationJson("{not json"));
assert.equal(malformed.kind, "malformedRequest");

console.log("wasm node test: OK (valid / valid / credentialRevoked / malformedRequest)");
