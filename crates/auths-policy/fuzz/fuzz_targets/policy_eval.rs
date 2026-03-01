#![no_main]

use auths_policy::{
    CanonicalDid,
    compile, compile_from_json,
    context::EvalContext,
    evaluate3, evaluate_strict,
    expr::Expr,
};
use chrono::Utc;
use libfuzzer_sys::fuzz_target;

// These are hardcoded valid DIDs used only to construct a minimal evaluation context.
// The fuzzer is testing policy compilation and evaluation, not DID parsing.
const ISSUER: &str = "did:keri:issuer";
const SUBJECT: &str = "did:keri:subject";

fuzz_target!(|data: &[u8]| {
    // Path 1: compile_from_json exercises:
    //   - max_json_bytes limit (64 KiB default)
    //   - serde JSON parse of Expr
    //   - full compile pipeline: depth/node/list limits, DID/cap/glob validation
    let _ = compile_from_json(data);

    // Path 2: if data is a syntactically valid JSON Expr, compile it and evaluate.
    // This exercises the evaluator with arbitrary expression trees that pass compile.
    if let Ok(expr) = serde_json::from_slice::<Expr>(data) {
        if let Ok(policy) = compile(&expr) {
            // Use a fixed minimal context. We're not fuzzing context fields here —
            // we're verifying that evaluate_strict/evaluate3 never panic regardless
            // of the compiled expression shape.
            let issuer = CanonicalDid::parse(ISSUER).expect("hardcoded valid DID");
            let subject = CanonicalDid::parse(SUBJECT).expect("hardcoded valid DID");
            let ctx = EvalContext::new(Utc::now(), issuer, subject);

            // Both evaluation modes must return a Decision (Allow/Deny/Indeterminate),
            // never panic.
            let _ = evaluate_strict(&policy, &ctx);
            let _ = evaluate3(&policy, &ctx);
        }
    }
});
