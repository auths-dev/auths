//! Concurrency semantics: exactly-one-wins per sequence, and — the whole point
//! of this backend — concurrent onboarding of *different* identities that does
//! NOT serialize on a global lock (unlike the git single-writer backend).

use std::sync::{Arc, Barrier};
use std::thread;

use auths_id::ports::RegistryBackend;
use auths_id::ports::registry::RegistryError;

use super::support;

/// N writers race the same identity at seq 1 → exactly one INSERT wins the
/// `(tenant, prefix, seq)` primary key; the rest get `EventExists`.
#[test]
fn concurrent_appends_same_prefix_exactly_one_wins() {
    let Some(backend) = support::setup() else {
        return;
    };

    let (icp, prefix, _kp) = support::make_signed_icp();
    let icp_said = icp.said().as_str().to_string();
    backend.append_event(&prefix, &icp).unwrap();

    let thread_count = 8;
    let barrier = Arc::new(Barrier::new(thread_count));
    let ixn = support::make_signed_ixn(&prefix, 1, &icp_said);

    let handles: Vec<_> = (0..thread_count)
        .map(|_| {
            let backend = backend.clone();
            let barrier = Arc::clone(&barrier);
            let prefix = prefix.clone();
            let ixn = ixn.clone();
            thread::spawn(move || {
                barrier.wait();
                backend.append_event(&prefix, &ixn)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "exactly one writer should win seq 1, got {successes}"
    );

    // Every loser is a clean append-only refusal, never a corrupt/other error.
    for r in &results {
        if let Err(e) = r {
            assert!(
                matches!(e, RegistryError::EventExists { .. }),
                "loser should be EventExists, got {e:?}"
            );
        }
    }

    assert_eq!(backend.get_tip(&prefix).unwrap().sequence, 1);
}

/// N writers concurrently incept N *different* identities. Because they touch
/// different rows and share no lock, ALL succeed on the first attempt with zero
/// `ConcurrentModification` — the behavior the git backend cannot provide (there
/// they contend on `registry.lock` + a single-ref CAS and must retry).
#[test]
fn concurrent_onboarding_different_identities_does_not_serialize() {
    let Some(backend) = support::setup() else {
        return;
    };

    let thread_count = 16;
    let barrier = Arc::new(Barrier::new(thread_count));

    let inceptions: Vec<_> = (0..thread_count)
        .map(|_| {
            let (icp, prefix, _kp) = support::make_signed_icp();
            (icp, prefix)
        })
        .collect();

    let handles: Vec<_> = inceptions
        .into_iter()
        .map(|(icp, prefix)| {
            let backend = backend.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                // Single attempt — no retry loop. A global lock would force
                // ConcurrentModification here; this backend must not.
                backend.append_event(&prefix, &icp)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let concurrent_mods = results
        .iter()
        .filter(|r| matches!(r, Err(RegistryError::ConcurrentModification(_))))
        .count();
    assert_eq!(
        concurrent_mods, 0,
        "concurrent onboarding must not serialize on a global lock"
    );

    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, thread_count,
        "all {thread_count} distinct identities should onboard on the first try, got {successes}"
    );

    // All identities are visible.
    let mut count = 0usize;
    backend
        .visit_identities(&mut |_p| {
            count += 1;
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(count, thread_count);
}
