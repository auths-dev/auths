//! Statistical (dudect-style) check that secret comparison is constant-time.
//!
//! The `check_constant_time` xtask lint proves every secret compare *calls*
//! `subtle::ConstantTimeEq::ct_eq`; it cannot prove the *compiled* comparison runs in
//! input-independent time (the optimizer could lower it to a branch, or a future compare
//! could slip the lint). This measures it: it times the comparison across two input
//! classes and applies a Welch t-test, exactly as `dudect` does.
//!
//! It is self-validating. A timing test that cannot detect a leak proves nothing, so a
//! deliberately variable-time byte compare is included as a **negative control**: the
//! harness must flag *its* leak before the production `ct_eq` is required to show none.

use std::hint::black_box;
use std::time::Instant;
use subtle::ConstantTimeEq;

const LEN: usize = 32; // a key/MAC/channel-binding-sized secret
const BATCH: usize = 256; // comparisons per timed sample (amortizes timer overhead)
const SAMPLES: usize = 3000; // timed samples per input class, per round
const ROUNDS: usize = 5; // median over rounds — one noisy round can't decide the verdict
const KEEP: f64 = 0.5; // keep the cleanest lower fraction of samples (drop preemption spikes)

/// The production constant-time comparison — the primitive every secret-compare site uses.
fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A deliberately variable-time comparison (the negative control): it early-returns on the
/// first differing byte, so its run time leaks where two inputs first diverge.
fn naive_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

fn mean_var(x: &[u64]) -> (f64, f64) {
    let n = x.len() as f64;
    let mean = x.iter().map(|&v| v as f64).sum::<f64>() / n;
    let var = x.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var)
}

/// |Welch t| between two timing populations after trimming upper-tail outliers (the
/// scheduling spikes dudect discards by working in the lower percentiles).
fn welch_t(mut a: Vec<u64>, mut b: Vec<u64>) -> f64 {
    a.sort_unstable();
    b.sort_unstable();
    a.truncate((a.len() as f64 * KEEP) as usize);
    b.truncate((b.len() as f64 * KEEP) as usize);
    let (ma, va) = mean_var(&a);
    let (mb, vb) = mean_var(&b);
    let denom = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    ((ma - mb) / denom).abs()
}

/// Time `cmp` over two input classes — class L: the input equals the secret (a full-length
/// compare); class R: the input differs in the first byte (an early-out for a leaky compare)
/// — interleaved to cancel slow drift, and return the |t| between the two classes' timings.
fn leak_t(cmp: fn(&[u8], &[u8]) -> bool) -> f64 {
    let secret = [0x42u8; LEN];
    let input_l = secret;
    let mut input_r = secret;
    input_r[0] ^= 0xff;

    let mut tl = Vec::with_capacity(SAMPLES);
    let mut tr = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES * 2 {
        let (input, bucket) = if i % 2 == 0 {
            (&input_l, &mut tl)
        } else {
            (&input_r, &mut tr)
        };
        let start = Instant::now();
        for _ in 0..BATCH {
            black_box(cmp(black_box(&secret), black_box(input)));
        }
        bucket.push(start.elapsed().as_nanos() as u64);
    }
    welch_t(tl, tr)
}

fn median_leak_t(cmp: fn(&[u8], &[u8]) -> bool) -> f64 {
    let mut ts: Vec<f64> = (0..ROUNDS).map(|_| leak_t(cmp)).collect();
    ts.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    ts[ts.len() / 2]
}

/// The threshold sits in the wide gap between the two regimes, set from the measured |t|
/// across repeated runs: the constant-time `ct_eq` produces ~1–4, while the early-return
/// control produces ~3000–11000 — three orders of magnitude apart. 100 is near the
/// geometric midpoint, so both directions carry ~30× margin and a noisy CI runner cannot
/// flake it either way. The negative control re-verifies the lower bound (the control must
/// still exceed it) on every run.
const LEAK_THRESHOLD: f64 = 100.0;

#[test]
fn secret_comparison_is_constant_time() {
    let _ = leak_t(ct_compare); // warm up: page-in, branch predictor, CPU frequency

    let control = median_leak_t(naive_compare);
    let ct = median_leak_t(ct_compare);
    eprintln!(
        "[constant-time] naive(control) |t|={control:.1}  ct_eq |t|={ct:.1}  threshold={LEAK_THRESHOLD}"
    );

    assert!(
        control > LEAK_THRESHOLD,
        "negative control failed: the harness must detect the naive compare's leak, but |t|={control:.1} <= {LEAK_THRESHOLD} — the test has no detection power",
    );
    assert!(
        ct < LEAK_THRESHOLD,
        "subtle::ct_eq is not constant-time on this build: |t|={ct:.1} >= {LEAK_THRESHOLD} (the leaky control measured {control:.1})",
    );
}
