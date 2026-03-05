//! Benchmarks for cryptographic operations in auths-core.
//!
//! Run with: cargo bench --package auths_core
#![allow(clippy::unwrap_used, clippy::expect_used)]

use auths_core::crypto::signer::{SeedSignerKey, SignerKey, decrypt_keypair, encrypt_keypair};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Generate a test Ed25519 keypair for benchmarking (ring, for encrypt/decrypt benches).
fn generate_test_keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key generation should succeed");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parsing should succeed")
}

/// Generate a SeedSignerKey for benchmarking the SignerKey trait.
fn generate_test_signer() -> SeedSignerKey {
    let (seed, pubkey) = auths_core::crypto::provider_bridge::generate_ed25519_keypair_sync()
        .expect("keypair generation should succeed");
    SeedSignerKey::new(seed, pubkey)
}

/// Benchmark Ed25519 keypair generation.
fn bench_key_generation(c: &mut Criterion) {
    let rng = SystemRandom::new();

    c.bench_function("ed25519_key_generation", |b| {
        b.iter(|| {
            let pkcs8 =
                Ed25519KeyPair::generate_pkcs8(&rng).expect("key generation should succeed");
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parsing should succeed")
        })
    });
}

/// Benchmark Ed25519 signing with different message sizes.
fn bench_sign(c: &mut Criterion) {
    let keypair = generate_test_keypair();

    let mut group = c.benchmark_group("ed25519_sign");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| keypair.sign(black_box(&data)))
        });
    }

    group.finish();
}

/// Benchmark Ed25519 signature verification with different message sizes.
fn bench_verify(c: &mut Criterion) {
    use ring::signature::{ED25519, UnparsedPublicKey};

    let keypair = generate_test_keypair();
    let public_key_bytes = keypair.public_key().as_ref();

    let mut group = c.benchmark_group("ed25519_verify");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];
        let signature = keypair.sign(&data);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
                public_key
                    .verify(black_box(&data), black_box(signature.as_ref()))
                    .expect("verification should succeed")
            })
        });
    }

    group.finish();
}

/// Benchmark key encryption (encrypt_keypair).
fn bench_key_encryption(c: &mut Criterion) {
    // Generate a sample PKCS#8 key
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key generation should succeed");
    let passphrase = "Bench-P@ss12345!";

    c.bench_function("key_encryption", |b| {
        b.iter(|| encrypt_keypair(black_box(pkcs8.as_ref()), black_box(passphrase)))
    });
}

/// Benchmark key decryption (decrypt_keypair).
fn bench_key_decryption(c: &mut Criterion) {
    // Generate and encrypt a sample key
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key generation should succeed");
    let passphrase = "Bench-P@ss12345!";
    let encrypted = encrypt_keypair(pkcs8.as_ref(), passphrase).expect("encryption should succeed");

    c.bench_function("key_decryption", |b| {
        b.iter(|| decrypt_keypair(black_box(&encrypted), black_box(passphrase)))
    });
}

/// Benchmark signing through the SignerKey trait.
fn bench_signer_trait(c: &mut Criterion) {
    let signer = generate_test_signer();
    let data = vec![0u8; 1024];

    c.bench_function("signer_trait_sign_1kb", |b| {
        b.iter(|| SignerKey::sign(&signer, black_box(&data)))
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_sign,
    bench_verify,
    bench_key_encryption,
    bench_key_decryption,
    bench_signer_trait,
);
criterion_main!(benches);
