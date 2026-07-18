//! Shared harness for the Postgres registry integration tests.
//!
//! Self-provisions the `auths_registry_test` database on the local Postgres and
//! isolates every test by a unique tenant id, so all tests share one schema
//! without colliding. If Postgres is unreachable, [`setup`]/[`connect_only`]
//! print a clear skip and return `None`.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use auths_core::crypto::said::{compute_next_commitment, compute_said};
use auths_id::keri::KeriSequence;
use auths_id::keri::event::{Event, IcpEvent, IxnEvent};
use auths_id::keri::seal::Seal;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::validate::finalize_icp_event;
use auths_id::ports::RegistryBackend;
use auths_id::ports::registry::ValidatedTenantId;
use auths_keri::{CesrKey, Threshold, VersionString};
use auths_storage::postgres::{PostgresAdapter, create_database_if_absent};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const TEST_DB: &str = "auths_registry_test";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn db_user() -> String {
    std::env::var("PGUSER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "postgres".to_string())
}

/// Maintenance-database URL used to `CREATE DATABASE` the test DB.
pub fn admin_url() -> String {
    std::env::var("AUTHS_TEST_ADMIN_DATABASE_URL")
        .unwrap_or_else(|_| format!("postgres://{}@127.0.0.1:5432/postgres", db_user()))
}

/// URL of the dedicated test database.
pub fn test_url() -> String {
    std::env::var("AUTHS_TEST_DATABASE_URL")
        .unwrap_or_else(|_| format!("postgres://{}@127.0.0.1:5432/{}", db_user(), TEST_DB))
}

/// A fresh, unique tenant id (per process + time + counter) for test isolation.
pub fn unique_tenant() -> ValidatedTenantId {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    ValidatedTenantId::new(format!("t{pid}x{nanos}x{n}")).expect("valid tenant id")
}

fn ensure_database() -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot build runtime: {e}"))?;
    let result = rt.block_on(create_database_if_absent(&admin_url(), TEST_DB));
    result.map_err(|e| format!("cannot provision {TEST_DB}: {e}"))
}

/// Connect a fresh single-tenant adapter (migrated but NOT `init_if_needed`).
///
/// Returns `None` with a printed skip if Postgres is unreachable.
pub fn connect_only() -> Option<PostgresAdapter> {
    if let Err(e) = ensure_database() {
        eprintln!("SKIP postgres registry test: {e}");
        return None;
    }
    match PostgresAdapter::connect_for_tenant(&test_url(), unique_tenant()) {
        Ok(adapter) => Some(adapter),
        Err(e) => {
            eprintln!(
                "SKIP postgres registry test: cannot connect to {}: {e}",
                test_url()
            );
            None
        }
    }
}

/// Connect a fresh single-tenant adapter and run `init_if_needed`.
pub fn setup() -> Option<PostgresAdapter> {
    let adapter = connect_only()?;
    adapter.init_if_needed().expect("init_if_needed");
    Some(adapter)
}

/// Build a finalized, self-certifying inception event and its prefix.
pub fn make_signed_icp() -> (Event, Prefix, Ed25519KeyPair) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key_encoded = auths_keri::KeriPublicKey::ed25519(keypair.public_key().as_ref())
        .unwrap()
        .to_qb64()
        .unwrap();

    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
    let next_commitment = compute_next_commitment(
        &auths_keri::KeriPublicKey::ed25519(next_keypair.public_key().as_ref()).unwrap(),
    );

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(key_encoded)],
        nt: Threshold::Simple(1),
        n: vec![next_commitment],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    };

    let finalized = finalize_icp_event(icp).unwrap();
    let prefix = finalized.i.clone();
    (Event::Icp(finalized), prefix, keypair)
}

/// Build a self-addressing interaction event at a given sequence.
pub fn make_signed_ixn(prefix: &Prefix, seq: u128, prev_said: &str) -> Event {
    let mut ixn = IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: Said::new_unchecked(prev_said.to_string()),
        a: vec![Seal::digest("EPostgresTest")],
    };
    let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
    ixn.d = compute_said(&value).unwrap();
    Event::Ixn(ixn)
}
