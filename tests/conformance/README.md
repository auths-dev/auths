# keripy conformance suite

Proves the **auths** KERI CLI is byte-for-byte interoperable with the KERI
reference implementation, **keripy 1.3.4**. For each KERI surface, identical
fixed inputs are fed to both keripy and the auths CLI, and the outputs are
compared as canonical JSON.

## What it proves

For every surface the suite asserts **two** things:

1. **Live cross-check** — `auths CLI output == keripy oracle output`
   (`oracle.py`, pure keripy). This is the real interop claim, computed fresh on
   every run from the installed keripy.
2. **Drift / provenance** — `auths CLI output == the frozen vector` in
   `vectors/`, and (`test_vectors_provenance.py`) the frozen vectors reproduce
   the keripy oracle byte-for-byte. So the goldens are provably keripy's, and a
   keripy-version drift fails loudly.

No expected value is ever hand-copied from auths output: every expected SAID and
field is produced by keripy code (`oracle.py`), using the exact recipes the auths
Rust modules document (`auths-keri/src/{oobi,ipex,did_webs}.rs`).

## Surfaces and match type

| # | Surface | auths command | keripy oracle | Match |
|---|---------|---------------|---------------|-------|
| 1 | ksn emit | `key-state --from-kel` | `eventing.state(...)._asdict()` | byte-exact (canonical JSON); `dt` pinned to epoch on both sides |
| 2 | ksn ingest | `key-state --ingest` | subset `{i,k,s}` of `eventing.state(...)` | structural — auths prints a normalized internal view; gated on resolved key-state `(i,k,s)` + last-event SAID |
| 3 | did:webs (Ed25519) | `did-webs --from-kel --domain` | `gen_did_document` (OKP x-only JWK) | byte-exact |
| 3b | did:webs (P-256) | `did-webs --from-kel --domain` | `gen_did_document` (EC x/y JWK) | byte-exact |
| 4 | oobi endpoint | `oobi endpoint --from-kel --authority --url` | `eventing.reply('/loc/scheme')` + `eventing.reply('/end/role/add')` | byte-exact incl. SAIDs; `dt` pinned to epoch |
| 5 | ipex grant | `ipex grant --acdc --sender --recipient` | `exchanging.exchange('/ipex/grant', embeds={acdc})` | byte-exact incl. top-level `d`, embedded ACDC, and embeds-section `e.d` |
| 6 | ipex admit | `ipex admit --grant --sender` | `exchanging.exchange('/ipex/admit', dig=grant.said)` | byte-exact incl. `d` and prior `p` |

### Normalization notes (and why)

The comparison helper `canon()` only sorts object keys and compacts whitespace —
it never drops or rewrites a value, so any real type/value difference still
fails. The only places where the two sides are deliberately made to agree:

- **`dt` (ksn emit, oobi)** — keripy's `state()`/`reply()` default the timestamp
  to `now()`; auths defaults `--dt` to the epoch. We pin BOTH to the epoch (the
  auths default; `stamp=`/`date=` on keripy), so no field is normalized away.
- **`a.dt` (ipex ACDC)** — keripy's `proving.credential` stamps the subject `dt`
  with `now()` unless given; we pass `data={"dt": ...}` to fix it. auths is
  given the same fixed-`dt` ACDC and `--dt`.
- **ksn ingest shape** — auths `--ingest` prints `{prefix, current_keys,
  sequence, last_event_said, ...}` (a resolved internal view), not the wire ksn.
  The test maps those to `(i, k, s)` and compares; this surface is gated on the
  *resolved key-state*, not on echoing the wire bytes. This is the one
  structural-rather-than-byte-exact surface.

All other surfaces are byte-exact under canonical JSON.

## How to run

From the auths repo root, with keripy 1.3.4 importable:

```bash
python3 -m pytest tests/conformance -v
```

The auths binary is located via `$AUTHS_BIN`, else the release build at
`target/release/auths`, else `auths` on `PATH`. If none is found the suite
*skips* with a clear message (build with `cargo build --release -p auths`).

Every auths invocation is passed `--repo <tmpdir>`; an autouse session fixture
asserts `~/.auths` is never created or modified by the run.

## Regenerating vectors

The frozen inputs (`fixtures/`) and golden outputs (`vectors/`) plus their
provenance (`MANIFEST.yaml`) are generated from keripy:

```bash
cd tests/conformance && python3 gen_vectors.py
```

`test_vectors_provenance.py` then guarantees the checked-in files match what
keripy produces, byte-for-byte. Regenerate only on an intentional keripy version
bump and review the diff.

## Version pin

- **keripy 1.3.4** (`python3 -c "import keri; print(keri.__version__)"`).
- Deterministic key material: Ed25519 raw = `bytes(range(32))`; recipient
  Ed25519 raw = `bytes((b+5)%256 for b in range(32))`; P-256 scalar =
  `int(bytes(range(1,33)))`. AID for the primary key:
  `EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J`.

## Honest scope

- **Byte-exact (canonical JSON):** ksn emit, did:webs (Ed25519 + P-256), oobi
  `/loc/scheme` + `/end/role/add` (SAIDs included), ipex grant (incl. embedded
  ACDC + embeds-section SAID), ipex admit (incl. prior SAID).
- **Structural:** ksn ingest — gated on the resolved key-state `(i, k, s)` and
  the last-event SAID, because auths emits a normalized view rather than the wire
  ksn.
- **Out of scope for this gate:** no network, no Docker, no signify-ts/KERIA live
  peers. Signatures and witnessing are covered by the separate interop harness,
  not here. This suite is keripy-only and offline.
