# Auths-Radicle Integration Plan

## 1. Problem Statement

Verification logic alone -- even if perfectly implemented and deployed as WASM to every node -- cannot solve revocation propagation in a P2P network. A verifier can only check facts it knows about: if a node has never received a revocation attestation, its verifier will correctly validate a signature from the revoked device because, from that node's perspective, the device is still authorized. The problem is not verification correctness but *state availability*. Revocation is an *event* that must physically propagate through the gossip network, and until it arrives, every honest node with stale state will make a locally-correct but globally-wrong authorization decision. Therefore, the integration must define explicit rules for what a node should do when its identity state may be incomplete, rather than relying on "verification works, so we're safe."

---

## 2. Source of Truth and Storage Model

### Chosen Model: Dedicated identity repository with project-level namespace binding (per RIP-X)

RIP-X specifies that a KERI identity lives in its own Radicle repository, and projects reference it via a DID namespace under `refs/namespaces/did-keri-<prefix>/`. This plan follows that design exactly.

**Where identity events live:** Each Auths identity (the KERI event log and device attestations) lives in a **dedicated identity repository** replicated via Radicle, one per identity. The repository layout follows RIP-X:

```
<rid>                           # KERI identity repository
└─ refs
   ├─ keri
   │  └─ kel                    # KEL commit history (tip = latest event)
   └─ keys
      ├─ <nid>                  # 2-way attestation for device A
      │  └─ signatures
      │     ├─ did-key          # Device's signature blob
      │     └─ did-keri         # Identity's signature blob
      └─ <nid>                  # 2-way attestation for device B
         └─ signatures
            ├─ did-key
            └─ did-keri
```

**Where project-level binding lives:** Per RIP-X, each project repository gains a new namespace entry for each KERI identity that participates:

```
<project-rid>
└─ refs
   └─ namespaces
      ├─ did-keri-EXq5...      # Identity namespace (new, per RIP-X)
      │  └─ refs
      │     ├─ rad
      │     │  └─ id            # Blob pointing to the identity repo RID
      │     └─ heads/...        # Canonical refs for this identity
      ├─ <nid-A>               # Device A's fork (existing pattern)
      │  └─ refs
      └─ <nid-B>               # Device B's fork (existing pattern)
         └─ refs
```

The `refs/namespaces/did-keri-<prefix>/refs/rad/id` blob contains the RID of the identity repository. This is how a node discovers which identity repo to fetch.

### Why this model

| Criterion | RIP-X model (chosen) | Alternative: embed in each project |
|---|---|---|
| **Revocation correctness** | Single authoritative source; revocations propagate once via identity repo | Revocation must be pushed to every project repo independently; easy to miss one |
| **Minimal codebase change** | Heartwood already has `IdentityNamespace` parsing for `did-keri-` prefixes; identity repos are just normal Radicle repos | Requires modifying every project's identity doc schema and replication logic |
| **Operational simplicity** | Identity owner manages one repo; projects just reference it via namespace | Every project must be updated on revocation |
| **RIP-X compliance** | Direct match | Deviates from the RIP |

The key insight from fn-4 (Heartwood's fetch/protocol epic): when a node fetches a project and encounters a `refs/namespaces/did-keri-<prefix>/refs/rad/id` blob, it queues a best-effort fetch of the referenced identity repo. This creates automatic replication dependency -- nodes that seed a project will discover and seed the identity repo without manual intervention.

---

## 3. Roles and Responsibilities

### auths crates (auths-core, auths-id, auths-verifier)

**Owns:**
- Identity truth: creation, storage, and validation of KERI event logs (inception, rotation, interaction events)
- Attestation lifecycle: creation, dual-signing (per RIP-X: `keri.sign(RID, did:key)` + `key.sign(RID, did:keri)`), revocation
- Policy evaluation: capability checks, expiration checks, revocation checks against *locally available* state
- DID resolution: converting `did:keri:` and `did:key:` to public key material
- Key state computation: `validate_kel()` produces `KeyState` from an ordered event sequence

**Does not own:** P2P replication, network transport, peer discovery, or any concept of "freshness" relative to the network.

### heartwood crates (radicle, radicle-fetch, radicle-node, radicle-cob)

**Owns:**
- P2P replication: gossip protocol, `RefsAnnouncement`, fetch pipeline
- Cryptographic signature verification: Ed25519 verification of `SignedRefs` and COB commits
- Project identity documents: `Doc` with delegates (including `Did::Keri` once fn-1 lands), threshold, visibility, payloads
- Repository storage: namespaced refs (including `did-keri-` identity namespaces per RIP-X), signed refs branches, Git object storage
- Namespace classification: `NamespaceKind::Peer(NodeId)` vs `NamespaceKind::Identity(Did)` (fn-4)
- Seeding policy: which repos to replicate, which peers to follow
- Identity repo auto-fetch: when encountering a DID namespace, queue fetch of the referenced identity repo (fn-4, best-effort)

**Does not own:** KERI event validation, capability-based authorization, or revocation semantics beyond its existing delegate threshold model.

### auths-radicle (the bridge)

**Responsible for:**

1. **DID translation:** Converting Radicle's `[u8; 32]` Ed25519 keys to Auths `did:key:z...` format and back. This is the type-system boundary.

2. **Ref path constants:** Exporting RIP-X ref paths (`refs/keri/kel`, `refs/keys/<nid>/signatures`) so both codebases use identical strings.

3. **Identity state loading:** Reading the KERI event log and device attestations from the identity repository (accessed as a local Git repo that Radicle has replicated). Computing current `KeyState` via `validate_kel()`.

4. **Authorization evaluation:** For a given signer key, answering: "Is this device currently authorized to perform this action on this project?" This involves:
   - Finding the device's attestation under `refs/keys/<nid>/signatures`
   - Verifying both signatures (RIP-X 2-way attestation)
   - Checking revocation status
   - Checking expiration
   - Checking capability (e.g., `sign_commit`)
   - Evaluating against the current `KeyState`

5. **Staleness detection:** Determining whether the locally-available identity state may be stale. The bridge compares what it has locally against what the gossip layer knows is available (see Section 4).

6. **Result production:** Returning a `VerifyResult` (Verified / Rejected / Quarantine) that Radicle's fetch pipeline can act on. The bridge never modifies repository state; it only reads and decides.

**Refuses to do:**
- Sign anything (zero new crypto)
- Modify Radicle repository state directly
- Make network requests (it reads locally-replicated Git data only)
- Override Radicle's own signature verification (Radicle checks Ed25519; the bridge checks authorization)

---

## 4. Stale-State Policy: Compare and Choose

### Policy A: Eventual Consistency (fail-open)

**Description:** Each node decides based solely on its local identity state. If a node hasn't received a revocation, it accepts the update. Disagreements resolve as revocations propagate.

**User experience:** Seamless in the happy path. Users never see delays or rejections due to missing state. However, a revoked device can continue pushing updates to nodes that haven't received the revocation until gossip catches up.

**Failure modes:**
- A revoked device's updates are accepted by stale nodes and become part of their local view. When the revocation arrives, those updates are already integrated. Cleaning them up requires manual intervention.
- In adversarial scenarios, a compromised device could race the revocation, pushing malicious updates to as many nodes as possible before the revocation propagates.
- An attacker can target nodes that haven't seeded identity repos, or exploit nodes with temporarily unreadable identity state (disk corruption, missing refs), and get accepted "because fallback."

**Node A vs Node B scenario:** Node A (has revocation) rejects the update. Node B (stale) accepts it. When Node B eventually receives the revocation, it has already accepted the update. There is no automatic rollback. The accepted update persists unless a delegate explicitly reverts it.

**Complexity:** Lowest. No additional state tracking. No quarantine mechanism. But cleanup after revocation races is undefined, and the system cannot honestly claim to "prevent unauthorized pushes" -- it only detects them after the fact.

### Policy B: Freshness Requirement (fail-closed on staleness)

**Description:** Nodes refuse to make authorization decisions unless their identity state is "fresh enough." Freshness is defined as: the node has synced the identity repository within a configurable window, OR there are no pending identity repo updates in the gossip layer.

**User experience:** Nodes that are offline or poorly connected may reject valid updates because they can't confirm freshness. This creates friction in truly offline or intermittently-connected environments -- exactly the environments Radicle is designed for.

**Failure modes:**
- Offline nodes become unable to accept any updates, even from non-revoked devices.
- Creates a soft availability dependency on the identity repository being reachable, undermining Radicle's offline-first design.
- Clock-based freshness is unreliable in P2P networks with no shared clock.

**Node A vs Node B scenario:** Node A (has revocation) rejects. Node B checks freshness: if it hasn't synced recently, it quarantines. This is safe but blocks legitimate work when nodes are offline.

**Complexity:** Medium-high. Requires freshness tracking, configurable windows, and graceful degradation. Adds a soft liveness dependency.

### Policy C: Proof-Carrying Authorization (fail-closed on missing proof)

**Description:** Every signed update carries enough evidence for any node to verify authorization *without* consulting external identity state. Specifically, each update includes: the device's current attestation, and a KEL snapshot up to the event that anchors that attestation. A node verifies the proof bundle independently.

**User experience:** Updates are self-contained. Nodes can verify authorization even while fully offline. No freshness anxiety and no quarantine friction.

**Failure modes:**
- Proof size: carrying attestations + KEL snapshots with every update adds overhead.
- Revocation latency: a revoked device can continue producing valid-looking proofs until the revocation is anchored in the KEL. The window is bounded by the time between compromise and revocation anchoring.
- Complexity of proof construction: the signing client must assemble proof bundles.
- **Protocol impact:** Proof bundles must be stored as auxiliary Git objects alongside the update, not embedded in `SignedRefs` or the wire format (see below for why).

**Node A vs Node B scenario:** Node B receives the update along with the proof bundle. If the proof was assembled before the revocation was anchored, it's valid and Node B accepts. Once the revocation is anchored, new proof bundles from that device fail. The vulnerability window equals the time between compromise and KEL update.

**Complexity:** Highest. But provides the strongest offline guarantee.

### Decision

**MVP: Policy A (Eventual Consistency) for observe mode + Policy B-lite (quarantine-on-known-staleness) for enforce mode**

Projects that opt into Auths identity choose an enforcement level:

#### Observe mode (default for MVP)

The bridge checks identity state if available and produces `Verified` / `Rejected` / `Warn` results, but the node always applies the update regardless. Results are logged and surfaced in `Validations`. This is a detection-and-flagging system, not an authorization boundary.

The system **does not claim to prevent unauthorized pushes** in observe mode. It detects and flags them with eventual convergence.

#### Enforce mode (recommended for projects that need revocation guarantees)

When a project opts into enforce mode, the bridge is a hard authorization boundary:

- `Verified` -> apply the update
- `Rejected` -> reject the update (add validation error, prune the remote)
- **Identity state unavailable** (identity repo not seeded, not yet fetched, or unreadable) -> **quarantine**: reject the update with a specific `Quarantine` validation error indicating which identity repo RID is needed. The node can retry after fetching the identity repo.

This is fail-closed for projects that opt in. The bridge does not "fall back to signature-only" for enforce-mode projects -- that would undermine the entire security model. If a project declares an Auths binding in enforce mode and the identity repo is missing, updates from KERI-attested devices are rejected until the identity state is available.

**Backward compatibility:** Projects without any Auths binding are completely unaffected (no bridge call). Projects in observe mode are never blocked. Only enforce mode adds rejection, and it's opt-in per project.

#### Enforce mode DoS resistance

Enforce mode introduces a new DoS surface: if "identity repo missing/unreadable/behind => quarantine," an attacker can try to keep nodes perpetually quarantined by:

- **Preventing identity repo fetch** (network partition, peer selection attacks): The mitigation is that quarantine is *per-update*, not per-project. The node continues to accept updates from `Did::Key` delegates (which don't require the bridge) and from devices whose identity state *is* locally available and current. Only the specific updates that can't be authorized are quarantined. The node is never fully blocked from a project.
- **Constantly advancing the identity repo** to keep nodes "behind": This requires the attacker to be a delegate of the identity repo (only delegates can push signed refs). If a delegate is malicious, the identity is already compromised -- this is not a new attack surface. A non-delegate cannot advance the identity repo's signed refs.
- **Corrupting local identity repo storage**: If the identity repo on disk becomes unreadable, the bridge returns `Quarantine` for enforce mode. This is correct behavior -- "I can't read the identity state" should not mean "accept everything." The node operator resolves this by re-fetching the identity repo (`rad sync --fetch`). This is recoverable, not permanent.

**Quarantine timeout**: If a node has been quarantining updates for a specific identity for more than a configurable period (default: 24 hours) without being able to resolve the quarantine (e.g., identity repo is persistently unreachable), the node logs a critical warning. It does *not* auto-downgrade to observe mode -- that would defeat the purpose. The operator must explicitly intervene: either fix the fetch problem, downgrade to observe mode, or remove the KERI delegate from the project. This is an operational decision, not an automatic one.

### Staleness detection (replaces min_kel_seq-as-freshness)

The previous draft used `min_kel_seq` from the project binding as a freshness heuristic. This does not actually detect the "Node B accepts revoked device" case -- a node can be at sequence 3 (above the binding minimum of 2) while the revocation is at sequence 4.

`min_kel_seq` serves a different purpose: **binding integrity**. It prevents a node from accepting identity state that predates the binding itself (e.g., an attacker feeding a truncated KEL). It is not a freshness tool.

For actual staleness detection, the bridge uses a **gossip-informed heuristic**:

> **Warn when the node knows there is a newer identity repo tip available (via `RefsAnnouncement`) but hasn't fetched it yet.**

This is concretely actionable:
- Radicle's gossip layer already announces `RefsAt(remote, oid)` for every repo. The node can compare its local identity repo tip against the announced tip.
- If they differ, the bridge returns `Warn` (observe mode) or `Quarantine` (enforce mode) with metadata: "identity repo `rad:z3gq...` has a newer tip `abc123` available -- fetch it."
- No shared clocks needed. No configurable windows. Just: "I know I'm behind."
- If no announcement has been received (fully disconnected), the node has no reason to suspect staleness and proceeds based on local state.

#### Which peers can trigger staleness signals

Not all `RefsAnnouncement` sources are equally trustworthy. An attacker could spam false "newer tip" announcements to force quarantine on enforce-mode nodes (a DoS vector). The policy:

1. **Only announcements from peers that are delegates of the identity repo (or tracked/followed peers for that repo) are considered credible.** Radicle already tracks which peers are delegates via the identity repo's own `Doc.delegates`. An announcement from a random peer is ignored for staleness purposes.
2. **A single credible announcement is sufficient to trigger a staleness signal.** We do not require multiple independent announcements. Rationale: the identity repo has a small, known delegate set (typically 1-3). Requiring a quorum would add complexity without meaningful security gain -- if an identity delegate is compromised, the identity itself has bigger problems than false staleness signals.
3. **An attacker who is not a delegate of the identity repo cannot trigger quarantine.** They can announce whatever they want, but the bridge filters by delegate status before acting on the signal.

This means the staleness signal is only as trustworthy as the identity repo's delegate set -- which is the same trust root as the identity itself.

### Later hardening path (backward-compatible)

**Phase 2: Proof-carrying authorization (Policy C) as additive auxiliary Git objects.**

Proof bundles are stored as **additional Git blobs in the identity repo** (not in `SignedRefs` or the wire format). A ref like `refs/keys/<nid>/proof-bundle` contains the attestation + KEL snapshot. Nodes that understand proof bundles verify them; nodes that don't (older versions) ignore the extra refs and fall back to direct identity repo lookup.

This avoids modifying `SignedRefs` canonicalization or the gossip wire format. `SignedRefs` uses a text-canonical format (`<oid> <ref>\n` lines) that is safe to extend with new refs but should not have its structure changed. The gossip `RefsAnnouncement` is binary-encoded and carries only `(rid, [(remote, oid)])` -- adding fields would require a protocol version bump. Proof bundles as auxiliary Git objects require neither.

---

## 5. Concrete Propagation Flow

### 5A. Normal Operation: Device Authorization and Update Acceptance

**Step 1: Identity creation.**
Alice creates a KERI identity. Per RIP-X, this generates:
- A KERI inception event with her initial Ed25519 key pair
- A `did:keri:<prefix>` identity DID derived from the SAID (Blake3 hash) of the inception event
- The KEL is stored as a commit chain under `refs/keri/kel`

**Step 2: Identity repository publication.**
Alice publishes her identity as a Radicle repository using `rad identity init-keri` (fn-5 CLI). This creates a Radicle `RepoId` (RID) for her identity and seeds it to the network.

**Step 3: Device authorization.**
Alice has a second device (laptop). Per RIP-X, she creates a 2-way attestation:
- `keri.sign(RID, did:key)` -- identity key signs the binding
- `key.sign(RID, did:keri)` -- device key signs the binding
- Both signatures are stored as blobs under `refs/keys/<laptop-nid>/signatures/` in the identity repo
- She pushes the updated identity repo: `git push rad`

**Step 4: Project setup with identity namespace.**
Alice creates a Radicle project. Per RIP-X, a new namespace is created:
- `refs/namespaces/did-keri-<prefix>/refs/rad/id` -> blob containing the identity repo RID
- `refs/namespaces/did-keri-<prefix>/refs/heads/...` -> canonical refs for the identity
- The project's `Doc` delegates include `Did::Keri(prefix)` alongside any `Did::Key` delegates

**Step 5: Signed update from authorized device.**
Alice's laptop pushes a commit to the project. Radicle creates `SignedRefs` signed by the laptop's Ed25519 key. The update appears under `refs/namespaces/<laptop-nid>/...`.

**Step 6: Node receives update.**
Bob's node receives Alice's `RefsAnnouncement`. During the fetch pipeline:

1. Radicle verifies the Ed25519 signature on `SignedRefs` (existing logic, unchanged)
2. Radicle classifies the remote's namespace. The laptop's `<nid>` is a `Peer` namespace.
3. The fetch pipeline encounters `refs/namespaces/did-keri-<prefix>/refs/rad/id` and queues a fetch of Alice's identity repo (fn-4 design, best-effort)
4. Per fn-3, `SignedRefs::verify_with_identity()` is called. It tries the fast path (exact delegate key match) first. Since the laptop isn't a direct delegate, it falls back to the auths-radicle bridge:
   a. Bridge reads Alice's identity repo from Bob's local storage
   b. Bridge loads the KEL and computes `KeyState` via `validate_kel()`
   c. Bridge converts the laptop's `[u8; 32]` key to `did:key:z6Mk...`
   d. Bridge loads the 2-way attestation from `refs/keys/<laptop-nid>/signatures`
   e. Bridge verifies both signatures, checks: not revoked, not expired, has `sign_commit` capability
   f. Bridge returns `VerifyResult::Verified`
5. Radicle proceeds with ref validation and applies the update

### 5B. Revocation

**Step 1: Revocation creation.**
Alice discovers her laptop was compromised. From her primary device, she runs `rad identity device revoke <laptop-nid>` (fn-5). This:
- Sets `revoked_at` on the attestation and re-signs with the KERI identity key
- Anchors the revocation in the KEL via an interaction event (IXN)
- KEL sequence advances (e.g., from 2 to 3)

**Step 2: Publication.**
Alice pushes the updated identity repository to Radicle. The identity repo's `SignedRefs` update, and a `RefsAnnouncement` propagates through the gossip network.

**Step 3: Network propagation.**
Nodes that seed Alice's identity repository receive the `RefsAnnouncement`, fetch the updated KEL and revocation. Their local state now reflects the revocation.

**Step 4: Post-revocation verification (node has revocation).**
When any node with the updated identity state receives an update signed by the revoked laptop key:
1. Radicle verifies the Ed25519 signature (passes -- the signature is cryptographically valid)
2. The bridge is consulted:
   a. Bridge loads the attestation for the laptop's DID
   b. Bridge finds `revoked_at` is set
   c. Bridge returns `VerifyResult::Rejected { reason: "Device <laptop-nid> was revoked at 2026-03-01T12:00:00Z" }`
3. Radicle rejects the ref update (enforce mode) or records a validation warning (observe mode)

### 5C. The Stale-Node Scenario

**Setup:**
- Alice revoked her laptop at KEL sequence 3
- Node A (Carol) has synced Alice's identity repo and has KEL up to sequence 3 (includes revocation)
- Node B (Dave) has not synced Alice's identity repo recently; his local copy is at KEL sequence 2 (no revocation)
- The compromised laptop pushes an update to the project, and Dave's node receives it

**What happens at Dave's node (stale state):**

1. **Signature verification passes.** The Ed25519 signature is valid.

2. **Bridge is consulted.**
   a. Bridge locates Alice's identity repo in Dave's local storage
   b. Bridge loads the KEL: sequence 2 (no revocation event present)
   c. Bridge loads attestation for the laptop: not revoked (in Dave's view), not expired, has capabilities

3. **Gossip-informed staleness check:**
   - If Dave's node has received a `RefsAnnouncement` for Alice's identity repo with a newer tip OID than what Dave has locally, the bridge detects staleness.
   - If no such announcement has been received (Dave is fully disconnected), Dave has no reason to suspect staleness.

4. **Outcome depends on mode:**

   **Observe mode:** Bridge returns `VerifyResult::Verified` (or `Warn` if staleness detected). Dave accepts the update. When Dave eventually syncs Alice's identity repo, he gets the revocation. From that point forward, the laptop is rejected. The previously-accepted update remains -- Dave's node cannot automatically roll it back.

   **Enforce mode with staleness detected:** Bridge returns `VerifyResult::Quarantine { reason: "Identity repo has newer tip available; fetch before deciding" }`. Dave's node rejects the update. When Dave syncs the identity repo and gets the revocation, the laptop would be rejected anyway. If the laptop had *not* been revoked, re-fetching the identity repo would resolve the quarantine and Dave could accept on retry.

   **Enforce mode without staleness detected (fully disconnected):** Bridge returns `VerifyResult::Verified` based on local state. This is the irreducible risk of any eventually-consistent system -- Dave has no reason to suspect his state is wrong and no way to check. The window closes when connectivity resumes.

**Blast radius of stale acceptance:**

The damage from accepting an update from a revoked device depends on what the revoked device can do:

- **If the revoked device is a project delegate (via `Did::Keri`):** It can update canonical refs, subject to threshold. A compromised delegate is a serious incident regardless of Auths -- the project must have a threshold > 1 to survive this. Auths adds revocation capability; it doesn't change the blast radius of a compromised delegate.
- **If the revoked device is a non-delegate contributor:** Its updates live in its own `refs/namespaces/<nid>/...` namespace. Radicle's delegate threshold mechanism means non-delegate refs don't affect the canonical project state *by default*. However, this containment has limits:
  - **No auto-merge from non-delegate namespaces.** Radicle does not auto-merge patches or auto-build from non-delegate forks without explicit delegate action (merging a patch requires a delegate to check it out, review, and push to their own namespace). So a revoked non-delegate device cannot inject code into canonical state without a human delegate approving the merge.
  - **UI visibility matters.** Non-delegate namespaces are visible in `rad patch`, `rad ls`, and other CLI output. A stale-accepted update from a revoked device will appear as a valid-looking patch or fork until the revocation propagates and the node flags it. Users could be misled into reviewing or merging it. **Mitigation:** When a previously-accepted update is retroactively flagged (identity repo syncs and reveals revocation), the node should surface a prominent warning: "Patch/fork from `<nid>` was accepted before device revocation was known. Treat contents as untrusted." This warning should appear in `rad patch show`, `rad inbox`, and any UX surface that displays the contributor's data.
  - **Object-level contamination.** Even though refs are namespaced, Git objects are shared. A malicious commit from a revoked device could reference the same tree as legitimate commits, or be a parent of future legitimate commits if a delegate inadvertently merges before the revocation arrives. This is a Git-level property, not something the bridge can prevent -- it reinforces that the operator should treat any stale-accepted data as potentially harmful.

- **In both cases:** Any accepted update from a revoked device must be treated as potentially harmful. The project owner must explicitly revert or repair after the revocation propagates. There is no automatic rollback. The bridge logs every `Verified` decision with enough context (device DID, identity DID, KEL sequence at decision time) to support a post-hoc audit: "which updates were accepted from device X before its revocation was known?"

### 5D. Revocation Race Window: Formal Bound

The system prevents unauthorized pushes only under specific conditions. Here is the precise bound:

**Guarantee:** A push signed by a revoked device is rejected by every node that satisfies *at least one* of:

1. **The node has fetched the identity repo at or past the KEL sequence containing the revocation seal.** This is the primary path. The revocation is an IXN event in the KEL; once the node has it, the device is rejected.

2. **The node has received a credible gossip signal (from an identity repo delegate) that a newer identity repo tip exists, AND the project is in enforce mode.** The push is quarantined until the node fetches the update. If the update contains the revocation, the push is rejected. If the update does *not* contain the revocation (the newer tip was for an unrelated event), the quarantine resolves and the push is accepted.

**No guarantee:** A fully-disconnected node with no gossip signal operates on cached authority. It has no mechanism to learn about the revocation and will accept the push as locally valid. This is the irreducible risk of any system that operates offline.

**Bound on the vulnerability window:**

```
T_vulnerable = T_propagation + T_fetch

Where:
  T_propagation = time for RefsAnnouncement to reach the node via gossip
                  (typically seconds on a connected network; unbounded if disconnected)
  T_fetch       = time for the node to fetch the updated identity repo after
                  receiving the announcement (typically seconds; bounded by
                  Git transfer speed)
```

For connected nodes on a well-seeded network, `T_vulnerable` is on the order of seconds to low minutes. For nodes with intermittent connectivity, it equals their disconnection interval. For permanently-offline nodes, it is infinite -- they run on cached authority indefinitely.

**This is not a weakness unique to this design.** It is the same bound as every revocation system that operates without a synchronous online check (TLS CRL/OCSP, PGP key revocation, SSH certificate revocation). The contribution of this design is making the bound *explicit* and providing the enforce-mode quarantine to narrow it for nodes that do have gossip connectivity.

---

## 6. Minimal Hook Point in Radicle

**Where:** Per fn-3's design, the hook is in `SignedRefs::verify_with_identity()` -- a new method that extends the existing `SignedRefs::verify()`. The existing method handles the fast path (exact delegate key match); the new method adds a fallback path for KERI-attested devices.

Concretely, in the fetch pipeline (fn-4, `FetchState::run()`): after `SignedRefs<Unverified>` is loaded for a remote, and after the Ed25519 signature is verified, the pipeline checks whether the signer's `NodeId` is:
1. A direct delegate (`Did::Key` in `Doc.delegates`) -> accept via existing path
2. An attested device of a `Did::Keri` delegate -> consult the auths-radicle bridge
3. Neither -> reject (non-delegate, non-attested)

**What the bridge call does:**
1. Read the identity repo RID from `refs/namespaces/did-keri-<prefix>/refs/rad/id`
2. Load the identity repo from local Radicle storage
3. Run authorization checks (KEL validation, attestation verification, revocation/expiry/capability checks)
4. Return `VerifyResult` mapped to Radicle's existing `Validations` / prune flow:
   - `Verified` -> accept as a valid contributor under this KERI identity
   - `Rejected` -> prune the remote, add validation error (enforce mode), or add warning (observe mode)
   - `Quarantine` -> prune the remote, add validation error indicating which identity repo to fetch (enforce mode only)

**What "reject" means precisely:**

In Radicle, "accepting an update" involves multiple layers. The bridge operates at the **ref update** layer, not the transport layer. Specifically:

1. **Git objects are always fetched and stored.** The Git packfile transfer happens before the bridge is consulted. Objects (commits, trees, blobs) are written to the local Git object store regardless of the bridge verdict. This is unavoidable -- the fetch protocol transfers objects before refs are validated. Blocking at the object level would require aborting the Git protocol mid-stream, which is fragile and leaks metadata anyway.

2. **Ref updates are gated by the bridge.** After objects are stored, the fetch pipeline decides which refs to update. This is where the bridge's verdict takes effect:
   - `Verified`: The remote's refs (under `refs/namespaces/<nid>/...`) are updated to point to the fetched objects.
   - `Rejected` / `Quarantine`: The remote's ref updates are **pruned** -- the local refs are not advanced. The fetched objects become unreachable (no ref points to them) and will be garbage-collected by Git's normal GC.

3. **Canonical refs are never updated for rejected remotes.** The canonical refs (under `refs/namespaces/did-keri-<prefix>/refs/heads/...`) aggregate only from verified device namespaces. A rejected device's objects never appear in the canonical view.

4. **COBs (issues, patches) authored by rejected devices are not applied.** COB operations check the same authorization path. A rejected device's COB entries are pruned alongside its refs.

This means: rejected updates leave transient Git objects on disk (until GC), but no refs, no canonical state, and no COB state are affected. The UI never sees them.

**If the bridge is unavailable** (identity repo not in local storage, bridge returns error):
- **Observe mode:** Accept the update, log a warning. The bridge is informational only.
- **Enforce mode:** Reject the update. The project opted into hard authorization. "Unable to verify" is not "verified." This is fail-closed for projects that require it.
- **No Auths binding (no DID namespace in project):** The bridge is never called. Behavior is identical to current Heartwood. This is the default for all existing projects.

**Feature flag:** The bridge integration is behind the fn-1 work (extending `Did` to an enum). Once `Did::Keri` exists in Heartwood's type system, the multi-device verification path is structurally available. There is no separate feature flag needed in `radicle-fetch` because the bridge call is gated on the presence of a `Did::Keri` delegate in the project's `Doc` -- no KERI delegate means no bridge call.

---

## 7. Execution Roadmap

### Relationship to Existing Heartwood Epics (fn-1 through fn-5)

This plan's epics are designed to complement, not duplicate, the Heartwood `.flow/` epics. The mapping:

| Heartwood epic | This plan's coverage |
|---|---|
| fn-1 (Core types: `Did` enum, `IdentityNamespace`) | Not duplicated. This plan assumes fn-1 is completed in Heartwood. |
| fn-2 (KERI storage: `KeriIdentityStore`, `GitKeriIdentityStore`) | Partially overlaps with our Epic 2 (identity state loading). Our Epic 2 focuses on the auths-radicle bridge side; fn-2 focuses on the Heartwood storage adapter side. |
| fn-3 (SignedRefs verification: `DeviceAuthorityChecker`) | Directly consumed by our Epic 3 (authorization checks). fn-3.2 explicitly wires `auths-radicle::DefaultBridge` as the backend. |
| fn-4 (Fetch/protocol: identity repo auto-fetch, namespace classification) | Directly consumed by our Epic 5 (Radicle integration seam). |
| fn-5 (CLI: `rad identity init-keri`, `device add/revoke/list`) | Not duplicated. This plan assumes fn-5 is completed in Heartwood. |

The epics below focus on work in the **auths** repository (auths-radicle, auths-id, auths-verifier) and cross-repo integration testing.

---

### Epic 1: RIP-X Ref Layout and Attestation Format Alignment

**Objective:** Align auths-radicle's ref paths and attestation format with RIP-X's specification.

**Why it matters:** RIP-X defines specific ref paths (`refs/keri/kel`, `refs/keys/<nid>/signatures`) and a specific 2-way attestation format (`keri.sign(RID, did:key)` + `key.sign(RID, did:keri)`). The existing auths-id code uses different paths (`refs/did/keri/<prefix>/kel`, `refs/auths/devices/nodes/<did>`). The bridge must map between these or the existing auths-id code must support the RIP-X layout.

**Success metrics:**
- Ref path constants for RIP-X layout exist in auths-radicle
- Attestation serialization/deserialization handles the RIP-X 2-blob format (separate `did-key` and `did-keri` signature blobs)
- Round-trip: create attestation in RIP-X format, store under RIP-X refs, read it back

**Exit criteria:**
- Constants match RIP-X spec exactly
- Bridge can read attestations stored in RIP-X format
- 100% of format tests pass

#### Tasks

**Task 1.1: Define RIP-X ref path constants in auths-radicle**
- *Why:* Both codebases must agree on ref paths. auths-radicle is the source of truth for the mapping.
- *Acceptance criteria:* Constants for `KERI_KEL_REF` (`refs/keri/kel`), `KEYS_PREFIX` (`refs/keys`), `SIGNATURES_REF` (`signatures`), `DID_KEY_BLOB` (`did-key`), `DID_KERI_BLOB` (`did-keri`). Documented with their RIP-X section references.
- *Test plan:*
  - Unit: constants match RIP-X spec strings exactly
  - Unit: path construction helpers produce valid Git refnames
- *Affected areas:* `crates/auths-radicle/src/refs.rs` (new file, per fn-5.2)

**Task 1.2: Attestation-to-bytes / from-bytes for RIP-X format**
- *Why:* RIP-X stores attestation signatures as two separate Git blobs, not as a single JSON attestation. auths-verifier needs to support this.
- *Acceptance criteria:* `Attestation::to_bytes()` / `from_bytes()` round-trip for the RIP-X 2-blob format. The canonical payload for signing is `(RID, other_did)` as specified in RIP-X.
- *Test plan:*
  - Unit: serialize attestation to two blobs, deserialize back, signatures verify
  - Unit: reject truncated/corrupt blobs
  - Unit: reject mismatched RID (tamper detection)
- *Affected areas:* `crates/auths-verifier/src/` (per fn-5.3), `crates/auths-radicle/src/bridge.rs`

**Task 1.3: `GitKel::with_ref()` constructor for custom ref paths**
- *Why:* auths-id's KEL reader currently uses `refs/did/keri/<prefix>/kel`. For RIP-X, it needs to read from `refs/keri/kel`.
- *Acceptance criteria:* `GitKel` accepts an optional custom ref path, defaulting to the existing path but allowing `refs/keri/kel` for RIP-X repositories.
- *Test plan:*
  - Unit: default path works as before (no regression)
  - Unit: custom path reads KEL from `refs/keri/kel`
  - Unit: invalid ref path returns error
- *Affected areas:* `crates/auths-id/src/keri/` (per fn-6.1, fn-6.2, fn-6.3)

---

### Epic 2: Identity State Loading from Radicle-Replicated Repos

**Objective:** Enable the bridge to read KERI identity state from locally-replicated Radicle repositories.

**Why it matters:** The bridge makes authorization decisions based on identity state. It must be able to open a Radicle-replicated identity repo (by RID), load the KEL, compute `KeyState`, and load device attestations -- all from local Git storage.

**Success metrics:**
- `AuthsStorage` impl can load `KeyState` and attestations from a Radicle-replicated repo
- Handles missing repos, corrupt KELs, and missing attestations with domain-specific errors
- Reports KEL sequence for staleness comparison

**Exit criteria:**
- Bridge loads `KeyState` from a test identity repo in RIP-X layout
- All error scenarios return appropriate `BridgeError` variants
- Integration test: create identity repo, replicate it (simulate by copying), load via bridge

#### Tasks

**Task 2.1: `AuthsStorage` implementation for Radicle-backed repos**
- *Why:* The existing `AuthsStorage` trait in auths-radicle needs a concrete impl that reads from Radicle's Git storage
- *Acceptance criteria:* Given a local filesystem path to a Radicle-stored identity repo, loads: (a) KEL events from `refs/keri/kel` commit chain, (b) device attestations from `refs/keys/<nid>/signatures`, (c) computes `KeyState` via `validate_kel()`. Returns `BridgeError` variants for all failure modes.
- *Test plan:*
  - Unit: load valid KEL, verify `KeyState` fields match expected
  - Unit: load 2-way attestation for known device NID
  - Unit: missing identity repo -> `BridgeError::IdentityLoad`
  - Unit: corrupt/truncated KEL -> `BridgeError::PolicyEvaluation` (wrapping `ValidationError`)
  - Unit: missing attestation for unknown NID -> `BridgeError::AttestationLoad`
  - Integration: create full identity repo with inception + attestation, load via bridge, verify
- *Affected areas:* `crates/auths-radicle/src/verify.rs`

**Task 2.2: `find_identity_for_device()` implementation**
- *Why:* The bridge needs to discover which KERI identity (if any) a given NodeId is attested under. Per fn-5.1, this method is added to the `RadicleAuthsBridge` trait.
- *Acceptance criteria:* Given a device's NodeId and a project repository, scan `refs/namespaces/did-keri-*/refs/rad/id` to find identity repos, then check each identity repo's `refs/keys/<nid>` for a matching attestation. Returns the KERI DID or `None`.
- *Test plan:*
  - Unit: device attested under one identity -> returns that identity's DID
  - Unit: device not attested under any identity -> returns `None`
  - Unit: device attested under multiple identities (edge case) -> returns first match with warning
  - Unit: identity repo not locally available -> returns `None` (not error)
- *Affected areas:* `crates/auths-radicle/src/bridge.rs` (per fn-5.1)

---

### Epic 3: Authorization Checks in the Bridge

**Objective:** Implement the full authorization evaluation pipeline.

**Why it matters:** This is the core value: answering "is this device authorized?" using Auths identity state, per fn-3's `DeviceAuthorization` design.

**Success metrics:**
- Bridge correctly authorizes valid devices
- Bridge correctly rejects revoked, expired, and unauthorized devices
- Bridge correctly checks capabilities
- Works with fn-3.2's `CompositeAuthorityChecker` integration

**Exit criteria:**
- All authorization scenarios produce correct `VerifyResult`
- 100% of authorization tests pass including edge cases and tamper scenarios

#### Tasks

**Task 3.1: Full verification pipeline (wired to Radicle-backed storage)**
- *Why:* `DefaultBridge::verify_signer()` must work against the `AuthsStorage` impl from Epic 2
- *Acceptance criteria:* `verify_signer()` executes: DID translation -> identity repo lookup -> KEL validation -> attestation load -> RIP-X 2-way signature verification -> policy evaluation -> result.
- *Test plan:*
  - Unit: valid device with `sign_commit` capability -> `Verified`
  - Unit: revoked device -> `Rejected`
  - Unit: expired attestation -> `Rejected`
  - Unit: device with wrong capability -> `Rejected`
  - Unit: unknown device (no attestation) -> `Rejected`
  - Unit: valid device after key rotation (KEL sequence > 0) -> `Verified`
  - Tamper: modified attestation blob (signature mismatch) -> `Rejected`
  - Tamper: swapped `did-key` and `did-keri` blobs -> `Rejected`
- *Affected areas:* `crates/auths-radicle/src/verify.rs`, `crates/auths-radicle/src/bridge.rs`

**Task 3.2: Capability-scoped authorization**
- *Why:* Different operations require different capabilities
- *Acceptance criteria:* Bridge accepts a required capability and checks it against the attestation. `sign_commit` for ref updates; `sign_release` for release tags.
- *Test plan:*
  - Unit: device with `sign_commit` pushing refs -> `Verified`
  - Unit: device with only `sign_release` pushing refs -> `Rejected`
  - Unit: device with `[sign_commit, sign_release]` pushing release tag -> `Verified`
- *Affected areas:* `crates/auths-radicle/src/bridge.rs`, `crates/auths-radicle/src/verify.rs`

**Task 3.3: Threshold verification for multi-delegate projects**
- *Why:* Radicle projects can require M-of-N delegates
- *Acceptance criteria:* `verify_multiple_signers()` and `meets_threshold()` work with the full pipeline
- *Test plan:*
  - Unit: 3 signers, threshold 2, all valid -> passes
  - Unit: 3 signers, threshold 2, one revoked -> passes (2 valid remain)
  - Unit: 3 signers, threshold 2, two revoked -> fails
  - Unit: mixed `Did::Key` + `Did::Keri` delegates in threshold -> both types checked correctly
- *Affected areas:* `crates/auths-radicle/src/verify.rs`

---

### Epic 4: Stale-State Handling and Enforcement Modes

**Objective:** Implement observe/enforce modes and gossip-informed staleness detection.

**Why it matters:** Without explicit staleness handling, the system silently makes wrong decisions when identity state is incomplete. Without enforcement modes, users cannot choose their security/availability tradeoff.

**Success metrics:**
- Observe mode: never blocks updates, always logs warnings
- Enforce mode: rejects updates when identity state is unavailable or known-stale
- Gossip-informed staleness: warns when local identity repo tip differs from announced tip
- `min_kel_seq` correctly enforces binding integrity (not freshness)

**Exit criteria:**
- All mode/staleness combinations tested
- Stale-state test matrix passes
- Warning and quarantine messages include actionable information

#### Tasks

**Task 4.1: Enforcement mode configuration**
- *Why:* Projects must choose their security/availability tradeoff
- *Acceptance criteria:* Bridge accepts an enforcement mode (observe/enforce) per verification call. In observe mode, `Rejected` results are downgraded to `Warn`. In enforce mode, `Rejected` and `Quarantine` are hard rejections.
- *Test plan:*
  - Unit: observe mode + revoked device -> `Warn` (not `Rejected`)
  - Unit: enforce mode + revoked device -> `Rejected`
  - Unit: observe mode + missing identity repo -> `Warn`
  - Unit: enforce mode + missing identity repo -> `Quarantine`
- *Affected areas:* `crates/auths-radicle/src/bridge.rs`, `crates/auths-radicle/src/verify.rs`

**Task 4.2: Gossip-informed staleness detection**
- *Why:* `min_kel_seq` doesn't detect the "Node B at seq 3, revocation at seq 4" case. We need a better signal.
- *Acceptance criteria:* Bridge accepts an optional `known_remote_tip: Option<Oid>` (the latest identity repo tip OID seen via gossip). If provided and differs from the local identity repo tip, the bridge returns a staleness warning (`Warn` in observe, `Quarantine` in enforce).
- *Test plan:*
  - Unit: local tip == remote tip -> no staleness warning
  - Unit: local tip != remote tip -> staleness detected
  - Unit: no remote tip known (disconnected) -> no staleness warning (can't know)
  - Unit: remote tip provided, identity repo missing locally -> staleness + missing state
- *Affected areas:* `crates/auths-radicle/src/verify.rs`

**Task 4.3: Binding integrity via `min_kel_seq`**
- *Why:* Prevents accepting identity state that predates the project binding (e.g., attacker feeding truncated KEL)
- *Acceptance criteria:* Bridge compares `local_kel_sequence` against `min_kel_seq` from the project binding. If local < minimum, the result is `Rejected` (not just `Warn`) -- this is a tamper indicator, not a freshness signal.
- *Test plan:*
  - Unit: local seq 5, min seq 2 -> passes
  - Unit: local seq 2, min seq 2 -> passes (at minimum)
  - Unit: local seq 1, min seq 2 -> `Rejected` (binding integrity violation)
  - Unit: local seq 0 (only inception), min seq 3 -> `Rejected`
- *Affected areas:* `crates/auths-radicle/src/verify.rs`

**Task 4.4: Stale-state integration tests**
- *Why:* Must prove the system behaves correctly in the Node A vs Node B scenario under both modes
- *Acceptance criteria:* Integration tests simulating two nodes with different identity state, verifying correct behavior per mode
- *Test plan:*
  - Integration (observe): stale node accepts revoked device's update with `Warn`; after sync, rejects
  - Integration (enforce, staleness detected): stale node quarantines; after sync, rejects
  - Integration (enforce, no staleness signal): stale node accepts (irreducible risk); after sync, rejects
  - Integration: node with identity repo below `min_kel_seq` -> `Rejected` in both modes
  - Tamper: forged KEL event mid-chain -> `validate_kel()` fails -> `Rejected` regardless of mode
- *Affected areas:* `crates/auths-radicle/tests/`

---

### Epic 5: Minimal Radicle Integration Seam

**Objective:** Wire the bridge into Heartwood's fetch pipeline at the point defined by fn-3 and fn-4.

**Why it matters:** This is where the bridge actually gets called. The seam must align with Heartwood's existing epic plan.

**Success metrics:**
- `DeviceAuthorization` (fn-3) calls `auths-radicle::DefaultBridge::verify_signer()`
- Fetch pipeline (fn-4) passes enforcement mode and gossip tip to the bridge
- Projects without KERI delegates are unaffected

**Exit criteria:**
- Heartwood's existing test suite passes
- Projects with KERI delegates trigger bridge verification
- Observe/enforce mode is respected in the fetch pipeline

#### Tasks

**Task 5.1: Wire `DefaultBridge` into `DeviceAuthorization` (fn-3.2 counterpart)**
- *Why:* fn-3.2 in Heartwood creates `CompositeAuthorityChecker` which calls into auths-radicle. This task ensures the bridge API matches what Heartwood expects.
- *Acceptance criteria:* `DefaultBridge<RadicleAuthsStorage>::verify_signer()` signature is compatible with fn-3.2's expected API. Accepts `node_id: &[u8; 32]`, `repo_id: &str`, `now: DateTime<Utc>`, `enforcement_mode: Mode`, `known_remote_tip: Option<Oid>`.
- *Test plan:*
  - Unit: mock Heartwood caller invokes bridge with correct parameter types
  - Integration: end-to-end from `DeviceAuthorization::is_authorized()` through bridge to result
- *Affected areas:* `crates/auths-radicle/src/bridge.rs`, `crates/auths-radicle/src/verify.rs`

**Task 5.2: Pass gossip state to bridge in fetch pipeline (fn-4 counterpart)**
- *Why:* The bridge needs the `known_remote_tip` from gossip to detect staleness. This is available in the fetch pipeline from `RefsAnnouncement` data.
- *Acceptance criteria:* When the fetch pipeline calls the bridge, it includes the latest announced tip OID for the identity repo (if known from prior `RefsAnnouncement`s).
- *Test plan:*
  - Integration: fetch with gossip-announced identity repo tip -> bridge receives it
  - Integration: fetch without prior gossip data -> bridge receives `None`
- *Affected areas:* Heartwood: `crates/radicle-fetch/src/state.rs`. Auths: `crates/auths-radicle/src/bridge.rs`

---

### Epic 6: End-to-End Demo and Test Scenarios

**Objective:** Prove the integration works in realistic scenarios including the stale-node case.

**Why it matters:** End-to-end tests are the only way to prove the system works across crate boundaries and under realistic conditions.

**Success metrics:**
- All three demo scenarios (authorization, revocation, stale node) pass under both modes
- Tests run in CI without external dependencies

**Exit criteria:**
- End-to-end test suite passes on all CI platforms
- Demo script is executable and produces documented output

#### Tasks

**Task 6.1: Multi-device authorization end-to-end test**
- *Why:* Proves device authorization works through the full stack
- *Acceptance criteria:* Test creates a KERI identity (inception event + KEL), creates a 2-way attestation in RIP-X format, creates a project with a DID namespace, signs an update from the authorized device, and verifies the bridge accepts it.
- *Test plan:*
  - E2E: full flow from identity creation to update acceptance
  - E2E: unauthorized device (no attestation) is rejected
  - E2E: device with wrong capabilities is rejected
- *Affected areas:* `crates/auths-radicle/tests/`

**Task 6.2: Revocation end-to-end test**
- *Why:* Proves revocation stops a device from being authorized
- *Acceptance criteria:* Test creates identity, authorizes device, verifies acceptance, revokes device, verifies rejection. Tests under both observe and enforce modes.
- *Test plan:*
  - E2E: device accepted before revocation, rejected after (enforce mode)
  - E2E: device accepted before revocation, warned after (observe mode)
  - E2E: revocation of one device does not affect other authorized devices
  - E2E: re-authorization after revocation (new attestation) works
- *Affected areas:* `crates/auths-radicle/tests/`

**Task 6.3: Stale-node end-to-end test**
- *Why:* Proves the system behaves safely under the core adversarial scenario
- *Acceptance criteria:* Test simulates two nodes with different identity state and gossip knowledge. Verifies correct behavior per enforcement mode.
- *Test plan:*
  - E2E (observe): stale node accepts with `Warn`, converges to `Rejected` after sync
  - E2E (enforce, staleness detected): stale node quarantines, resolves after sync
  - E2E (enforce, no staleness signal): stale node accepts (irreducible risk, document this)
  - E2E: node with identity repo below `min_kel_seq` -> hard reject in both modes
  - Tamper: forged KEL event -> `Rejected` regardless of mode
- *Affected areas:* `crates/auths-radicle/tests/`

**Task 6.4: CI integration**
- *Why:* All tests must run in CI to prevent regressions
- *Acceptance criteria:* CI workflow runs the auths-radicle test suite. Tests work on Ubuntu, macOS, and Windows.
- *Test plan:*
  - CI: all tests pass on all three platforms
  - CI: tests complete within reasonable time (< 5 minutes)
- *Affected areas:* `.github/workflows/`, `crates/auths-radicle/`

---

### PR Slicing Plan

The work is sliced into 10 PRs, ordered by dependency. PRs target the **auths** repository unless noted.

| PR | Title | Epic | Description | Depends on |
|----|-------|------|-------------|------------|
| **PR 1** | RIP-X ref path constants and attestation format | 1 | `refs.rs` with RIP-X constants. `Attestation::to_bytes()` / `from_bytes()` for 2-blob format. | None |
| **PR 2** | `GitKel::with_ref()` for custom KEL ref paths | 1 | Allow auths-id's KEL reader to use `refs/keri/kel` instead of default path. | None |
| **PR 3** | `AuthsStorage` impl for Radicle-replicated repos | 2 | Load KEL + attestations from identity repos in RIP-X layout. | PR 1, PR 2 |
| **PR 4** | `find_identity_for_device()` and DID namespace scanning | 2 | Scan project namespaces to find which identity a device belongs to. | PR 3 |
| **PR 5** | Full authorization pipeline | 3 | Wire `verify_signer()` through the Radicle-backed storage. All auth scenarios tested. | PR 3, PR 4 |
| **PR 6** | Observe/enforce modes + gossip-informed staleness | 4 | Enforcement mode config, `known_remote_tip` staleness, `min_kel_seq` binding integrity. | PR 5 |
| **PR 7** | Stale-state integration tests | 4 | Node A vs Node B simulation under both modes. Tamper tests. | PR 6 |
| **PR 8** | Bridge API alignment with Heartwood fn-3.2 | 5 | Ensure bridge signature matches `DeviceAuthorization` expectations. Gossip tip passthrough. | PR 6 |
| **PR 9** | End-to-end tests | 6 | Full E2E: authorization, revocation, stale-node under both modes. | PR 7, PR 8 |
| **PR 10** | CI integration and demo script | 6 | CI workflow, demo documentation, cross-platform verification. | PR 9 |

```
PR 1 ──┐
PR 2 ──┼──► PR 3 ──► PR 4 ──► PR 5 ──► PR 6 ──► PR 7 ──► PR 9 ──► PR 10
       │                                  │                  ▲
       │                                  └──► PR 8 ────────┘
```

---

## 8. Demo Script

**Title:** "Multi-device authorization, revocation, and stale-node safety in 5 minutes"

**Prerequisites:** Two terminal windows (simulating two nodes). Radicle CLI with KERI support installed (fn-5 commands available). Both nodes running (`rad node start`).

---

**Act 1: Setup and Authorization (Node A = Alice, Node B = Bob)**

> "Alice creates her KERI identity and authorizes her laptop."

On Node A:
```
rad identity init-keri
# Shows: Created KERI identity did:keri:EXq5...
# Shows: Identity repo rad:z3gq... seeded to network
# Shows: Current device automatically attested (KEL sequence 1)

rad identity device add --key <laptop-nid>
# Shows: 2-way attestation created for <laptop-nid>
# Shows: Attestation anchored at KEL sequence 2
# Shows: Run `rad identity device confirm` on the laptop to complete
```

On Laptop (complete 2-way attestation):
```
rad identity device confirm --identity did:keri:EXq5...
# Shows: Device attestation signed and stored
```

> "She creates a project with her KERI identity as a delegate."

On Node A:
```
mkdir my-project && cd my-project && git init && echo "hello" > README.md && git add . && git commit -m "init"
rad init --name "my-project"
rad id update --allow did:keri:EXq5...
# Shows: Project delegate added: did:keri:EXq5...
# Shows: DID namespace refs/namespaces/did-keri-EXq5.../refs/rad/id -> rad:z3gq...
```

> "Bob seeds Alice's project. His node auto-discovers and fetches the identity repo."

On Node B:
```
rad seed rad:<project-rid>
rad sync --fetch
# Shows: Fetched project rad:<project-rid>
# Shows: Discovered KERI identity did:keri:EXq5... -> fetching identity repo rad:z3gq...
# Shows: Identity repo fetched, KEL at sequence 2
```

> "Alice's laptop pushes a commit."

On Laptop:
```
cd my-project
echo "feature code" > feature.rs
git add . && git commit -m "Add feature"
git push rad main
```

> "Bob's node accepts it -- the laptop is authorized via the KERI identity."

On Node B:
```
rad sync --fetch
# Shows: Fetched 1 update for my-project
# Shows: Signer <laptop-nid> VERIFIED (attested under did:keri:EXq5...)
```

**Act 2: Revocation**

> "Alice discovers her laptop was compromised. She revokes it."

On Node A:
```
rad identity device revoke <laptop-nid>
# Shows: Device <laptop-nid> revoked at 2026-03-01T14:00:00Z
# Shows: Revocation anchored at KEL sequence 3
# Shows: Updated identity repo pushed to network
```

> "Bob syncs and gets the revocation."

On Node B:
```
rad sync --fetch
# Shows: Identity repo rad:z3gq... updated to KEL sequence 3
# Shows: Device <laptop-nid> marked as revoked
```

> "The compromised laptop tries to push again."

On Laptop (simulating compromised device):
```
echo "malicious code" > backdoor.rs
git add . && git commit -m "Innocent update"
git push rad main
```

> "Bob's node rejects it (enforce mode)."

On Node B:
```
rad sync --fetch
# Shows: Signer <laptop-nid> REJECTED (device revoked at 2026-03-01T14:00:00Z)
# Shows: 0 updates applied from <laptop-nid>
```

**Act 3: Stale Node Safety**

> "Charlie is a new node that seeds the project but hasn't yet fetched the latest identity repo."

On Node C (or simulate by pausing identity repo sync on Node B):
```
rad seed rad:<project-rid>
# Charlie fetches the project but his identity repo is stale (sequence 2, pre-revocation)
# Meanwhile, gossip has announced a newer identity repo tip...
```

> "The compromised laptop pushes to Charlie."

```
rad sync --fetch
```

**Enforce mode (recommended):**
```
# Shows: Signer <laptop-nid> QUARANTINED
# Shows: Identity repo rad:z3gq... has newer tip available (announced via gossip)
# Shows: Fetch identity repo before accepting updates from KERI-attested devices
# Shows: 0 updates applied
```

> "Charlie fetches the identity repo and the quarantine resolves."

```
rad sync --fetch  # Now fetches identity repo
# Shows: Identity repo rad:z3gq... updated to KEL sequence 3
# Shows: Device <laptop-nid> is revoked -- quarantined update would have been rejected anyway
```

**Observe mode (alternative):**
```
# Shows: Signer <laptop-nid> VERIFIED (WARNING: identity state may be stale)
# Shows: Warning: identity repo rad:z3gq... has newer tip available
# Shows: 1 update applied with warning

# After syncing identity repo:
# Shows: Device <laptop-nid> revoked -- previously-accepted update flagged for review
```

> "Key takeaways:"
> 1. "In enforce mode, the stale node quarantined the update because it knew (via gossip) that its identity state was behind. No malicious data was accepted."
> 2. "In observe mode, the update was accepted but flagged. The system detected and logged the risk. After convergence, all nodes agree."
> 3. "The irreducible risk: a fully-disconnected node with no gossip signal cannot know it's stale. This is fundamental to any eventually-consistent system. The mitigation is to seed identity repos and maintain gossip connectivity."
