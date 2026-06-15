export const meta = {
  name: 'murmur-burndown',
  description: 'Scaffold + unattended FULL-STACK burndown for Murmur (phone-number-free messenger): Rust core in auths + SwiftUI iOS/macOS apps in ../murmur, one federated gate',
  phases: [
    { title: 'Scaffold', detail: 'PRD claims → baselined recurve suite + buildable murmur-core (auths) + buildable SwiftUI app skeleton (../murmur)' },
    { title: 'Preflight', detail: 'validate + federated gate on the fresh baseline' },
    { title: 'Burndown', detail: 'sequential cycles: triage → sculpt → gate → promote (core + apps; visual claims review-gated)' },
    { title: 'Wrap-up', detail: 'read-only report: ledger delta, parked, the human review/simulate queue' },
  ],
}

// murmur-burndown.js — a Murmur-specific twin of workflows/burndown.js.
//
// Murmur is GREENFIELD and FULL-STACK: cycle 0 scaffolds the suite + a buildable
// murmur-core (Rust, in the auths [target]) + a buildable SwiftUI multiplatform
// app skeleton (../murmur [sculpts.murmur]); then the same park-and-continue loop
// builds EVERY component — identity addressing/continuity, the relay/transport,
// the libsignal encryption integration, AND the iOS/macOS apps with Liquid Glass.
//
// Simulators are ALLOWED for this suite (the operator lifted the usual sacred
// restriction): a cycle MAY `xcrun simctl` boot an iOS/macOS sim and screenshot
// to verify its own work. ~/.auths, global git config, and live Docker stay sacred.
//
// Gate hygiene: the federated gate stays DETERMINISTIC/hermetic — cargo tests for
// the core; xcodebuild + snapshot tests + computed WCAG-contrast math for the app.
// A live-simulator screenshot is dev-verification + human review, NEVER the gate.
// Subjective "does the trust state read unmistakably under Reduce Transparency /
// Reduce Motion" claims are REVIEW-GATED — the loop builds + screenshots them and
// holds them for the operator to confirm by simulating; it never self-closes them.

const AUTHS = '/Users/bordumb/workspace/repositories/auths-base/auths'
const MURMUR = '/Users/bordumb/workspace/repositories/auths-base/murmur'
const CFG = '.recurve/murmur.toml'
const PROG = `recurve --config ${CFG}`
const PRD = '.recurve/prds/go_to_market/murmur.md'
const CAP = (args && args.cap) || 16
const MAX_FAILS = (args && args.maxConsecFails) || 3
const RUNAWAY = (args && args.runawayNetPositive) || 2

const RESULT_SCHEMA = {
  type: 'object',
  required: ['status', 'gap', 'attempts', 'net_new_gaps', 'summary'],
  additionalProperties: true,
  properties: {
    status: { enum: ['closed', 'parked', 'no-work-left', 'failed'] },
    gap: { type: 'string' },
    attempts: { type: 'integer' },
    files: { type: 'array', items: { type: 'string' } },
    net_new_gaps: { type: 'integer' },
    parked_reason: { type: 'string' },
    summary: { type: 'string' },
  },
}

const HARD_RULES = `Hard rules (non-negotiable, embedded because you are stateless):
- work in the auths repo at ${AUTHS} (where .recurve/ lives); run every recurve command as \`${PROG}\` from there. The app sculpt tree is ${MURMUR}.
- FIRST read ${AUTHS}/.recurve/AGENTS.md (conventions) and ${AUTHS}/.recurve/RUN.md (the per-cycle contract) and obey them.
- the PRD ${PRD} is CANONICAL and READ-ONLY: never edit, rename, duplicate, or recreate it. The old sovereign_messenger.md was intentionally renamed to murmur.md — do NOT recreate it under any name. Read it, build FROM it.
- NEVER run \`git reset\` / \`git checkout -- \` / \`git stash\` / \`git clean\` on the working tree, and never discard uncommitted changes you did not create — the operator may have edits in flight. Stage and commit ONLY the specific new paths your cycle created; never \`git add -A\` or \`git add .\`. SACRED (do not touch): ~/.auths, global git config, live Docker. Simulators are ALLOWED for this suite — you MAY \`xcrun simctl\` boot a sim and screenshot to verify your work.
- no loop vocabulary (gap ids, cycle names, the tool's name) in product code (auths crates OR ${MURMUR}) — leakcheck enforces both trees.
- the ONLY arbiter is \`${PROG} matrix --gate\`; rebuild BOTH trees before trusting any probe. Keep gate probes DETERMINISTIC (cargo / xcodebuild / snapshot / contrast-math) — a live-simulator screenshot is your dev check, not the gate.
- a subjective VISUAL claim (UI-TRUST etc.) is REVIEW-GATED: build it, screenshot it, leave it for the operator to confirm by simulating — never self-close it. Never sculpt a security-tradeoff gap.
- one gap per cycle; ~3 honest attempts then \`${PROG} park\` with an attempt journal (observations, never conclusions). A problem you find but can't close becomes a new DRAFT gap + probe sketch, never a TODO.
- commit policy: unsigned per-cycle (-c commit.gpgsign=false), no AI/Co-Authored attribution, never run a command that can prompt (signing hangs you), do NOT push. Commit PER-REPO — never one commit spanning auths and ${MURMUR}.`

phase('Scaffold')
const scaffold = await agent(
  `You are the SCAFFOLD cycle for Murmur — a greenfield, FULL-STACK recurve suite. Murmur is the ` +
  `phone-number-free messenger fully specified in ${AUTHS}/${PRD}. Read that PRD end to end, then ` +
  `${AUTHS}/.recurve/AGENTS.md, and use ${AUTHS}/.recurve/auths-mcp.toml + ${AUTHS}/.recurve/claims/auths-mcp/ ` +
  `as the EXACT template to mirror.\n\n` +
  `Produce a baselined, gate-green SKELETON (not the features — just enough that target + sculpt BUILD ` +
  `and every claim is an open RED draft):\n` +
  `1. ${AUTHS}/${CFG} — a multi-tree config mirroring auths-mcp.toml: [target] tree="." (auths) building the ` +
  `   new murmur core/relay crates; [sculpts.murmur] tree="${MURMUR}" (rebuild = xcodebuild for the iOS+macOS ` +
  `   schemes, gate = the app's snapshot+contrast test scheme); [reads.relay] artifact="bin/murmur-relay" ` +
  `   source="target/release/murmur-relay"; suite dir .recurve/claims/murmur; [gate] traps=required ` +
  `   quality=pre-launch leakcheck=on; [commit] unsigned-per-cycle; a [burndown] block. Set [target] sacred ` +
  `   to the usual list MINUS simulators (the operator lifted that for this suite).\n` +
  `2. murmur core in ${AUTHS}/crates — a buildable Rust lib (murmur-core) + a murmur-relay bin building to ` +
  `   target/release/murmur-relay, wired into the workspace Cargo.toml. A SKELETON that COMPILES.\n` +
  `3. ${MURMUR} — a NEW git repo: a buildable SwiftUI MULTIPLATFORM app skeleton (iOS + macOS targets, ` +
  `   latest-SDK / Liquid Glass), embedding murmur-core through a uniffi FFI like auths-mobile-ffi, plus a ` +
  `   test scheme with one trivial snapshot test and one WCAG-contrast unit test so \`gate\` is runnable. ` +
  `   Must build clean under xcodebuild. \`git init\` + an initial unsigned commit.\n` +
  `4. ${AUTHS}/.recurve/claims/murmur/ mirroring the template: gaps.yaml as DRAFT gaps drawn straight from ` +
  `   the PRD §10 thin slice — MSG-1, MSG-2, MSG-3, MSG-4, ENC-1..6, UI-TRUST — plus APP-1 "iOS+macOS apps ` +
  `   build and launch" and DEV-1 "a message sent from the Mac arrives, authenticated, on the iPhone sim". ` +
  `   Each draft gets a probe SKETCH (exit 1 RED, "feature absent") + a note on the trap it will need. Mark ` +
  `   UI-TRUST (and any purely-visual claim) review-gated. harness/env.sh + probes/_contract.sh mirrored; ` +
  `   bin/.gitignore.\n\n` +
  `Then iterate \`${PROG} validate\`, \`${PROG} baseline murmur\`, \`${PROG} matrix --gate\` until validate ` +
  `passes and the FEDERATED gate is GREEN (all drafts promoted to open RED; no BROKEN probe; ${MURMUR} builds ` +
  `and its gate scheme runs; no failed trap). Commit per-repo, unsigned, no attribution, no push.\n` +
  `${HARD_RULES}\n` +
  `Return ok=true ONLY if \`${PROG} validate\` passes AND \`${PROG} matrix --gate\` is green, with the open gap ids.`,
  { schema: { type: 'object', required: ['ok'], properties: { ok: { type: 'boolean' }, open_gaps: { type: 'array', items: { type: 'string' } }, detail: { type: 'string' } } } }
)
if (!scaffold || !scaffold.ok) {
  log('scaffold/baseline not green — refusing to burn down on a broken baseline')
  return { halted: 'scaffold', detail: scaffold && scaffold.detail }
}
log(`scaffold green — open gaps: ${(scaffold.open_gaps || []).join(', ')}`)

phase('Preflight')
const preflight = await agent(
  `Preflight the Murmur burndown from ${AUTHS}: run \`${PROG} validate\`, \`${PROG} matrix --gate\`, and ` +
  `\`${PROG} lock status\`. Change nothing, park nothing. Return ok=false with the failing output if anything ` +
  `is red or locked.`,
  { schema: { type: 'object', required: ['ok'], properties: { ok: { type: 'boolean' }, detail: { type: 'string' } } } }
)
if (!preflight || !preflight.ok) { log('preflight failed'); return { halted: 'preflight', detail: preflight && preflight.detail } }

phase('Burndown')
let fails = 0, runaway = 0, closed = 0
const cycles = []
for (let i = 1; i <= CAP; i++) {
  const result = await agent(
    `You are running EXACTLY ONE improvement cycle for Murmur (cycle ${i}/${CAP}) from ${AUTHS}.\n` +
    `Read ${AUTHS}/.recurve/RUN.md and obey it exactly. Triage with \`${PROG} next\`; if it reports no ` +
    `green-gate-sufficient open gaps, return status "no-work-left". Build the REAL feature — Rust core ` +
    `(identity / transport / encryption) and/or the SwiftUI app — turn its probe GREEN, rebuild both trees, ` +
    `and trust only \`${PROG} matrix --gate\`.\n${HARD_RULES}\n` +
    `Finish by returning the structured run record — never prose.`,
    { label: `cycle-${i}`, schema: RESULT_SCHEMA }
  )
  cycles.push(result)
  if (!result) { fails++; log(`cycle ${i}: agent died → failed cycle (${fails}/${MAX_FAILS})`) }
  else if (result.status === 'no-work-left') { log('no work left — halting'); break }
  else if (result.status === 'closed') { fails = 0; closed++; log(`cycle ${i}: closed ${result.gap}`) }
  else if (result.status === 'parked') { fails = 0; log(`cycle ${i}: parked ${result.gap} — ${result.parked_reason || ''}`) }
  else { fails++; log(`cycle ${i}: failed on ${result.gap} (${fails}/${MAX_FAILS})`) }
  runaway = result && result.net_new_gaps > 0 ? runaway + 1 : 0
  if (fails >= MAX_FAILS) { log('consecutive-failure watchdog — halting'); break }
  if (runaway >= RUNAWAY) { log('runaway-scope watchdog — halting to re-scope'); break }
}

phase('Wrap-up')
const wrap = await agent(
  `Read-only wrap-up for the Murmur burndown from ${AUTHS}. Run \`${PROG} matrix\`, \`${PROG} park\`, and ` +
  `\`${PROG} coverage\`. Report: ledger delta, parked list with reasons, and the human queue ranked — ` +
  `adjudications first, then the review-gated VISUAL claims for the operator to confirm by SIMULATING ` +
  `(name each + exactly how to view it: which app, which simulator, which accessibility setting), then ` +
  `parked triage. Change nothing.`,
  { schema: { type: 'object', required: ['report'], properties: { report: { type: 'string' }, simulate_queue: { type: 'array', items: { type: 'string' } }, parked: { type: 'array', items: { type: 'string' } } } } }
)

return { closed, cycles: cycles.filter(Boolean), wrapUp: wrap }
