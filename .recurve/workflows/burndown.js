export const meta = {
  name: 'auths-network-burndown',
  description: 'Unattended claims burndown: one fresh agent per cycle, ratcheting monotonically',
  phases: [
    { title: 'Preflight', detail: 'validate + gate on the untouched baseline' },
    { title: 'Burndown', detail: 'sequential cycles: triage → sculpt → gate → promote' },
    { title: 'Wrap-up', detail: 'read-only report: ledger delta, parked, review queue' },
  ],
}

// burndown.js — orchestrator-runtime twin of workflows/burndown.sh.
// Deterministic control flow lives HERE; judgment lives in the agents. The
// same contract must stay runnable as the dumb shell loop (burndown.sh) so
// the loop is never married to one harness — RUN.md is the portability layer.
//
// Hard-won rules encoded below (each was paid for):
//  - park-and-continue: an un-greenable gap never halts the fleet
//  - watchdogs: cap, consecutive failures, runaway scope (net-gap-positive)
//  - structured results only: schema-validated, never free text
//  - the cycle prompt embeds the non-negotiable rules (agents are stateless)
//  - a timed-out/dead agent is a failed cycle, not a hang (results tolerate null)
//  - resume: relaunch with resumeFromRunId — completed cycles return cached
//
// Parallel burndown (v2): implemented in workflows/burndown-parallel.sh —
// worktree-isolated lanes over disjoint suites (`next --lanes`); the gate is
// the serialization point (gap GREEN + fleet gate per landing); failing
// candidates are reverted and discarded, re-run fresh against the new
// baseline. Never merge two sculpts. This sequential script remains the v1
// default; reach for lanes when wall-clock matters and suites are disjoint.

const CAP = (args && args.cap) || 12
const MAX_FAILS = (args && args.maxConsecFails) || 3
const RUNAWAY = (args && args.runawayNetPositive) || 2
const PARKED_SEED = (args && args.parked) || []
const PROG = 'recurve'

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
- never git reset/checkout shared state; never touch sacred paths
- no loop vocabulary (gap ids, cycle names, tool name) in product code
- never sculpt review-gated (security-tradeoff) gaps
- ~3 honest attempts then park with an attempt journal (observations, never conclusions)
- rebuild before trusting any probe; the only arbiter is \`${PROG} matrix --gate\`
- commit policy: none — never run a command that can prompt`

phase('Preflight')
const preflight = await agent(
  `Run preflight for the auths-network burndown. Execute \`${PROG} validate\` and ` +
  `\`${PROG} matrix --gate\` and \`${PROG} lock status\`. Park nothing, change nothing. ` +
  `Seed-park these still-stuck gaps first: ${JSON.stringify(PARKED_SEED)} via ` +
  `\`${PROG} park <id> --reason "seeded from prior run"\`. ` +
  `Return ok=false with the failing output if anything is red or locked.`,
  { schema: { type: 'object', required: ['ok'], properties: { ok: { type: 'boolean' }, detail: { type: 'string' } } } }
)
if (!preflight || !preflight.ok) {
  log('preflight failed — never start an unattended run on a broken baseline')
  return { halted: 'preflight', detail: preflight && preflight.detail }
}

phase('Burndown')
let fails = 0, runaway = 0, closed = 0
const cycles = []
for (let i = 1; i <= CAP; i++) {
  const result = await agent(
    `You are running EXACTLY ONE improvement cycle for auths-network (cycle ${i}/${CAP}).\n` +
    `Read .recurve/RUN.md and obey it exactly. Triage with \`${PROG} next\`; if it reports no ` +
    `green-gate-sufficient open gaps, return status "no-work-left".\n${HARD_RULES}\n` +
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
  `Read-only wrap-up for the auths-network burndown. Run \`${PROG} matrix\`, ` +
  `\`${PROG} park\`, \`${PROG} coverage\`. Report: ledger delta, parked list with ` +
  `reasons, the review-gated queue. Rank the human queue: adjudications first ` +
  `(one human sentence unblocks the most agent-work), then review-gated ` +
  `promotions, then parked triage. Change nothing.`,
  { schema: { type: 'object', required: ['report'], properties: { report: { type: 'string' }, parked: { type: 'array', items: { type: 'string' } } } } }
)

return { closed, cycles: cycles.filter(Boolean), wrapUp: wrap }
