# Auths CLI Developer Experience Analysis

**Date:** 2026-03-27
**Smoke Test Results:** 30/34 passed (88%)
**Scope:** All 10 phases of the identity lifecycle across 34 commands

---

## Executive Summary

The Auths CLI is **functionally solid** but has **discoverability and DX friction points** that could prevent new users from succeeding. The most impactful improvements are:

1. **Unhide advanced commands** so users can discover them without `--help-all`
2. **Fix command inconsistencies** (subcommand naming patterns)
3. **Improve error messages** with actionable next steps
4. **Add examples to all critical help text**
5. **Resolve trust policy friction** for first-time verification

**Critical Path Blockers:** Identity verification (trust policy), command discoverability, help text clarity.

---

## Test Results Summary

| Phase | Commands | Passed | Failed | Skip |
|-------|----------|--------|--------|------|
| 1: Init & Identity | 3 | 3 | 0 | 0 |
| 2: Key & Device | 3 | 3 | 0 | 0 |
| 3: Sign & Verify | 2 | 1 | 1 | 0 |
| 4: Config & Status | 2 | 1 | 1 | 0 |
| 5: Identity Management | 2 | 1 | 1 | 0 |
| 6: Advanced Features | 5 | 5 | 0 | 0 |
| 7: Registry & Account | 3 | 3 | 0 | 0 |
| 8: Agent & Infrastructure | 4 | 4 | 0 | 0 |
| 9: Audit & Compliance | 1 | 1 | 0 | 0 |
| 10: Utilities & Tools | 9 | 8 | 1 | 0 |
| **TOTAL** | **34** | **30** | **4** | **0** |

### Failures Breakdown

| Failure | Actual Error | Root Cause | Category |
|---------|--------------|-----------|----------|
| `auths verify (artifact)` | Trust policy error | Explicit trust policy not set; unclear recovery | **Friction** |
| `auths doctor` | Exit code 1 (env issue) | ssh-keygen not on PATH; doctor rightly fails | **Environment** |
| `auths id list` | "unrecognized subcommand" | No `list` subcommand; inconsistent with expectations | **Discoverability** |
| `auths error list` | "Unknown error code: LIST" | Wrong syntax; should be `--list` not `list` | **Inconsistency** |

---

## Phase-by-Phase Analysis

### Phase 1: Initialization & Core Identity

**Current Flow:**
```bash
auths init --profile developer --non-interactive --force
auths status
auths whoami
```

**Pain Points:**

1. **Non-obvious interactive vs. non-interactive mode**
   - Help text explains it but doesn't highlight the three profiles clearly
   - No examples of what each profile sets up
   - Users may not understand why they should choose "developer" vs "ci" vs "agent"

2. **`--force` flag feels aggressive**
   - Help text doesn't explain what "force" overrides
   - Should clarify: "Overwrite existing identity if present" vs "Start fresh"

3. **Markdown formatting bug in help text**
   - Usage section shows: `Usage: ```ignore // auths init // ...`
   - Looks like unrendered markdown; should be clean examples

4. **Missing success feedback after init**
   - Silent success is good for scripting, but for interactive users, no confirmation
   - `auths status` works but users have to run it themselves

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| Unclear profiles | Add examples to `--help`: show output of each profile | Interactive chooser if TTY | Smart defaults based on git config |
| `--force` confusing | Clarify: "Overwrite existing identity" | Confirm before overwriting | Structured prompt for recovery |
| Markdown formatting | Fix help text rendering | Standardize help format | Help text template system |
| No success feedback | Add `✓ Identity created` message | Show identity DID in output | Pretty-print identity details |

---

### Phase 2: Key & Device Management

**Current Flow:**
```bash
auths key list
auths device list
auths pair --help
```

**Pain Points:**

1. **`key list` and `device list` succeed but are minimal commands**
   - `key list` output is sparse; no context about usage or roles
   - `device list` shows devices but doesn't explain what each field means
   - Users won't know if they should have keys/devices or how to add more

2. **No `create`, `add`, or `register` commands for keys/devices**
   - To create a new key, users must discover `auths id rotate` (for identity keys) or `auths device pair` (for device keys)
   - No obvious path to "I want to add a new key"

3. **`pair` is a top-level command, but `device` also exists**
   - Confusion: is it `auths pair` or `auths device pair`?
   - `pair` and `device` feel like they should be subcommands of each other

4. **Missing help for what "pairing" means**
   - `auths pair --help` is generic; doesn't explain the workflow
   - Should clarify: "Link this machine's device key to your identity"

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| Sparse list output | Add descriptions/labels to list output | Show device/key roles | Unified key/device view |
| No create commands | Add `auths key create` | Integrated setup workflow | Key lifecycle dashboard |
| `pair` vs `device` confusion | Add cross-reference in help | Consolidate under one command | Command namespace review |
| Unclear pairing docs | Add example: "# Link a second machine" | Interactive pairing guide | Wizard for device onboarding |

---

### Phase 3: Signing & Verification

**Current Flow:**
```bash
auths sign /path/to/artifact
auths verify /path/to/artifact
```

**Pain Points:**

1. **Trust policy error on verify is opaque**
   - Error: `Unknown identity 'did:keri:E8...' and trust policy is 'explicit'`
   - Suggests: "1. Add to .auths/roots.json in the repository"
   - Problem: Users don't know what `roots.json` is, where to find it, or how to edit it
   - Error doesn't explain WHY trust policy exists

2. **No guidance on trust policy setup**
   - `auths init` doesn't set up trust policy automatically
   - First verify fails mysteriously
   - Users must edit `.auths/roots.json` manually with no UX guidance

3. **Signature file naming convention unclear**
   - `auths sign artifact.txt` produces `artifact.txt.auths.json`
   - Help text says "Defaults to <FILE>.auths.json" but doesn't explain the naming
   - Users might not realize the file was created

4. **`sign` and `verify` don't have reciprocal help text**
   - `sign --help` doesn't mention what verify expects
   - `verify --help` doesn't mention how to prepare files for verification
   - Workflow is not obvious from individual help texts

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| Opaque trust policy error | Show exact path to roots.json | Add `auths trust add <did>` | Auto-trust own identity |
| No trust setup in init | Add `--setup-trust` flag | Interactive trust setup | Trust policy wizard |
| Unclear signature naming | Show filename in output: "Signed → artifact.txt.auths.json" | Configurable naming | Output summary with paths |
| Reciprocal help gap | Link verify in sign help, vice versa | Add workflow example | Sign/verify unified command |

**Highest Priority:** Fix trust policy error message with actionable next step + path.

---

### Phase 4: Configuration & Status

**Current Flow:**
```bash
auths config show
auths doctor
```

**Pain Points:**

1. **`doctor` exit code 1 on environment issues**
   - ssh-keygen not found → doctor fails → script stops
   - Output is helpful but exit code masks success of actual Auths checks
   - Users can't tell if Auths is working or if environment is misconfigured

2. **`config show` output is raw JSON**
   - No explanation of what each field means
   - New users don't know if their config is correct
   - No suggested next steps

3. **No "status" clarity for common scenarios**
   - `auths status` works but output is verbose
   - No summary of "what can I do right now?"
   - Should answer: "Can I sign commits? Can I verify signatures?"

4. **No dry-run or preview mode for config changes**
   - `auths config` doesn't have `--dry-run`
   - Users can't preview what a config change would do

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| doctor exit code | Exit 0 if Auths checks pass (only fail on critical) | Separate output for warnings/info | Structured health reporting |
| Raw JSON config | Pretty-print with field annotations | Add `--explain` mode | Config validation UI |
| Unclear status | Highlight critical info (signing ready?) | Status dashboard view | Capability summary |
| No dry-run | Add `config set --dry-run` | Preview + confirmation | Config change workflow |

---

### Phase 5: Identity Management

**Current Flow:**
```bash
auths id list  # ✗ FAILS: "unrecognized subcommand 'list'"
auths signers list
```

**Pain Points:**

1. **`auths id list` does not exist**
   - Smoke test expects `auths id list` but the command is `auths id show`
   - Error message: "unrecognized subcommand 'list'" with suggestion "similar: register"
   - UX gap: users expect "list" pattern from other commands

2. **Inconsistent subcommand naming across CLI**
   - `auths key list` ✓ works
   - `auths device list` ✓ works
   - `auths id list` ✗ doesn't exist (should be `show` or add `list`)
   - `auths signers list` ✓ works
   - Pattern inconsistency breaks user mental model

3. **`auths id` has too many subcommands**
   - `create`, `show`, `rotate`, `export-bundle`, `register`, `claim`, `migrate`, `bind-idp`
   - No clear grouping or learning path
   - New users don't know what each does or when to use it

4. **`id show` output is cryptic**
   - Shows DID and storage ID but no context
   - Doesn't explain what these identifiers mean
   - No examples of what to do next

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| `id list` missing | Add `auths id list` as alias for `show` or new list subcommand | Audit all `list` patterns | Standardize list/show semantics |
| Inconsistent subcommands | Rename `show` → `list` or add `list` | Command namespace audit | Design command patterns doc |
| Too many subcommands under `id` | Group docs better: show relationships | Split into `auths id` (local) + `auths identity` (remote) | Hierarchical command structure |
| Cryptic show output | Add annotations: "Your identity:" + explain DID | Pretty-print with examples | Identity summary command |

---

### Phase 6: Advanced Features

**Current Flow:**
```bash
auths policy --help
auths approval --help
auths trust --help
auths artifact --help
auths git --help
```

**All passed.** But:

**Pain Points:**

1. **All advanced commands are hidden by default**
   - Requires `auths --help-all` to see: `id`, `device`, `key`, `policy`, `approval`, `trust`, etc.
   - New users won't know these exist
   - First-time usage: `auths --help` shows only basic commands

2. **Help text for hidden commands is sparse**
   - `policy --help`, `approval --help` are minimal
   - No examples of real workflows
   - Users must read docs or source code to understand

3. **Advanced features are powerful but undiscoverable**
   - KERI, witness management, policy expressions, approval gates
   - No graduation path from beginner to advanced
   - No hints like "for advanced workflows, try `auths policy`"

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| Hidden commands | Unhide `policy`, `approval`, `trust`, `artifact`, `git` | Progressive disclosure: show in status | Help system with learning paths |
| Sparse help text | Add examples to all commands: "# Use case: ..." | Interactive help with scenarios | Guided workflows |
| No discovery path | Add section in `status` output: "Try these next:" | Capability scoring | Feature recommendation engine |

---

### Phase 7: Registry & Account

**Current Flow:**
```bash
auths account --help
auths namespace --help
auths org --help
```

**All passed.** But:

**Pain Points:**

1. **`account`, `namespace`, `org` feel disconnected from identity lifecycle**
   - When would a user use these? What problem do they solve?
   - No clear relationship to earlier init/sign/verify phases
   - Hidden by default; users won't discover them

2. **No onboarding for registry features**
   - `auths init` doesn't mention registry
   - No guide: "Once you have an identity, you can register and claim a namespace"
   - Users must intuit the workflow

3. **Help text doesn't explain concepts**
   - What's the difference between account, namespace, org?
   - Why would you register vs. claim vs. bind?
   - No mental model building

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| Disconnected from lifecycle | Add to status output: registry account info | Integrated onboarding wizard | Registry-aware init |
| No onboarding | Add examples: "# Claim a username" | Guided registry workflow | Step-by-step tutorial |
| Concept confusion | Add description to help: "Account = ..." | Multi-level help system | Domain glossary |

---

### Phase 8: Agent & Infrastructure

**Current Flow:**
```bash
auths agent --help
auths witness --help
auths auth --help
auths log --help
```

**All passed.** But:

**Pain Points:**

1. **`agent`, `witness`, `auth` are highly specialized**
   - No clear trigger for when to use these
   - Help text is minimal; doesn't explain operational context
   - Hidden by default

2. **`auth` vs `account` confusion**
   - Both exist; unclear difference
   - No cross-reference in help text
   - Users might try wrong command

3. **No operational guidance for infrastructure features**
   - How to set up a witness? When would I need one?
   - How to enable auth for services?
   - Missing troubleshooting context

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| Specialized features hidden | Add section in docs: "Advanced Operators" | Context-aware help | Role-based help mode |
| `auth` vs `account` | Add clarification in both help texts | Rename for clarity | Command naming audit |
| Missing operational docs | Link to guides in help text | In-CLI operator manual | Just-in-time help |

---

### Phase 9: Audit & Compliance

**Current Flow:**
```bash
auths audit --help
```

**Passed.** But:

**Pain Points:**

1. **`audit` is hidden; no one knows it exists**
   - Only discoverable via `--help-all` or source code
   - Critical for compliance workflows but invisible

2. **Help text doesn't explain audit purpose**
   - What gets audited? Who should run this?
   - Where does output go?
   - How is it used?

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| Hidden from users | Unhide `audit` | Audit readiness check | Compliance dashboard |
| Missing context | Add examples: "# Generate compliance report" | Explain audit trail | Structured audit output |

---

### Phase 10: Utilities & Tools

**Current Flow:**
```bash
auths error list        # ✗ FAILS: Wrong syntax
auths completions bash
auths debug --help
auths tutorial --help
auths scim --help
auths emergency --help
auths verify --help
auths commit --help
auths --json whoami
```

**Pain Points:**

1. **`auths error list` fails; should be `auths error --list`**
   - Inconsistent with pattern expectations
   - Error message: "Unknown error code: LIST"
   - Should suggest correct syntax

2. **Help text formatting issues**
   - Markdown-like syntax not rendered: `Usage: ```ignore //...`
   - Looks unprofessional; confuses users
   - Affects multiple commands (init, etc.)

3. **`completions` command is hidden**
   - Users won't know shell completions exist
   - Should be discoverable and easy to install

4. **`debug`, `emergency`, `scim` are obscure**
   - Purpose unclear from name alone
   - No hints when they should be used
   - Hidden by default

5. **`tutorial` help text is minimal**
   - Should summarize what topics are covered
   - Should show available lessons

6. **JSON output not documented**
   - `--json` flag works but users might not know about it
   - No examples of JSON output format
   - Help text doesn't highlight this capability

**Recommended Improvements:**

| Issue | Quick Win | Medium | Architectural |
|-------|-----------|--------|-----------------|
| `error list` wrong | Fix error message: "Try: auths error --list" | Standardize flag patterns | Command design rules |
| Markdown formatting | Fix help text rendering | Build help text system | Documentation engine |
| `completions` hidden | Unhide + add install guidance | Auto-detect shell, suggest install | Shell integration wizard |
| Obscure utilities | Add context: "debug: troubleshoot issues" | Help text with examples | Just-in-time help system |
| `tutorial` sparse | Show available lessons in help | Interactive lesson explorer | Learning mode for CLI |
| JSON undocumented | Add examples to main help | JSON schema documentation | Machine-readable docs |

---

## Cross-Cutting Pain Points

### 1. Command Discoverability (HIGH IMPACT)

**Problem:** Many powerful commands are hidden by default. Users must run `--help-all` to discover them.

**Evidence:**
- 20+ commands hidden with `#[command(hide = true)]`
- Help text says: "Run 'auths --help-all' for advanced commands"
- Smoke test assumes users will discover commands somehow

**Impact:** New users never learn about `policy`, `approval`, `trust`, `artifact`, `id`, `device`, `key`, etc.

**Recommendation:**
- Unhide frequently-used commands: `id`, `device`, `key`, `config`, `git`
- Keep operational commands hidden: `witness`, `scim`, `emergency`, `debug`
- Add footer hint in `status` output: "Explore more with `auths id`, `auths policy`, `auths trust`"

---

### 2. Inconsistent Subcommand Patterns (MEDIUM IMPACT)

**Problem:** Similar concepts use different subcommand naming.

| Command | Pattern |
|---------|---------|
| `auths key list` | `list` subcommand ✓ |
| `auths device list` | `list` subcommand ✓ |
| `auths id show` | **No `list`** ✗ |
| `auths signers list` | `list` subcommand ✓ |
| `auths error --list` | **Flag, not subcommand** ✗ |

**Recommendation:** Standardize:
- Add `auths id list` (or rename `show` to `list`)
- Change `auths error --list` to `auths error list`
- Document pattern: "Commands with multiple items use `<entity> list`"

---

### 3. Error Messages Lack Actionable Next Steps (MEDIUM IMPACT)

**Problem:** Errors explain what went wrong but not how to fix it.

| Command | Error | Missing |
|---------|-------|---------|
| `auths verify` | "Unknown identity ... trust policy is 'explicit'" | "Run `auths trust add <did>` or edit ~/.auths/roots.json" |
| `auths id list` | "unrecognized subcommand 'list'" | "Did you mean `auths id show`?" |
| `auths error list` | "Unknown error code: LIST" | "Try `auths error --list` to see all codes" |

**Recommendation:**
- Every error should include: "Next step: ..."
- Use clap's suggestion feature to recommend similar commands
- Add error code system with searchable explanations

---

### 4. Help Text Quality Issues (MEDIUM IMPACT)

**Problems:**
- Markdown not rendered (`Usage: ```ignore // ...`)
- Sparse descriptions without examples
- No links between related commands
- Missing "use case" or "when to use this"

**Evidence:**
- `auths init --help` shows unrendered code block
- `auths policy --help` has 2-line description; no examples
- `auths trust --help` doesn't explain trust policy concept

**Recommendation:**
- Add standard help format: Description → Use Cases → Examples → Related Commands
- Pre-render markdown before displaying
- Add `(hidden)` badge to hidden commands in cross-references

---

### 5. First-Time User Friction (HIGH IMPACT)

**Critical Path:** `init` → `sign` → `verify`

**Friction Points:**
1. Init completes silently (no confirmation of success)
2. Sign produces file with auto-generated name (no confirmation)
3. Verify fails on trust policy (opaque error, unclear recovery)

**Mental Model:** User thinks they're done after `init`, but actually they're stuck when they verify.

**Recommendation:**
- Confirm after init: "✓ Identity created: did:keri:E8i..."
- Show after sign: "Signed → ./artifact.txt.auths.json"
- Auto-trust own identity during init, or guide trust setup with `auths verify --help`

---

### 6. JSON Output Underdocumented (LOW IMPACT)

**Problem:** `--json` flag exists but users might not know about it.

**Evidence:**
- Help text mentions `--json` but no examples
- No documentation of JSON schema
- Used in smoke test but not explained

**Recommendation:**
- Add `--json` examples to critical commands: `status`, `whoami`, `key list`
- Link to JSON schema or add `--json-schema` option
- Document in tutorial

---

## Recommended Implementation Roadmap

### Phase 1: Quick Wins (1-2 days)

1. **Fix error messages** (highest ROI)
   - Trust policy error: Add path and actionable step
   - Subcommand errors: Use clap suggestions
   - `auths error` syntax: Suggest `--list`

2. **Add help text examples**
   - `auths id --help`: Show `auths id show`, `auths id register`
   - `auths sign --help`: Show expected output filename
   - `auths verify --help`: Link to `auths trust` for setup

3. **Fix markdown rendering**
   - Remove code block markdown from help text
   - Use raw text examples

4. **Add success feedback**
   - Init: Print identity DID after success
   - Sign: Print output filename
   - Verify: Print verification details

### Phase 2: Medium Effort (3-5 days)

1. **Unhide key commands**
   - Remove `hide = true` from: `id`, `device`, `key`, `config`, `git`, `policy`, `approval`, `trust`, `artifact`, `audit`
   - Keep hidden: `witness`, `scim`, `emergency`, `debug`, `log` (operational/specialized)

2. **Standardize subcommand patterns**
   - Add `auths id list` subcommand
   - Change `auths error --list` to `auths error list`
   - Document pattern in CLAUDE.md

3. **Improve list output**
   - Add column headers
   - Show descriptions/roles
   - Add "Try this next" hints

4. **Add configuration wizard for trust policy**
   - Create `auths trust init` or wizard in verify error
   - Guide user to add own identity to roots.json

### Phase 3: Architectural (1-2 weeks)

1. **Help text system**
   - Template for all commands: Description → Use Cases → Examples → Related
   - Pre-render markdown
   - Auto-link related commands

2. **Progressive disclosure**
   - Show basic commands by default
   - Hint at advanced commands in output
   - Add learning path in tutorial

3. **Error handling framework**
   - Error enum with actionable recovery
   - Consistent error rendering
   - Error code catalog with examples

4. **Command discovery improvements**
   - `status` output shows available next steps
   - `--help` for any error that suggests commands
   - "New to Auths?" section in main help

---

## Success Criteria for MVP CLI

- [ ] New user can init → sign → verify in <5 minutes without docs
- [ ] Every error message includes "Next step: ..."
- [ ] All `list`-like commands use `<entity> list` pattern
- [ ] All public commands visible by default (no `--help-all` needed)
- [ ] Every command has ≥2 real-world examples
- [ ] Trust policy setup is guided, not mysterious
- [ ] Help text is clean (no unrendered markdown)

---

## Summary: Top 5 Highest-Impact Changes

| Priority | Change | Impact | Effort | ROI |
|----------|--------|--------|--------|-----|
| 🔴 1 | Fix trust policy error message + add guided setup | Unblocks core workflow | 1 day | 10/10 |
| 🔴 2 | Unhide advanced commands | Enables discovery | 2 hours | 9/10 |
| 🟡 3 | Standardize subcommand patterns (add `id list`) | Mental model consistency | 1 day | 7/10 |
| 🟡 4 | Add success feedback (init, sign) | User confidence | 4 hours | 8/10 |
| 🟡 5 | Fix markdown in help text | Professionalism | 2 hours | 6/10 |

---

## Critical Path Blockers

**Must fix before v0.1 launch:**
1. Trust policy verification error is opaque (users get stuck)
2. Command naming inconsistency breaks mental model (`id list` vs `id show`)
3. Help text formatting looks broken (markdown not rendered)

**Should fix before v0.1 launch:**
1. Hidden commands prevent discovery of powerful features
2. Error messages don't guide users to recovery

**Can defer to v0.2:**
1. Progressive disclosure (learning path hints)
2. Advanced help text improvements
3. JSON schema documentation

---

## Files to Modify

### High Priority
- `src/commands/error_lookup.rs` — Better error message for `--list` syntax
- `src/commands/unified_verify.rs` — Trust policy error with actionable guidance
- `src/commands/id/identity.rs` — Add `List` subcommand or rename `Show`
- `src/cli.rs` — Unhide commands, fix `hide = true` markers

### Medium Priority
- `src/commands/init/guided.rs` — Add success feedback after init
- `src/commands/sign.rs` — Show output filename after sign
- `src/commands/status.rs` — Add "Try these next" section
- Help text in all commands — Add examples using clap's `after_help`

### Lower Priority
- `src/errors/renderer.rs` — Structured error recovery suggestions
- Tests — Verify all commands work with new patterns

---

## Conclusion

The Auths CLI has a solid foundation and most commands work. The path to MVP readiness is clear:

1. **Fix friction points** (trust policy, help text formatting)
2. **Improve consistency** (subcommand patterns)
3. **Enhance discoverability** (unhide commands, show hints)
4. **Add examples** (critical for learning)

With these changes, new users can complete the core workflow (init → sign → verify) confidently in under 5 minutes. The advanced features will remain accessible but won't overwhelm beginners.

**Estimated effort:** 5-10 days of focused work across the CLI, error handling, and help text systems.
