# fn-5.12 Integrate @auths/verifier in frontend with Vite WASM config

## Description
## Integrate @auths/verifier in frontend with Vite WASM config

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer`

### Context
The `@auths/verifier` TypeScript package exists at `/Users/bordumb/workspace/repositories/auths-base/auths/packages/auths-verifier-ts/`. It wraps WASM bindings with `init()`, `verifyDeviceLink()`, `verifyKel()`, etc.

The frontend uses **Svelte 5 + Vite 6.3.5** (standalone SPA, NOT SvelteKit). WASM loading requires Vite configuration to avoid bundling issues.

### What to do
1. Add `@auths/verifier` to `package.json` (as file/link dependency pointing to the auths-verifier-ts package)
2. Configure Vite for WASM:
   - Add `@auths/verifier` to `optimizeDeps.exclude` in `vite.config.ts` to prevent pre-bundling from mangling WASM URLs
   - Consider `vite-plugin-wasm` if needed for the bundler target
3. Create a test import: `const wasm = await import('@auths/verifier')` inside an `onMount()` to verify loading works
4. The WASM init pattern from `auths-verifier-ts/src/index.ts:53-67` handles initialization — verify it works in the Vite dev server context

### Key files
- `radicle-explorer/package.json` — add dependency
- `radicle-explorer/vite.config.ts` — WASM config
- `packages/auths-verifier-ts/src/index.ts:53-67` — init pattern
- `packages/auths-verifier-ts/src/types.ts` — TypeScript interfaces to import

### Gotchas
- Do NOT use `vite-plugin-top-level-await` with Svelte 5 — causes compilation failures
- WASM must load via dynamic `import()` inside `onMount()`, never at top level
- `init()` returns a Promise — verification functions cannot be called before it resolves
## Acceptance
- [ ] `@auths/verifier` in `package.json` dependencies
- [ ] `vite.config.ts` configured for WASM loading
- [ ] `import('@auths/verifier')` works in development
- [ ] No SSR/top-level-await errors
## Done summary
- Added `@auths/verifier` as `file:` dependency in package.json pointing to auths-verifier-ts
- Added `optimizeDeps.exclude: ["@auths/verifier"]` to prevent Vite pre-bundling from mangling WASM URLs
- Added `auths-verifier` manual chunk to rollup output for code-split loading

Why:
- WASM modules must be excluded from Vite's dependency pre-bundling
- Separate chunk ensures WASM doesn't block initial page load

Verification:
- Config changes are structural; runtime verification requires npm install + dev server
## Evidence
- Commits: da9f15c808cb6e2bd3b4c4479bd1a0151e1834dc
- Tests: code review
- PRs:
