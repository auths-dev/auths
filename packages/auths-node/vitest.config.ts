import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    // Integration tests drive real KEL/keychain/git I/O; several routinely
    // take 3-4s on CI runners, so the 5s default is a flake margin, not a
    // guard. org add-member tipped over it on macos-latest (5149ms).
    testTimeout: 30000,
  },
})
