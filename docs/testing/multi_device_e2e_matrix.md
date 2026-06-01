# Multi-Device End-to-End Test Matrix

On-device scenarios exercised manually on real hardware (Mac + iPhone).
Each row has a precondition, steps, expected outcome, and a pass-log.
The matrix is living — update the "last run" column when re-verifying a
row; do not delete rows when they pass.

**Note**: rows whose "Device" column reads `ci / unit` are covered by
in-tree unit tests and do not require physical hardware to re-verify.
Rows requiring real devices depend on the iOS Swift rewrite landing
first.

| # | Scenario | Precondition | Steps | Expected | Last run | Device |
|---|---|---|---|---|---|---|
| 1 | Fresh `auths init` | No `~/.auths` on Mac | `rm -rf ~/.auths && auths init` | Device KEL created; stdout matches pinned copy; no shared identity yet | 2026-04-22 | ci / unit (`auths_sdk::keri::copy::format_init_success`) |
| 2 | First pair | Mac post-init + iPhone on clean install | `auths pair` on Mac, scan QR on iPhone, SAS confirm | Shared KEL created; both devices listed as controllers; `auths status` shows shared-KEL DID + both controllers | — | — |
| 3 | Second phone pair | Post-scenario-2 + second iPhone on clean install | `auths pair` on Mac, scan QR on iPhone-2 | `rot` adds third controller; `auths status` lists all three | — | — |
| 4 | Local device-key rotation | Post-scenario-2 | `auths identity rotate` on Mac | Mac's device KEL `s` advances; shared KEL unchanged; other devices still verify lazily | — | — |
| 5 | Remove a device | Post-scenario-3 | `auths device remove <iphone-did>` on Mac | Shared-KEL `rot` drops controller; `auths status` no longer lists the removed iPhone | — | — |
| 6 | Self-removal is rejected | Post-scenario-2 | `auths device remove <own-did>` | Structured error with pointer to `auths identity forget`; no rotation emitted | 2026-04-22 | ci / unit (self-removal pre-flight in `DeviceSubcommand::Remove`) |
| 7 | Stolen-laptop recovery | Post-scenario-2 with new Mac on clean install | `auths pair --recover <old-mac-did>` on new Mac, SAS confirm on iPhone | Single rotation swaps old Mac for new Mac; `auths status` reflects the swap atomically | — | — |
| 8 | Forget identity on iPhone | Post-scenario-2 | Settings → Forget Identity on iPhone | Keychain items absent (`security dump-keychain` shows no `dev.auths.*` entries); app returns to onboarding | — | — |
| 9 | Duplicity warning | Post-scenario-2 with simulated split-brain (two controllers sign conflicting rotations before sync) | Resync both sides | `auths status` shows pinned duplicity warning with actionable `auths device remove` instruction; iOS `IdentityView` shows orange banner | — | — |
| 10 | Duplicity resolution | Post-scenario-9 | `auths device remove <other-controller-did>` on the trusted side | After resync, all devices reach a clean state; `DuplicityReport::Clean` | — | — |
| 11 | Pair-URI size assertion | — | Attempt to construct a `SubmitResponseRequest` with `shared_kel_inception_event` larger than 1 KB | `validate()` returns structured error naming the cap | 2026-04-22 | ci / unit (`auths_pairing_protocol::types::SubmitResponseRequest::validate`) |

## How to Record a Run

When you exercise a scenario, update that row:

1. Fill in the **Last run** column with today's date (ISO 8601).
2. Fill in the **Device** column with a hardware identifier (e.g., `MBP14-M3`, `iPhone15Pro-US`).
3. If the scenario fails, open a task describing the regression and leave the row untouched — the matrix is a log, not a checklist.

## Related Documents

- `docs/architecture/multi_device_accepted_risks.md` — tradeoffs these scenarios are exercising.
- `essays/design/multi_device.md` — ladder overview.
