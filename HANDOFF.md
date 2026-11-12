<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Handoff: `product/momentum-workspace` (Momentum workspace)

This branch is LumberJack `main` at the cut commit `da93661` (`main` `d18f3e7` plus the design and the
compatibility fixtures), with this file added. The whole tree is here, unchanged, so the product
builds and its tests run exactly as they did. `main` removes this code at P3b-5
(`docs/extension-api.md` §8) and does not port, maintain or fix it. The design this hands off
against is `docs/keep-move.md` and `docs/extension-api.md` on this branch.

## What it is

Momentum's workspace: the `/workspace` projection and `/workspace/commands` (create, update, log,
plan, run, timers, subscribe, preferences), the work codec (`work_*`), the feed (`/feed`,
`/feed/preferences`, reminders and alerts), conversations and messages (`/conversations*`), the
attachment index (`/assets/index`), the `core.Conversation`, `core.FeedState` and
`core.FeedPreferences` types, and `internal/ciphertext` (`Product` must be `momentum|manifest`,
`envelope.go:48`).

## Seams it used in the old engine

| Call point (at the cut) | What it did |
|---|---|
| `api.go` routes | `/workspace`, `/workspace/commands`, `/conversations` (GET, POST), `/conversations/{id}/messages` (GET, POST), `/conversations/{id}/membership`, `/conversations/{id}/preferences` |
| `activation_application.go:30-60` | application-only `/feed`, `/feed/preferences`, `/assets/index` and the message operations |
| `application.go:165-171` | backpressure exemptions naming its routes |
| `application_hub.go:16` `enqueueCorrespondence(actor, WorkCommand, path)` | the `share` / `assigned_to` / `kind == "conversation"` recipient rules |
| `application_hub.go:358` `/notifications` filter | re-derived entitlement from `node.Kind != "conversation"` and `Metadata["assigned_to"]` |
| `application_changes.go:21` `notificationRevision` | hashed `workMetadata(node)` minus `"preferences"` |
| `access.go:254`, `access.go:271-287` | the share notice as a `WorkCommand`, and `stopRevokedAccessTimer` through `workActive` |
| `secure_storage.go:189-232` | the encrypted `conversations` section with per-member key wraps |
| root `subscriptions` | written only by its `subscribe` command and reminders |

## Public extension seams that replace them

| Old call point | Seam (`docs/extension-api.md`) |
|---|---|
| its HTTP and application-only routes | `extension.RouteProvider` with `Transport` and `BackpressureExempt` (§4.3) |
| `enqueueCorrespondence` | `extension.Tx.Enqueue(core.OutboxChange{..., Direct})`; the caller decides recipients (§4.6) |
| the `/notifications` re-derivation | the recorded `Direct` flag; `extension.OutboxEntitlement` vouches for records written before it |
| `notificationRevision` over `workMetadata` | the generic node projection minus presentation-only metadata keys |
| revoked-access timer stop | generic, over `core.TimeEntryStart` / `TimeEntryStop` |
| `conversations`, `correspondence.feed` | root slot key and outbox slot key (§4.5) |

## FFI exports it takes

None. Its routes are reached through `ic_lj_application_call`.

## What a product must do to rebuild on the extension API

1. Implement `extension.Extension` with `Spec{Name: "momentum-workspace", Slot: {RootKeys: [{Name: "conversations"}], OutboxKeys: [{Name: "feed"}]}}`.
2. Register its routes through `RouteProvider`; write only through `Host.Change`; publish with
   `Host.Publish` after `Change` returns.
3. Enqueue notices with `Tx.Enqueue`, setting `Direct` for assignment and conversation recipients.
4. Implement `OutboxEntitlement` if records written before `Direct` must stay visible.
5. Rebuild `ciphertext` outside the engine if it is still wanted.

## State it owns in existing stores

| Key | Level | Without this extension registered |
|---|---|---|
| `conversations` | root | preserved byte-for-byte; never projected. An encrypted store's `conversations` section is read into this slot and, on write, sealed inside the backend-only root (Q4(a)) |
| `correspondence.feed` | outbox | preserved byte-for-byte |
| `subscriptions` | root (generic, stays typed) | still the outbox's recipients; nothing new writes them |
| work metadata (`assigned_to`, `preferences`, …) on nodes | node `metadata` (generic) | ordinary metadata |

## When it left `main`

`finalize/split` commit `254c0be` (P3b-5), except `internal/core/conversation.go`,
`internal/core/feed_state.go` and `internal/core/feed_preferences.go`, which held `core.Node`'s and
`core.Outbox`'s typed fields until `7386fc6` (P3b-8, deviation D7). From then on `conversations` is a
root slot key and `feed` an outbox slot key, kept as their bytes; an encrypted store's conversations
section is read into the root's slot and sealed inside the root (Q4(a)).

## Tests that left from shared files

These were in files that stay on `main` (their fixtures used `/workspace/commands`; `main` sets up
the same state through the engine's write path, deviation D11):

- `internal/access_durability_test.go`, whole (`TestAccessEncryptedFailureRecoveryKeepsStableCommandAndNotice`:
  command receipts and idempotent retry).
- `TestAccessLegacyAudienceMutationsRetired` in `internal/access_authority_test.go`.
- The `Workspace()` projection assertion, and the independent-conversation membership wraps, in
  `TestAccessWallClockExpiryDeniesReadsWritesWrapsAndStream` (`internal/access_expiry_test.go`).
- The per-member conversation key scope in `TestStorageEnvelopesGrantHistoryAndTampering`
  (`internal/storage_envelopes_test.go`).
- `TestAReplayIsNotAcknowledgedUntilTheCommandIsDurable` in `internal/persistence_replay_test.go`, and
  the receipt-retry assertion in `TestARecordAppendedButNotAcknowledgedIsKeptAcrossAKill`
  (`internal/persistence_test.go`).
- The workspace `create` notice and command-replay assertions in
  `TestApplicationHubSurvivesRestartAndFiltersRevocation` (`embedded/application_hub_test.go`).

## Files and lines

45 non-test Go files, 4018 lines; 20 test files and test data, 1734 lines. Tests leave with the code they test. `sha256` is of the file at the cut, in the format of `docs/activity-source-import.jsonl`.

### Source

| Path | Lines | sha256 |
|---|---:|---|
| `internal/api_assets_index.go` | 152 | `30d096203fce3af18d1cc8f991fa995bafac55db302366ebd8c674ac9a4736fb` |
| `internal/api_assets_index_budget.go` | 112 | `be7287e85c05ef3a170cbb5d35b1007284f74feaeb1a6aaec228cf67288e46e9` |
| `internal/api_assets_index_projection.go` | 119 | `acd7c29241a77021cf8282da66648a90f37f8012c0987a90b0bcf309c146e006` |
| `internal/api_feed.go` | 176 | `ec6aaf3a6d22bfc1d776d044eb4024f20984f690ab10253436ef7a7586097e06` |
| `internal/api_feed_durability.go` | 26 | `d079667695b34357dbabb602be0bb25645d4ecb689ae8ae272737e1f43e1e11c` |
| `internal/api_workspace.go` | 258 | `93acf6149ac772dff462dc35df1c81902eada27622f1b1031bcb4e77e76ccc99` |
| `internal/api_workspace_commands.go` | 156 | `471b0bf952c667dfb49f6192594b7a1380afd2ae0232ca41d0314222df2bccba` |
| `internal/api_workspace_commands_create.go` | 41 | `a09ef1738b11ba4e3e8ca4a32a1bf3f2a5fdd3ed456bf1df4e6b2773bef61b59` |
| `internal/api_workspace_commands_event_transition.go` | 13 | `603c0d4d5406aa4f933b14d6c14b6f8f075d988e53e763232c8a326c994be91e` |
| `internal/api_workspace_commands_initialize.go` | 17 | `6790fb09aa0d82bdf6a9863b0b0dccb1074bed719aedf8c95a51b258b77922e2` |
| `internal/api_workspace_commands_log.go` | 34 | `b74e07c281310e1377167b4f015a954a06ad92f5fa72675ad1a1e4af17d6d6e3` |
| `internal/api_workspace_commands_plan.go` | 37 | `61655b0b0203bb845361aa814b2d1ccdb036707f47dcb4ef8453f390051398f9` |
| `internal/api_workspace_commands_preferences.go` | 12 | `d83c55fc801f72a82a016208f02e8ff046934dca39687b15d1f2f616fd20b956` |
| `internal/api_workspace_commands_run.go` | 15 | `e4ba120d3d5e7d1ba55f05d61ea1d07ca97e607e9fa107f331b06786866691cc` |
| `internal/api_workspace_commands_run_definition.go` | 102 | `62042033c4b5405ac2537f2b07d97bf5e6cbde1fa59a54d214b44aad3dce9a51` |
| `internal/api_workspace_commands_subscribe.go` | 16 | `6fb916f0549767562aff40798414cc763989d959387ddbb381196a47469331e0` |
| `internal/api_workspace_commands_time.go` | 45 | `6869bbfbc1a4df2ede2b64f84a71e01e1e9d757b6d3f543ffe4e19b6b941ff57` |
| `internal/api_workspace_commands_timer_start.go` | 40 | `d9a6da10f10f4774587452bc2c5856fe7cb1d352d7c0689efb36e856b8e337f2` |
| `internal/api_workspace_commands_timer_stop.go` | 26 | `6c777138afc4178090aa479ddf7cce74556d109f2a2ccafb8fad739a4897190e` |
| `internal/api_workspace_commands_update.go` | 68 | `1519916cf8537def0e84bc2519fa62fba627383c59d43f88f0c30f18ebd04a0f` |
| `internal/application_alerts.go` | 92 | `8a866f47d386a2da2b4a007bbc966c7a5d4b40d9113b6330f2e4055f36726f6f` |
| `internal/application_conversation_create.go` | 154 | `127ae2d5a3772a0798c11c2f488102575cb7dc39e8dc2c04a66e9f01c50304dc` |
| `internal/application_conversation_membership.go` | 87 | `42a5e5688d6e123da262ebf43445eeee2a82e7e53052f7c5b601ec5da4c3de08` |
| `internal/application_conversation_preferences.go` | 90 | `e05c2e9f70aea22b529cc246b1ec60f90d31bf4c72f7a0ea70946082dbb0085e` |
| `internal/application_conversations.go` | 226 | `7ad1051260973080abc5947eb641eaebbc17cd97d40d23df76a0cbb335083468` |
| `internal/application_feed_preferences.go` | 138 | `e96a8c141f446b9e4f6074f7f7fb81b17528b0ffbe2a889193d678b9ed4e5865` |
| `internal/application_message_attachments.go` | 98 | `4ebbeee3b74d1dcedf2d01221a203d2db1d312b9606cd2e1a08a21ae1a7dc023` |
| `internal/application_message_contract.go` | 121 | `a60f8a3bf4c64d3421d075567d1027246e90eb5c42ba088ff67f24d27a3adeae` |
| `internal/application_message_mutations.go` | 163 | `e6f9a4cf06e751f8dc69c715fa93850311e0963e7d7f94b68d1ef91f57db596d` |
| `internal/application_message_operations.go` | 121 | `496e36a7ebc3e51db372d43112d9004690eddb67fb45a9fe2702bf95bcfa816e` |
| `internal/application_reminders.go` | 136 | `57f5820b109552176c88024f54516e9c5c5be2ff15cb67b5fb3fe6775c9b97f4` |
| `internal/ciphertext/envelope.go` | 179 | `58f6842cbb98b24b372c57c7e5c6d6ab65737de276fb6ca76fbf3eaf852f7321` |
| `internal/core/conversation.go` | 91 | `d621614198d53e9b729404048bc143438303fa233ffeacd6c8c05ba52e0c3ac2` |
| `internal/core/feed_preferences.go` | 16 | `b50e45634c8a7a1c1e8dda3185cd12a1925034d06fbb36bb751d537801fb8bd4` |
| `internal/core/feed_state.go` | 45 | `691f3fa79cd55e81592b9cf7a4a0a42b9e06c8af00155cb0f56708293a06c6bc` |
| `internal/work_categories.go` | 81 | `74e1fb9dba9b75a2f00519d98b0803691953d0a9ef59e4db51f6a79b0afc5543` |
| `internal/work_category_patch.go` | 76 | `9da0b9124140c17967f8235527358fe8b6067936097c9dc02971a72baac6c1cd` |
| `internal/work_defaults.go` | 75 | `41ef5b934c5dcdad776bce2ed404b8c593190308da8322e182d3f2dd34af61ef` |
| `internal/work_details.go` | 104 | `250329eb4a7d6bb55a3799dc36d3eeea2d3a6db6bd01874bf6b8ec8848bbd6d7` |
| `internal/work_editor_details.go` | 36 | `72f7d9020e91e2bdd9030aadbdca7e9accdf208c1dc585e897efd055408a86fa` |
| `internal/work_events.go` | 49 | `b0b29da3437ee440c4b529b9ca71a54812ad5a4386ce271e61faf7dfd464120b` |
| `internal/work_examples.go` | 131 | `e0245db7f2987b438d2c7854af3535083e8f4c258254160e0e718c594e4e01db` |
| `internal/work_legacy_temporal.go` | 81 | `431f240a9502a858dead14596bc2356534a28735bc61957bab3f275f7c3aa442` |
| `internal/work_metadata_value.go` | 17 | `02358216825915b0b8ce51b68a63ac1e02e363e2705c8feb6b93bed28e2fc11f` |
| `internal/work_temporal.go` | 146 | `e124c880c77cb55ee80247f647fd20b34aee1f1f271e0452561562f7b32a2091` |

### Tests and test data

| Path | Lines | sha256 |
|---|---:|---|
| `internal/api_assets_index_test.go` | 200 | `5f0b22f3de1bcd46aa205f12844d5dd37318476566ea1ccd7080b1030ca68502` |
| `internal/api_feed_test.go` | 56 | `e16d7115745f3480245a774282f573a6da2aaa3214f68ecd1fde07ced32dedf9` |
| `internal/api_workspace_test.go` | 157 | `3f07f52c988567977b0fe408b7a7c4b1799f235c2329448260f524f7d6a7e2bf` |
| `internal/application_alerts_test.go` | 84 | `07e586643cdc36b6ab2f38277ac948d3df7b8230e4da647593f546d25b3b6a5d` |
| `internal/application_feed_preferences_test.go` | 78 | `8168badc2ab7f63cc3349e28a95a62c56a8858a8451bafcd5b381cae7ff8532a` |
| `internal/application_message_attachments_test.go` | 67 | `b53eb173b5589e1de564f1796594c50cde7c6b25997efb034080aa589bf269f9` |
| `internal/application_message_mutations_test.go` | 90 | `4bc125215ee156cfee138fe607b7cdc35c1fd2e9c9a77399ba752fe826b2669d` |
| `internal/application_reminders_test.go` | 174 | `8174c27f7b6850fb5adfc99b890e981800ecd63afd986cb675ee832c99cf9267` |
| `internal/ciphertext/envelope_test.go` | 65 | `e1c2a821ccebdeb7ed64f014da2bb0b56eb298abe771a398da3d7eeeac1d10f2` |
| `internal/conversation_boundaries_test.go` | 81 | `c3bf06605044dd89a0776c96fbe8988e215c2812b0b9191307e2c014449e4e7e` |
| `internal/conversation_history_projection_test.go` | 32 | `2944a7a938cfb407d701a9eb120e237e1708744934eae56fa7cf155ed990337f` |
| `internal/conversation_history_test.go` | 149 | `bc500e9777ff87410e6937f2ac1501247a1c1e856b64bab269e9af78b500ee8e` |
| `internal/conversation_preferences_private_test.go` | 39 | `6d23f4773d3ea736ca1d101d1c0693474bc4f74129dac573e31a2e94ec965504` |
| `internal/conversation_receipts_test.go` | 91 | `398f02967e959f34e4e8e9ee7d7970a00a3369459f775995f9a8975d634e2fd3` |
| `internal/conversations_test.go` | 52 | `5aee30e36dd073d85b854b8c0b875042364cee4f1f8118e94574b9fca49cf8ee` |
| `internal/personal_notifications_test.go` | 34 | `1b5377547c60a4a2a1a903738a6c223ada28c20324e9d7ab0a19377f5551e3c2` |
| `internal/work_account_details_test.go` | 91 | `3ea3a081f6da7bf12a589f5afc73fd384c2d6dff197fb9ddb0fa7a87789672f5` |
| `internal/work_codec_diagnostic_test.go` | 29 | `745d71def8c6ef48561334ce310f92cdb9cdb8faf4890d6ced98cbe568759374` |
| `internal/work_integration_test.go` | 142 | `2b4c697bbec832fa81c608deda4a916256e00dd94980170f602358c77d61e1cb` |
| `internal/work_privacy_test.go` | 23 | `a645b5390c225a4f006b5118f1403e08afa6c78b91a1496d392724183ceb1243` |

