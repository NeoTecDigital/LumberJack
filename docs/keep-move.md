<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Keep / move classification

Status: design for owner review, against `main` at `d18f3e7`. No source has changed. The API these
seams become is in [extension-api.md](extension-api.md).

**The rule.** Code is generic if a store needs it, or if Corresponder or Intercessor need it from a
store. Generic code stays on `main`. Product code leaves for a `product/<name>` branch and is not
ported. Where a file mixes the two, it is KEEP-NEUTRALISE: it stays, and its product literals,
environment names, labels and hardwired calls are replaced by a seam.

Line counts are `wc -l` of non-test `.go` files tracked at `d18f3e7`. Tests leave with the code they
test.

## 1. Totals

| Scope | KEEP | KEEP-NEUTRALISE | MOVE | Total |
|---|---:|---:|---:|---:|
| `internal/` + `embedded/` + `ffi/` | 12,620 | 6,823 | **23,520 (54.7%)** | 42,963 |
| `products/` | 0 | 0 | 2,858 | 2,858 |
| `cmd/`, `types/`, `app.go` | 1,922 | 203 | 0 | 2,125 |
| **All** | 14,542 | 7,026 | **26,378** | 47,946 |

The scoping pass estimated about 24k of 43k (57%). This pass keeps `api_views.go`,
`api_stream.go`, `access*` and the session registry. The scoping estimate may have counted those as
product; that was not checked.

Inside the 7,026 KEEP-NEUTRALISE lines, about 700 more lines are product branches or literals that
leave or get rewritten (estimated per file in §4). So `main` ends at roughly 20.9k lines, before the
seam code P3b adds (about 3.8k, extension-api.md §8).

| Destination | Lines |
|---|---:|
| `main` | 21,568 (before the ≈700 extracted from KEEP-NEUTRALISE files) |
| `product/manifest-domain` | 12,584 (includes the 3,111-line owned-scope base) |
| `product/momentum-personal` | 5,294 |
| `product/momentum-workspace` | 4,018 |
| `product/activity-runtime` | 2,570 |
| `product/momentum-auth` | 1,912 |

### How the branches are cut

All five `product/*` branches are cut from **one** commit: the P3b-0 commit, which is `main` with
the compatibility fixtures added (extension-api.md §8). Each branch adds only `PRODUCT-INVENTORY.md`
on top of that commit. The inventory lists:

- the files the product owns, with sha256, in the format of `docs/activity-source-import.jsonl`;
- the shared files it depends on;
- its entry points (FFI exports, routes, `Configure*` calls);
- the persisted keys it owns (§5);
- the seams it would rebuild on.

Because every branch holds the whole tree at the cut, the shared owned-scope base (`staged_*`,
`activation_source_*`) exists on every branch. The inventory says who owns it: `manifest-domain`
owns it, and `momentum-personal` lists it as a dependency.

**No `product/mindfull-app` branch.** No code is specific to Mindfull's application. The one
Mindfull literal is `CanvasMetadataKey = "mindfull.canvas"`, which nothing outside tests reads
(`api_canvas.go:23`). The workspace files have `Copyright 2026 Mindfull` headers, but they implement
Momentum's workspace. Mindfull's Python host calls `ic_lj_domain_*`, so it consumes the
`manifest-domain` archive. See open question Q9.

## 2. The six calls

### (a) Application in-process route-call transport → KEEP

Evidence:

- `ApplicationCall` (`application.go:143-179`) and `makeApplicationRequest`/`applicationOutput`
  (`activation_application.go`) are how Intercessor's `call`/`hub` ops reach the engine
  (`crates/intercessor/src/service/dispatch.rs:78-97`).
- Corresponder's `HubRuntime` uses the same path (`nativecall`, `hubcall`).
- The transport itself has no product literal.

What is product: the `dispatchApplication` switch (`activation_application.go:30-60`) hardwires the
application-only routes:

- `/session/mfa` belongs to auth.
- `/session/admit` and `/activation/probe` belong to Activity.
- `/feed`, `/feed/preferences`, `/assets/index` and the message operations belong to the workspace.

The application-only routes that stay are `/session`, `/session/activity`, `/principal`,
`/notifications` and `/changes`.

The backpressure gate (`application.go:165-171`) is generic: it 503s writes while the outbox holds
4096 pending changes. Its exemption list names product routes, so the exemption becomes a route flag
(extension-api.md §4.3).

Also product: `invalidActivationHeaders`/`isActivationRequest`, which are Activity's and become the
request-authenticator seam.

### (b) Hub/outbox (`Correspondence`) → KEEP with a neutral name

Evidence:

- The trusted `ApplicationHub` ops `pending`, `status`, `deliver`, `outbound`, `outbound_ack` and
  `outbound_failed` (`application_hub.go:73-300`) are exactly the ops HubRuntime calls.
- `/notifications` and `/changes` are the routes it reads.
- Change capture (`captureCorrespondence`/`recordCompatibilityChanges`, `application_changes.go`)
  runs inside the one write path (`forest_lock.go:226-247`).

Recommendation:

- Rename the Go types: `CorrespondenceState` → `core.Outbox`, `CorrespondenceChange` →
  `core.OutboxChange`.
- Keep the JSON key `correspondence`, so persisted state does not change.

Product couplings to remove:

1. `enqueueCorrespondence(actor, WorkCommand, path)` (`application_hub.go:16`) takes the
   workspace's command type and its `share` / `assigned_to` / `kind == "conversation"` rules. It
   becomes `Tx.Enqueue(core.OutboxChange)`, with recipients and a `Direct` flag decided by the
   caller.
2. The `/notifications` read filter (`application_hub.go:358`) re-derives entitlement from
   `node.Kind != "conversation"` and `Metadata["assigned_to"]`. The recorded `Direct` flag replaces
   it. Records written before the flag existed keep today's rule for `share`. For the other two
   cases, an extension can vouch through an optional entitlement hook.
3. `notificationRevision` (`application_changes.go:21`) hashes `workMetadata(node)` minus
   `"preferences"`. It switches to the generic node projection, minus metadata keys an extension
   declares as presentation-only.
4. `outbound_ack` and `outbound_failed` write delivery marks onto `MFAChallenges`. These become an
   `OutboxListener` the second-factor extension implements. The outbound queue itself stays generic.
5. `CorrespondenceState.Feed` is workspace state. It becomes an outbox slot key (`feed`).

Finding: in a build with only `main`, almost nothing feeds the outbox. Recipients come from
`Subscriptions`, which are written only by the workspace `subscribe` command and reminders. The only
generic enqueue is the `/access` share notice (`access.go:254`). Corresponder's drain keeps working,
but it will be idle until an extension writes subscriptions. See Q5.

### (c) Login / JWT / users / permissions → KEEP generic; second factor becomes pluggable

KEEP:

- `/login`, `/refresh`, `/users*`, `/settings*`;
- the JWT pair and the server-side session registry: `ms_` bearers, `ApplicationSessions`,
  `application_session.go` minus its MFA branch, `api_auth_tokens.go`, `api_auth_legacy.go`;
- credential epochs (`application_credential_epoch.go`);
- the lockout counter (`api_auth_lockout.go`);
- `/principal`'s generic projection (`handleApplicationPrincipal`);
- `/session` (the browser password exchange).

Evidence that these are needed:

- `generateTokenPair` mints a registry session (`api_auth_tokens.go:34`).
- HubRuntime resolves every non-public target through `GET /principal`
  (`HubRuntime.jl:271`).
- Intercessor's tests log in through `/login` (`tests/service.rs:96-105`).

MOVE → `product/momentum-auth`:

- `account_security*` (TOTP, WebAuthn, QR, email, recovery);
- `application_mfa*` (SMS codes and their delivery and resend);
- `api_user_mfa.go`;
- `core.AccountSecurity` and `core.MFAChallenge`;
- every `MOMENTUM_*` variable (`account_security.go:18`, `account_security_passkey.go:40-41`,
  `account_security_handlers.go:165`);
- the `momentum:login:` QR literal.

The call points are `api_auth.go:347` (the middleware), `api_auth.go:142` (`beginAccountLogin`),
`api_auth_lockout.go:106-118` (the phone gate and factor check) and the MFA branch of
`application_session.go`. They become the `SecondFactor` seam (extension-api.md §4.4).

**This changes the default security posture.** Today `requireAccountMFA()` returns true unless
`MOMENTUM_REQUIRE_MFA=false`, so a bare engine forces TOTP enrolment on every login. That is why
Intercessor's test sets `MOMENTUM_REQUIRE_MFA=false` (`tests/service.rs:74`). With the second factor
moved out, a `main`-only build logs in with a password.

Two fail-closed rules stop this from being a silent downgrade:

- An account with `User.MFAEnabled` set is refused password-only login when no `SecondFactor` is
  registered.
- So is any account whose id appears under the root's preserved `account_security` key.

See Q1.

`/session/admit`, the Activity verifier and the signed admission (`admission/`) are Activity's
protocol. The verifier hardcodes products `momentum|manifest` (`admission/verifier.go:141`), the
issuer is `activity-personal` and the audience is `momentum-personal`. They MOVE →
`product/activity-runtime` and become a `RequestAuthenticator` there.

### (d) Staged/owned scopes and the source fence → split: keep the guard, move the engine

**Source fence (`activation_source_fence.go`, `_legacy.go`, `_session.go`): MOVE.**

- On a plain store, `beginOrdinaryWrite` takes the legacy branch (`activation_source_legacy.go:27-35`),
  which only increments a counter.
- The fence becomes "required" only when `ConfigureDomain` runs (`activation_domain_config.go:21`)
  or a staged descriptor carries a product binding (`activation_source_legacy.go:21-25`).
- What it adds on top is product protocol:
  - whole-forest revision evidence;
  - unknown-outcome poisoning with witnessed recovery (`inspectSourcePair`, `recoverPersonalWitness`);
  - session fencing keyed by enrollment;
  - `enrollmentSourceCommand`.
- The mechanism it needs from the engine is product-free: a permit taken before the forest lock and
  settled with the durable outcome. That becomes the `PermitProvider` seam.

**Owned-scope command engine (`staged_*`, 2,193 lines): MOVE.**

- Descriptors, bounds, configure/reconcile, CAS, pending receipts, the snapshot overlay
  (`stagedOverlayLocked`), durability pairs (`stagedPairsFromBytes`, `state_writer.go`
  `commitPaired`/`pairedStamp`), and the personal builders that live in `staged_snapshot.go:247-427`.
- No generic route creates a scope. `configureStagedScope` is called only from `ConfigureDomain` and
  personal provisioning.
- The literals are `"momentum"` at `staged_snapshot.go:255` and `staged_candidate.go:337`.

**What stays, as built-ins with generic tests: the protection, not the engine.** A store written
today contains nodes marked `CommandReceipts["lumberjack.staged.scope/v1"]`. If `main` stopped
protecting them, two things would go wrong:

- They would become readable through generic routes. Today `isStagedNode` hides them at
  `api_helpers.go:35,51`, `api_queue.go:83`, `query_walk.go:59,93` and `forest_projection.go:65`.
- They could be clobbered or orphaned by ordinary writes, such as renaming or deleting an ancestor,
  or unlinking. Today `captureStagedProtectionLocked`/`verifyStagedProtectionLocked` refuse such a
  write and restore the subtree.

So `main` keeps two built-ins:

1. An **owned-marker visibility rule**: a node carrying a registered ownership marker is hidden from
   every generic read.
2. An **owned-subtree guard**: an ordinary write that changes an owned subtree or its ancestor links
   is refused with 403, and the subtree is restored from a clone.

The guard's logic is the product-free part of `staged_guard.go` (about 250 lines). It is
re-expressed over markers instead of `s.stagedScopes`. The legacy marker key is already
LumberJack-named, so it goes in the compatibility table as a marker owned by `manifest-domain` and
`momentum-personal`.

The alternative (d1) keeps the whole owned-scope engine in `main` as an engine feature. Rejected
because no generic path uses it, and it would keep 2.2k lines and a product protocol (pairs,
overlay) in the writer. Q6.

### (e) `AccessGrants` / `access*` → KEEP-NEUTRALISE, as the built-in grant source

Evidence that the mechanism is generic:

- It is scoped, expiring and revision-reviewed sharing over the DAG.
- Policies live on the root; per-node grants are materialised (`access.go:99`); `CheckPermission`
  reads them (`core/node_fn.go:238`).
- Storage encryption's per-node audience depends on them too (`secure_storage.go:163`).
- `/access`, `/access/preview` and `/access/apply` have no product literal.

The two product couplings:

- `stopRevokedAccessTimer` calls the workspace's `workActive` (`access.go:271-287`). It is
  re-expressed over core time entries (`core.TimeEntryStart`/`TimeEntryStop`, which are generic).
- The share notice builds a `WorkCommand{Command: "share"}` (`access.go:254`). It becomes
  `Tx.Enqueue`.

The materialisation in `refreshAccessGrantsLocked` becomes the `GrantSource` seam. Built-in access
policies are the first source, and an extension's ACL can be another. `CheckPermission` stays a pure
method on the node.

### (f) Storage encryption → KEEP-NEUTRALISE

Evidence: KMS and local wrapping, per-snapshot master keys, per-node resource keys and the sealed
object log are what an encrypted store needs. Nothing in them is product logic.

What changes:

| Item | Today | After |
|---|---|---|
| State AAD | `momentum/storage/v3/<id>/<purpose>` (`secure_storage.go:81`) | label from a versioned table (extension-api.md §7.5): legacy accepted on read, neutral `lumberjack/storage/v5/...` on write once enabled |
| Object AAD | `momentum/objects/v1/<id>/<purpose>` (`object_store_seal.go:47`) | key-file version 1 or 2, record flag 1 or 2 select the label |
| Env | `CORRESPONDER_STORAGE_{MODE,KMS_KEY,LOCAL_KEY_FILE,REWRAP_KEYS,MIGRATE_LEGACY}` (`storage_keys.go:81-91`, `secure_storage.go:366`, `file.go:89`, `persistence.go:143`) | explicit `Config.Storage`; `LUMBERJACK_STORAGE_*` read by `cmd`/`ffi`; the old names accepted as deprecated aliases for one release (Q10) |
| `conversations` section | written per conversation and message with per-member key wraps (`secure_storage.go:189-232`) | read for compatibility into the root's `conversations` slot; on write, sealed inside the backend-only root (Q4) |
| Number handling | `json.Unmarshal` into `nodeRecord` on both encode (`:148`) and decode (`:295`) | the number-exact codec (see finding F1) |

**Finding F1 (suspected defect, not verified by a test).** Owned-scope nodes rely on exact numbers.
`restoreStagedNumbers` decodes them with `UseNumber` (`state_codec.go:239`). The encrypted path
decodes each node with plain `json.Unmarshal` before that runs (`secure_storage.go:148,168,295,333`).
So `1.50` becomes `1.5`, and integers above 2^53 are rounded, every time an encrypted store is
written. The scratch check below shows the plain-decode behaviour; the encrypted call chain was
traced by reading the code. The P3b-1 compat step fixes it as a side effect.

```
encoding/json, plain decode → re-encode:  {"a":2,"b":1.50}  →  {"a":2,"b":1.5}
```

## 3. MOVE

| Branch | Group | Files | Lines |
|---|---|---:|---:|
| `product/manifest-domain` | `internal/activation_domain_*` (36 files: `_acl`, `_acl_reference`, `_adapter`, `_binding`, `_config`, `_gate`, `_json`, `_owned_root`, `_provision*`, `_registry`, `_resource_acl`, `_store_*`, `_types`, `_workload*`, …) | 36 | 4,188 |
| `product/manifest-domain` | `internal/activation_enrollment_*` | 13 | 1,744 |
| `product/manifest-domain` | `internal/domain_snapshot_cache.go` | 1 | 80 |
| `product/manifest-domain` | **owned-scope base (shared)**: `internal/staged_*` (`candidate` 398, `clone_structured` 63, `guard` 254, `receipt` 189, `reconcile` 404, `reopen` 26, `scope` 263, `snapshot` 427, `types` 169) | 9 | 2,193 |
| `product/manifest-domain` | **owned-scope base (shared)**: `internal/activation_source_fence.go` 416, `_legacy.go` 71, `_session.go` 431 | 3 | 918 |
| `product/manifest-domain` | `products/manifest/` | 5 | 803 |
| `product/manifest-domain` | `products/pngstore/` | 18 | 1,455 |
| `product/manifest-domain` | `products/momentum/` (Momentum's `DomainProduct` adapter, registered by `embedded/manifest.go:35`) | 8 | 600 |
| `product/manifest-domain` | `embedded/domain.go`, `domain_completion_ack.go`, `domain_enrollment.go`, `domain_lifetime.go`, `domain_owned_root.go`, `manifest.go` | 6 | 425 |
| `product/manifest-domain` | `ffi/domain.go`, `domain_completion_ack.go`, `domain_enrollment.go`, `domain_owned_root.go` | 4 | 178 |
| `product/momentum-personal` | `internal/activation_{personal,canonical,identity,native}_*` | 14 | 4,584 |
| `product/momentum-personal` | `internal/activation_owned_context.go` | 1 | 220 |
| `product/momentum-personal` | `internal/core/personal_binding.go` | 1 | 133 |
| `product/momentum-personal` | `embedded/personal_source.go`, `personal_source_lifetime.go` | 2 | 243 |
| `product/momentum-personal` | `ffi/personal_source.go` | 1 | 114 |
| `product/momentum-workspace` | `internal/work_*` | 10 | 796 |
| `product/momentum-workspace` | `internal/api_workspace*` | 15 | 880 |
| `product/momentum-workspace` | `api_feed.go`, `api_feed_durability.go`, `application_feed_preferences.go`, `application_reminders.go`, `application_alerts.go` | 5 | 568 |
| `product/momentum-workspace` | `internal/application_{conversation,message}*` | 8 | 1,060 |
| `product/momentum-workspace` | `internal/api_assets_index*` (indexes conversation attachments) | 3 | 383 |
| `product/momentum-workspace` | `internal/core/{conversation,feed_state,feed_preferences}.go` | 3 | 152 |
| `product/momentum-workspace` | `internal/ciphertext/` (`Product` must be `momentum\|manifest`, `envelope.go:48`; also imported by `businessruntime`) | 1 | 179 |
| `product/momentum-auth` | `internal/account_security*` | 5 | 960 |
| `product/momentum-auth` | `internal/application_mfa*` | 3 | 752 |
| `product/momentum-auth` | `internal/api_user_mfa.go` | 1 | 127 |
| `product/momentum-auth` | `internal/core/{account_security,mfa_challenge}.go` | 2 | 73 |
| `product/activity-runtime` | `internal/activation_{config,auth,protocol,actor,json}.go` (the Activity verifier) | 5 | 513 |
| `product/activity-runtime` | `internal/application_session_admit.go`, `application_business_scope.go` | 2 | 347 |
| `product/activity-runtime` | `internal/admission/` | 2 | 237 |
| `product/activity-runtime` | `internal/{businessruntime,replication,peertransport}/`: imported by nothing outside themselves; Raft with `Product == momentum\|manifest` (`replication/types.go:63`) | 12 | 1,415 |
| `product/activity-runtime` | `embedded/activation.go`, `session_admission.go` | 2 | 58 |

The 169 Activity-line files listed in `docs/activity-source-import.jsonl` agree with this split.
That list also includes the shared engine files (`forest_lock.go`, `state_codec.go`, `types.go`, …),
because the import reconciled them. Those files are KEEP-NEUTRALISE here.

## 4. KEEP-NEUTRALISE (stays on `main`; what changes)

| File | Lines | ≈ leaves | What changes |
|---|---:|---:|---|
| `forest_lock.go` | 289 | 40 | `changeForest`/`beginForestWrite`/`runChangeLocked` (`:131-247`) call `PermitProvider` and `WriteHook`s instead of `sourceFence()` and staged protection. The built-in owned-subtree guard, grant refresh and outbox capture stay in the bracket |
| `forest_projection.go` | 219 | 2 | `isStagedNode` → `s.hiddenLocked`; the projector carries the filter |
| `query_walk.go` | 150 | 4 | same at `:59,:93`; `childrenByName` takes the filter |
| `api_helpers.go` | 184 | 4 | same at `:35,:51` |
| `api_queue.go` | 191 | 2 | same at `:83` (cache path) |
| `types.go` | 127 | 20 | product fields on `Server` (`nativeControl`, `sourceCoordinator`, `personalSource`, `activation`, `sessionAdmission`, `domainSnapshots`, `domainConfiguring`, `domain`, `stagedScopes`) → one `extensions` field; drop the `admission` import |
| `state_codec.go` | 306 | 25 | STATE-3 banner: `stateHoldsACLReferences` stops importing `domainACLReferenceRevision`; the level is sticky plus a compat mark. `restoreStagedNumbers` (`:239`) → number-exact decode for every node. `nodeRecord` gets the slot codec |
| `state_writer.go` | 219 | 45 | drop `pairs`, `durablePairs`, `commitPaired`, `pairedStamp`, `equalStagedPairs` in the skip; `commit` returns a `Commit` stamp |
| `file.go` | 474 | 10 | `CORRESPONDER_STORAGE_MIGRATE_LEGACY` → config. `encodeStateLocked` must stop delegating to `encodeSnapshotLocked`, which lives in a MOVE file (`staged_snapshot.go:82`); the overlay-free half is re-homed here |
| `persistence.go` | 328 | 10 | `CORRESPONDER_STORAGE_MODE` → config; `refuseWholeStateWriterUnderTier` → `Spec.Persistence = SnapshotOnly` |
| `api.go` | 526 | 35 | product routes leave: `/mfa/*` (3), `/auth/*` (4), `/workspace`, `/workspace/commands`, `/conversations*` (6), `/account/*` (5), `/users/mfa`. Extension routes are registered before the `/nodes/{path:.*}` and `/stream` catch-alls. `/access*` stays |
| `activation_application.go` | 76 | 30 | the `dispatchApplication` switch → an application-transport route table; rename to `application_dispatch.go` |
| `application.go` | 254 | 25 | activation header checks → `RequestAuthenticator`; backpressure exemptions → route flag; `CORRESPONDER_ADMIN_RECONCILE` → an explicit `reconcile` config field, with the env name as an alias |
| `api_auth.go` | 391 | 40 | `phone_last4` → `Login.Extras`; `beginAccountLogin` → `SecondFactor.AfterPassword`; the middleware's activation branch → `RequestAuthenticator` chain |
| `api_auth_legacy.go` | 63 | 0 | this is the generic bearer path; rename to `api_auth_bearer.go`. Keep the `ms_` prefix (Q12) |
| `api_auth_lockout.go` | 195 | 25 | phone-last4 gate, `securityMethods`, `requireAccountMFA` → `SecondFactor`; built-in fail-closed rule |
| `application_session.go` | 303 | 70 | `handleApplicationSessionMFA` and the browser MFA branch → `SecondFactor` routes; registry, mint and renew stay |
| `application_hub.go` | 372 | 90 | see call (b), items 1, 2 and 4; rename the Go types |
| `application_changes.go` | 74 | 8 | see call (b), item 3 |
| `access.go`, `access_link.go`, `access_preview.go` | 603 | 25 | see call (e) |
| `secure_storage.go`, `storage_keys.go`, `object_store_seal.go` | 703 | 90 | see call (f) |
| `api_canvas.go` | 255 | 3 | drop `CanvasMetadataKey = "mindfull.canvas"`. The routes are generic metadata merge and link/unlink; metadata already stored under that key is untouched |
| `core/core_types.go` | 214 | 30 | five product fields → slot (§5); add slot storage and the record codec hooks |
| `core/correspondence.go` | 50 | 2 | `Feed` → outbox slot; rename types (JSON keys unchanged) |
| `embedded/runtime.go` | 209 | 30 | `domainLifetime`/`sourceLifetime` (`:33-35`, `:155-180`) → generic extension-instance lifecycle |
| `ffi/activation.go` | 48 | 30 | the `activation`/`admission` parts of `application_configure` → dispatched by name to `Configurable` extensions; an unknown non-empty part → `LJ_INVALID` |
| `cmd/serve.go` | 203 | 2 | `--admin-org "Momentum"` and `--admin-email admin@momentum.local` defaults → neutral |
| `ffi/lumberjack.h` (not Go) | 231 | 60 | remove the 14 product declarations; they move to per-product headers |

## 5. `core.Node` and the persisted product fields

Today 11 fields sit on `core.Node` (`core/core_types.go:116-154`). Six of them are generic and stay
as typed fields. Five become slot keys, preserved byte-for-byte when their owner is absent.

| JSON key | Level | Decision | Owner | If the owner is not registered |
|---|---|---|---|---|
| `command_receipts` | node | KEEP typed: an opaque receipt bag that extensions namespace; holds ownership markers | – | – |
| `correspondence` | root | KEEP typed as `core.Outbox` | – | – |
| `application_sessions` | root | KEEP (session registry) | – | – |
| `subscriptions` | root | KEEP (outbox recipients) | – | – |
| `access_policies`, `access_grants` | root, node | KEEP (built-in grant source) | – | – |
| `personal_bindings` | root | SLOT | momentum-personal | preserved; never projected (already true) |
| `conversations` | root | SLOT | momentum-workspace | preserved; never projected |
| `account_security` | root | SLOT | momentum-auth | preserved; **login refused** for every user id present |
| `mfa_challenges` | root | SLOT | momentum-auth | preserved; inert |
| `admitted_commands` | root | SLOT | activity-runtime | preserved; inert (no admissions are accepted) |
| `correspondence.feed` | outbox | SLOT | momentum-workspace | preserved |
| `command_receipts["lumberjack.staged.scope/v1"]` | node marker | ownership marker | manifest-domain, momentum-personal | **node hidden and subtree guarded** |
| `users[].mfa_enabled` | user field, KEEP | – | – | **login refused** without a `SecondFactor` |

`User` keeps all its fields (`Phone`, `MFAEnabled`, `FailedLogins`, `LockedUntil`,
`CredentialEpoch`). That avoids a third slot level, and lockout and epochs are generic.

## 6. FFI exports (33)

| Exports | Count | Decision |
|---|---:|---|
| `abi_version`, `echo`, `open`, `adopt`, `close`, `node_create`, `event_plan`, `event_start`, `event_append`, `event_end`, `event_entries`, `query`, `aggregate`, `forest`, `stream_poll` | 15 | KEEP |
| `events_publish` | 1 | KEEP |
| `application_call`, `application_free` | 2 | KEEP (the hub envelope `{"hub": …}` is generic) |
| `application_configure` | 1 | KEEP-NEUTRALISE (`activation`/`admission` parts → extension config parts) |
| `domain_configure`, `_resolve`, `_call`, `_control`, `_enroll`, `_provision_root`, `_ack_completion`, `_free` | 8 | MOVE → `manifest-domain` archive |
| `personal_source_configure`, `_call`, `_control`, `_free` | 4 | MOVE → `momentum-personal` archive |
| `native_control_configure`, `native_source_verify_seal` | 2 | MOVE → `momentum-personal` archive |
| `ic_lj__panic_for_test` | (tag) | KEEP; test-only, `lj_panic_test` |

The generic archive goes from 33 exports to 19. Corresponder's three groups match this split
exactly: `EXPORTS` (16) + `SERVICE_EXPORTS` (3) stay, and `HOST_EXPORTS` (14) leave
(`Abi.jl:71-90`).

## 7. Intercessor classification

Intercessor (`2ac7291`) is generic apart from four product-specific inputs:

| Item | Where | Product-specific? | After the move |
|---|---|---|---|
| `"products"` in the archive watch set | `crates/intercessor/build.rs:95`, added by `9a0a480`/`46cc1f2` ("track product build inputs") | yes; the only build input | drop it. Cargo reruns the build script on every build when a watched path is missing |
| `.env("MOMENTUM_REQUIRE_MFA", "false")` | `tests/service.rs:74` | yes; works around the default MFA policy | dead once the second factor is out; drop it |
| `GET /workspace` as the authenticated probe, `!contains_key(.., "canonical_id")` | `tests/service.rs:65-92,109-117` | yes; workspace route and personal-source field | 404 on a generic build; probe `GET /principal` (or `/forest`) instead |
| `/workspace` example and "former `/workspace` enrichment" note | `docs/native-service.md:48,94` | yes | replace with `/principal` |

Checked and generic:

- `745c40c` "lumberjack with the Momentum product" is a submodule pin bump only.
- `src/lumberjack/{mod,sys,status,application}.rs` only call base and application exports.
- `service/dispatch.rs` passes `request["auth"]` verbatim to `application_configure`. So an
  `admission`/`activation` part reaches the engine, and a generic build refuses it rather than
  ignoring it.
- `spec/`, `addons/`, `tools/`, `Makefile`: no product names.
- `build_archive` builds `./ffi`, which stays the generic archive.

## 8. Consumer calls after the move (generic archive, no extensions)

### Intercessor

| Call | After | Needs |
|---|---|---|
| `ic_lj_abi_version`, `open`, `adopt`, `close`, `node_create`, `event_plan/start/append/end`, `event_entries`, `query`, `aggregate`, `forest`, `stream_poll` | unchanged | nothing |
| `ic_lj_application_configure` with `{username,password,secret}` | unchanged | nothing |
| the same with `admission` or `activation` | `LJ_INVALID` (fail closed) | link the archive that carries `activity-runtime`, or stop sending the part |
| `ic_lj_application_call` → `/login`, `/refresh`, `/health`, `/session*`, `/principal`, `/changes`, `/notifications`, data routes, `/access*` | unchanged | nothing |
| `ic_lj_application_call` → hub `pending`, `status`, `deliver`, `outbound`, `outbound_ack`, `outbound_failed` | unchanged; `outbound` is always `[]` without `momentum-auth` | nothing |
| `ic_lj_application_free` | unchanged | nothing |
| `tests/service.rs` | `isolated_positive_authentication_reaches_workspace` fails (404) | probe `/principal`; drop the env |
| `build.rs` | builds; reruns every time | drop `"products"` |

### Corresponder

| Call | After | Needs |
|---|---|---|
| `Abi.jl` `CALLED` (11): `abi_version`, `open`, `close`, `node_create`, `event_start/append/end`, `event_entries`, `query`, `echo`, `events_publish` | unchanged | nothing |
| `EXPORTS` (16), `SERVICE_EXPORTS` (3) present in the library | unchanged | nothing |
| `HOST_EXPORTS` (14) | absent from header and library | drop `HOST_EXPORTS` from `Abi.jl:85-90`; `test/e2e/abi.jl:45-47,63` expects 19 declared and 16+3 lengths |
| `make lumberjack` (`go build ./ffi -buildmode=c-shared`) | unchanged path, smaller library | nothing |
| HubRuntime `/login`, `/refresh`, `/health`, POST `/session`, GET `/principal` (reads `id`), POST `/changes` | unchanged | nothing |
| HubRuntime `/mfa/verify`, `/mfa/start`, `/mfa/delivery`, `/session/mfa`, `/auth/factor`, `/auth/webauthn/finish`, `/auth/qr`, `/auth/qr/poll` | 404 | only with `momentum-auth`; `PUBLIC_TARGETS`/`PUBLIC_POST_TARGETS` (`HubRuntime.jl:254-259`) become deployment configuration, not code |
| HubRuntime `/session/admit`, `open_request(admission=…)` | 404 / `application_configure` refused | only with `activity-runtime` |
| HubRuntime `/workspace/commands` (special-cased at `HubRuntime.jl:278-287`) | 404 | only with `momentum-workspace`; the special case is inert otherwise |
| hub `pending`, `status`, `deliver`, `outbound`, `outbound_ack`, `outbound_failed` (`drain!`, outbound forwarder) | unchanged; outbox fed only by extensions and `/access` share notices (call (b) finding) | nothing to compile; Q5 for behaviour |
| `service/test/native.jl:171` `GET /workspace` (stranger) expects 401 | 404 | use `GET /forest` |
| `service/test/coordinator.jl` `/workspace/items…` | unaffected: it routes through a scripted runtime, not the engine | nothing |

## 9. Open questions for the owner

The full list, with recommendations, is in extension-api.md §10. These are the ones that settle
calls in this document:

- **Q1** Second factor no longer the default (recommend: accept, with the fail-closed rules).
- **Q4** Encrypted `conversations` section (recommend: fold into the root).
- **Q5** Idle outbox in a `main`-only build (recommend: accept).
- **Q6** Keep the guard, move the owned-scope engine (recommend: d2 as above).
- **Q9** No `mindfull-app` branch (recommend: none).
- **Q10** Env aliases for one release (recommend: yes).
