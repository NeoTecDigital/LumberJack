<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Workload write grant: the host's contract

The connection-bound R5 contract is specified in section 9. Sections 1–8 and their
examples are the explicit **legacy messaging-only** branch, not an accounting
grant or an automatic upgrade path. Source authoring is not deployment or acceptance.

A workload is a scheduled process that reads and writes an account's records with no person signed
in. It is its own kind of actor. It cannot be a person, a person cannot be it, and it holds store
read and store write over three families and nothing else.

The JSON blocks below are strict-decoded by `TestWorkloadContractExamplesDecode`, so they cannot drift
from what the engine accepts.

## 1. Configure the engine

Add `workloadPolicy` to the domain configuration passed to `ConfigureDomain`. In this repository's host
that is `configuration()` in `retained/native/domain.py`, beside `provisioningProfile`.

```json policy
{"issuer": "workload-authority:activity",
 "families": {
   "resource:png.messages": ["account_id", "direction", "id", "text"],
   "resource:png.conversations": ["account_id", "id", "title"],
   "resource:png_source.messaging.contacts": ["account_id", "id", "phone_number"]}}
```

- `issuer` must start `workload-authority:` and differ from `trust.issuer` and `integrationIssuer`.
- `families` may name only those three. The engine holds that list; configuration can only narrow it.
- Each field list needs `id` and `account_id`, holds plain names (`[A-Za-z_][A-Za-z0-9_]*`, no `data.` prefix)
  with no duplicates, and every `data.<name>`, `family.<family>` and the store's base fields must already
  be in the owner's profile for `png.store.read` and `png.store.write.define` on both `root` and
  `png_record`. Anything else fails `ConfigureDomain`. So omit a family the business has no mask for.
- List every column a row may hold. For a family, that is `field_masks[(IMPORT_ACTION, family)]`.
- Without `workloadPolicy`, no workload is admitted and no workload control runs.
- Narrowing the policy takes effect at once, over grants already made. Widening it needs a new grant.

This is host configuration, not business configuration. **Do not add it, or the two control names
below, to the business configuration, its `enrollmentPolicy` or the profile.** That would change the
digest and P&G's account id. Nothing in this contract needs them to change.

## 2. Identity

| | Form | Rule |
|---|---|---|
| Principal | `workload:<id>` | `<id>` matches `[a-z0-9][a-z0-9_-]{0,63}` |
| Session | `workload-session:<id>:<run>` | same `<id>`; `<run>` matches `[A-Za-z0-9_-]{1,128}` |
| Kind | `workload` | |
| Issuer | the configured one | |

Both prefixes are reserved in any letter case. A person's proof carrying either is refused, including
at enrollment and at the personal-source paths.

## 3. Answer the proof

The engine posts to the same `trust.verifierEndpoint`, with `Authorization: Bearer <channelToken>`, for
both `admission` and `handoff`. The body is the existing `DomainCheck`:
`{contractRevision, proof, phase, audience, intent, leaseBinding}`. Decide from the proof you issued that
this is the workload and its grant is current, then answer with 200 and exactly this:

```json workload-answer
{"contractRevision": "manifest-domain-handoff/0.1",
 "principalId": "workload:alive5-sync",
 "kind": "workload",
 "sessionId": "workload-session:alive5-sync:20261031t0500",
 "scope": {"accountId": "account-1", "product": "manifest"},
 "intent": {"contractRevision": "png-native-store/0.1",
   "scope": {"accountId": "account-1", "product": "manifest"},
   "binding": {"scope": {"accountId": "account-1", "product": "manifest"}, "rootId": "root-1", "bindingRevision": "manifest-binding/0.2"},
   "mode": "command", "operation": "png.store.write.define", "method": "POST", "target": "/manifest/native-store/execute",
   "requestFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "resources": [], "fields": []},
 "grantRevision": "alive5-sync-grant-1",
 "authorityResourceRevision": "alive5-sync-connection-3",
 "expiresAt": 1793400000.0,
 "issuer": "workload-authority:activity",
 "audience": "activity-native",
 "phase": "admission",
 "leaseBinding": null,
 "proofBinding": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
```

- `intent` and `leaseBinding` echo the check exactly. `scope` is the intent's.
- `proofBinding` is the lowercase SHA-256 hex of the proof. `expiresAt` is within `maxLifetimeSeconds` of now.
- `grantRevision` must equal the revision the grant carries. Keep that string when you grant.
- `authorityResourceRevision` is any non-empty string that names what you checked.
- Leave out, or send empty, `ownerAuthorized`, `principalReference`, `resolutionNamespace` and
  `integrationActor`. Any of them makes the answer invalid.
- `intent.contractRevision` must be `png-native-store/0.1`, on product `manifest`, mode `read` with no
  `operation` or mode `command` with `png.store.write.define`. So a workload never gets a graph read.

## 4. Read and write

The same channel and lease as a person's store call, and the same request body:

1. `DomainResolve` with `{mode, method: "POST", target, body}`. No proof is needed to resolve.
2. Issue a proof for that intent. `DomainCall` with `{...input, requestId, proof}`.
3. Control `adopt`, then `receive`.
4. Control `handoff` with a fresh proof, answered with `phase: "handoff"` and the lease as `leaseBinding`.
5. Control `finish` with `disposition: "handed-off"` and the permit.

| Mode | Target | Body |
|---|---|---|
| `read` | `/manifest/native-store/read` | `{contractRevision: "png-native-store/0.1", scope, action, query}` |
| `command` | `/manifest/native-store/execute` | `{contractRevision, scope, action, operation: "png.store.write.define", commandId, expectedRevision, mutations, result}` |

The revision for `expectedRevision` comes back on every read. `query.fields` must be explicit and inside
the list. A replayed `commandId` answers `replayed` to the workload that made it.

What is refused, all with the masked `native result denied/unavailable`:

- Another family, including `native.command_receipt`: there is no history read. Replay by `commandId`.
- `references`, and `unique` over another family.
- A creation of any kind but `png_record`, or with `id` other than its key, or `account_id` other than the scope's.
- A change to a field outside that family's own list, including another family's column. A patch may
  carry an existing outside field unchanged, and may not change or remove it.
- `result.derive_carrier_events`, because it writes another family.
- Another account, a stale `grantRevision`, or any time after a revoke.

## 5. Grant and revoke

Two controls, shaped like the read grant: `manifest.scope.workload.grant` and
`manifest.scope.workload.revoke`. Send through the existing `DomainEnrollJSON` channel and answer through
the existing enrollment callback. They write the root's list and the `png_record` template, and any
record in those families that holds its own copy. Records following the template need no write.

An owner, contract `0.2`:

```json grant-input
{"contractRevision": "manifest-native-enrollment/0.2",
 "requestId": "grant-request-1",
 "proof": "opaque_proof_1",
 "request": {"contractRevision": "manifest-account-enrollment/0.2",
   "scope": {"accountId": "account-1", "product": "manifest"},
   "commandId": "workload-grant-1",
   "expectedRevision": "lj.owned/v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
   "operation": "manifest.scope.workload.grant",
   "targetPrincipalId": "workload:alive5-sync",
   "profileRef": {"profileId": "activity-manifest-png", "profileRevision": "0.2", "profileDigest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}}
```

An administrator, contract `0.3`, sends the same with `manifest-native-enrollment/0.3`,
`manifest-account-enrollment/0.3` and the `administration` object it provisioned with. The engine rechecks
that object against the root, and the administrator's control stops at workloads: it still cannot change
a member's read.

The callback's answer, for an owner:

```json grant-answer
{"contractRevision": "manifest-native-enrollment/0.2",
 "principalId": "user-owner",
 "kind": "human",
 "sessionId": "session-1",
 "scope": {"accountId": "account-1", "product": "manifest"},
 "requestId": "grant-request-1",
 "request": {"contractRevision": "manifest-account-enrollment/0.2",
   "scope": {"accountId": "account-1", "product": "manifest"},
   "commandId": "workload-grant-1",
   "expectedRevision": "lj.owned/v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
   "operation": "manifest.scope.workload.grant",
   "targetPrincipalId": "workload:alive5-sync",
   "profileRef": {"profileId": "activity-manifest-png", "profileRevision": "0.2", "profileDigest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}},
 "requestFingerprint": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
 "grantRevision": "owner-grant-1",
 "authorityPolicyRevision": "policy-1",
 "authorityResourceRevision": "resource-1",
 "expiresAt": 1793400000.0,
 "issuer": "activity-person-issuer",
 "audience": "activity-native",
 "phase": "admission",
 "leaseBinding": null,
 "proofBinding": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
 "ownerAuthorized": true,
 "principalReference": {"actorPrincipalId": "user-owner", "actorSessionId": "session-1", "accountId": "account-1",
   "principalId": "workload:alive5-sync", "purpose": "manifest.scope.workload.grant", "requestId": "grant-request-1",
   "actorGrantRevision": "owner-grant-1", "targetGrantRevision": "alive5-sync-grant-1", "evidenceRevision": "connection-3",
   "authorityPolicyRevision": "policy-1", "checkedAt": 1793399990.0, "validUntil": 1793400010.0, "targetEligibility": "active"},
 "purpose": "manifest.scope.workload.grant"}
```

- `principalReference.targetGrantRevision` is the revision the grant holds and the proof must then
  answer as `grantRevision`. Granting again with a new one replaces it, and the old one stops working.
- A revoke sends `manifest.scope.workload.revoke`, with `targetEligibility` `"revoked"` and
  `targetGrantRevision` null, or `"active"` with the revision.
- An administrator answers `ownerAuthorized: false` and adds `administratorAuthorized: true`.
- The engine requires `kind: "human"` from the person issuer, and an owner's root list to hold the
  existing `manifest.scope.read.grant` or `.revoke` control. That existing right is what authorizes
  these, so your own check should be the same one: `account_purposes` maps those two to the access
  capability. The profile cannot name new controls without changing its digest.
- A control naming anything but a valid workload is refused. A read grant naming a workload is refused.
- An administrator must already hold `png.store.write.define` with `png_record` creation on the root.
- Stop issuing the workload's proofs when you revoke. The engine refuses them anyway.
- The existing Python enrollment path knows only the read controls. Teach it these two names in code,
  not through `enrollmentPolicy`.

## 6. What the receipts say

| Event | `command.principalId` | Also |
|---|---|---|
| Workload write | `workload:<id>` | `productIntent` holds the rows |
| Grant, revoke | the person who did it | `enrollmentRecord.request.targetPrincipalId` is the workload; `followers` counts the `png_record` records reached through the template; `targets` names what was written |

The principal form is reserved, so a receipt naming a workload cannot mean a person.

## 7. Limits to plan around

- A grant writes every record in the three families that holds its own copy, and `maxChanges` is 256. A
  forest with more of those than that refuses the grant: re-import it so its records follow the template.
- An engine older than this one refuses to open a forest once it holds a workload grant or revoke receipt:
  `owned receipt map contains unsupported state`. Rollback past the first one is restoring a backup.
- Every workload write is one command against one revision. A concurrent person's write makes it a
  conflict, and the next poll tries again.

## 9. Connection-bound policy, grant and run (R5)

The protected policy revision is `manifest-native-workload-policy/0.2`. Its exact
keys are `contractRevision`, `installationId`, `issuer`, `maxLifetimeSeconds`,
`legacyMessaging`, and `purposes`. `legacyMessaging` is null or the old explicit
messaging family map. It never includes accounting. The proof lifetime cap is
positive, at most 30 seconds and at most the host trust cap; it is not G's lifetime.

`purposes` has only `messaging.sync` (provider `alive5`) and `accounting.sync`
(provider `quickbooks`). Each value is exactly `{provider,policyDigest,families}`.
Each family is exactly `{kind,readFields,createFields,updateFields,rule}`. All
lists are explicit, sorted, unique and finite. R is bounded by the corresponding
checked-in schema plus `id`/`account_id`, intersected with actual owner profiles
and grants. No missing owner mask or AssociateCarrier is manufactured.

| Purpose | Family | Kind | Rule |
|---|---|---|---|
| messaging.sync | resource:png.messages | png_record | alive5.messages/1 |
| messaging.sync | resource:png.conversations | png_record | alive5.conversations/1 |
| messaging.sync | resource:png_source.messaging.contacts | png_record | alive5.contacts/1 |
| accounting.sync | resource:png_import | png_record | quickbooks.observation/1 |
| accounting.sync | business:associate | associate | quickbooks.client/1 |
| accounting.sync | business:job | png_record | quickbooks.project/1 |

The policy digest is SHA256 of `CanonicalDomainJSON` over
`{contractRevision,installationId,purpose,provider,families}`. Custody hashes use
their own encoding and cannot substitute for native request/intent/receipt hashes.

### Closed G, W and enrollment

G has exactly `{contractRevision,installationId,accountId,connectionId,provider,
purpose,grantRevision,policyDigest,expiresAt}`, revision
`manifest-workload-grant/0.2`. `expiresAt` is a strict JSON INTEGER token in
1..9007199254740991 Unix seconds; strings, booleans, fractions and exponent tokens
are refused. A different expiry requires a different grant revision and human
enrollment. G never grants permission to use credentials.

The principal is `workload:` plus lowercase SHA256 of canonical
`{installationId,accountId,connectionId,provider,purpose}`. W is exactly
`{contractRevision,grant,runId,fenceGeneration}`, revision
`manifest-workload-run/0.1`. The session is
`workload-session:<derived-id>:<runId>`; the existing run syntax is unchanged.
`fenceGeneration` is an ASCII decimal STRING matching `[1-9][0-9]{0,19}` and at
most `18446744073709551615`. Zero is unissued, not a valid W. No extra expiry is
added to W. The backend owns the durable installation/account/connection
high-water shared by manual and scheduled work; G replacement, revoke and restart
must not reset it. A valid already-issued MAX fence may finish, not wrap or mint
a successor. Native proof callbacks must attest that exact current run.

The existing workload grant/revoke operations use request
`manifest-account-enrollment/0.5`, input/proof `manifest-native-enrollment/0.5`,
and retained provenance `manifest-native-enrollment-record/0.5`. Requests retain
the seven original fields and require `workloadGrant:G` and `administration`
(null for a current human owner/co-owner; the exact existing object for an admin).
No /.4 co-owner fields are allowed. Verified answers require the explicit boolean
`administratorAuthorized`, mutually exclusive with owner authorization. The target
reference proves current registered target revision, not an echo of requested G.
Revoke can carry revoked/null target authority but still removes only exact
installed G, including expired G under fresh human authority.

Native ACL/2 store grants carry typed `workloadGrant:G` and
`targetGrantRevision==G.grantRevision`. Installation changes only the reserved
target; founder profile, identities, independent principals and co-owner
contributions remain untouched. Delegation requires ONE complete currently held
root/template grant for all fields and creation kinds, not combined partial
contributions. Legacy controls cannot alter bound grants. Historical grant/revoke
replay and handoff check current exact pins; an old revoke cannot become current
after a successor G is installed.

### Callback, retained request and actual ACK

`DomainInput.workload:W` is optional and absent on legacy human/channel/workload
calls. Native adds its private copy to the product-resolved intent; callers cannot
replace product intent. Only W-bearing requests use
`manifest-workload-handoff/0.1`. The six check keys/transport stay unchanged.
Verified answers require `workload:W` equal to `intent.workload`; even explicit
null owner/principal-reference/integration/namespace claims are refused.

Every admission and fresh handoff checks current protected policy, exact installed
G, scope, derived identity and current callback W. Callback expiry is finite and
bounded by the proof cap, G, approval and run deadline; handoff cannot extend the
original lease. The native engine retains shortened deadlines. Proof is never a
receipt or terminal ACK.

Native retains `workloadRecord` with exactly
`{contractRevision,principalId,sessionId,workload,requestFingerprint,intentFingerprint}`,
revision `manifest-native-workload-record/0.1`. The product hash E is unchanged;
the intent hash includes W. This typed record is covered by the actual paired
receipt hash/snapshot, accompanies only a native store command and its existing
product result, and never mixes with enrollment/mapping provenance. Old receipts
remain byte-compatible without the member.

Locked prepare/replay and handoff compare the complete retained record, even for
zero-target commands. Missing historical W cannot be adopted. Changed run/fence/G
conflicts, and a bound command ID already retained for another workload principal
in the same owned scope cannot be reused across connection/purpose tuples. Legacy
human command-key namespaces are unchanged. Reads bind W through the intent hash
without creating a command receipt. Unknown outcomes remain fenced; backend
checkpoint advancement requires actual finish/ACK and the same durable claim.

### Source-owned effects, not field unions

Queries require explicit fields and per-family filter/order ceilings. Each mutation
is checked independently against that family's R; actual changed/removed fields
must satisfy that family's W. Record key/family/id/account cannot move. Unchanged
local fields survive. Result metadata is null/empty or the existing command digest,
not derivation or approval effects. References, history, graph controls and arbitrary
metadata are not workload capabilities.

Messages are create-only. Conversations start unarchived and can update only
last_message/updated_at or a missing title. Contacts fill missing source fields.
QuickBooks observations retain bounded inert original source, exact connection,
realm/environment/entity/external identity and source hash; identity cannot move.
Clients remain type client; jobs cannot change lifecycle/approval fields.
The exact engine W ceiling lists live in `activation_domain_workload_policy.go`.

A png_record create still has exactly its original five metadata keys. An Associate
has exactly those plus the actual carrier's accountId, deterministic label and
empty initial roleIds. Existing native roles never change. Both require an exact
same-root/same-kind ACL reference; a generic png_record cannot impersonate an
AssociateCarrier.

### Source-phase evidence and remaining gates

Authored native tests include strict token/canonical vectors, complete policy and
delegation decisions, real /.5 enrollment/regrant/revoke/reopen, retained W/hash and
zero-target replay, six family delta rules, and actual embedded pngstore paired
create/read/update/reopen/revoke/fresh-handoff tests. The embedded fixture uses an
explicit synthetic authority/profile and the real product adapter, not a fixture
writer. Legacy examples and regressions remain.

No tests/builds/typechecks have been run during this source phase. Consolidated R5
QA must run these tests plus affected legacy/.4/staged/actual FFI regressions,
security/quality review, and the backend two-process fencing/ambiguous-outcome/
checkpoint integration. No native artifact, pin or deployment is promoted here.
