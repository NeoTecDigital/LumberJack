<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Workload write grant: the host's contract

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
