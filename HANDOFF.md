<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Handoff: `product/momentum-personal` (Momentum personal source)

This branch is LumberJack `main` at the cut commit `da93661` (`main` `d18f3e7` plus the design and the
compatibility fixtures), with this file added. The whole tree is here, unchanged, so the product
builds and its tests run exactly as they did. `main` removes this code at P3b-7
(`docs/extension-api.md` §8) and does not port, maintain or fix it. The design this hands off
against is `docs/keep-move.md` and `docs/extension-api.md` on this branch.

## What it is

Momentum's personal source: personal provisioning and its registry (`activation_personal_*`),
canonical identity mapping (`activation_canonical_*`), identity control and evidence
(`activation_identity_*`), native control binding and seal verification (`activation_native_*`),
the owned-context resolver (`activation_owned_context.go`), the `core.PersonalBindingLedger`
type, and the embedded and FFI personal-source surfaces. It builds on the owned-scope base
(`staged_*`, `activation_source_*`) that `product/manifest-domain` owns; personal builders live in
`staged_snapshot.go:247-427` and the literal `"momentum"` at `staged_snapshot.go:255` and
`staged_candidate.go:337`.

## Seams it used in the old engine

| Call point (at the cut) | What it did |
|---|---|
| everything listed for the owned-scope base in `product/manifest-domain`'s handoff | permit, staged protection, visibility, overlay, pairs |
| `staged_snapshot.go:82-113` | composed its private ledger into the same snapshot as the pending owned nodes (`personalOverlayLedgerLocked`) |
| `state_codec.go` / `restoreAllNumbers` | a root holding `personal_bindings` made every node decode with `UseNumber` |
| `types.go` `Server.personalSource`, `Server.nativeControl` | per-server registry and control state |
| `embedded/personal_source_lifetime.go:117` | the shared close path with the domain |
| `application_session.go` | session deadlines for identity-control leases |

## Public extension seams that replace them

| Old call point | Seam (`docs/extension-api.md`) |
|---|---|
| fence, protection, visibility | as for `manifest-domain`: `PermitProvider`, `WriteHook`, built-in marker rule (§4.1, §4.2) |
| the ledger on the root | root slot key `personal_bindings` (§4.5), set with `Tx.SetSlot` in the same `Host.Change` |
| number preservation | built in: every node decodes number-exact |
| lifecycle | `Instance.Close` |
| session-bound leases | `Host.Sessions()` and the session registry |

## FFI exports it takes

`ic_lj_personal_source_configure`, `ic_lj_personal_source_call`, `ic_lj_personal_source_control`,
`ic_lj_personal_source_free`, `ic_lj_native_control_configure`, `ic_lj_native_source_verify_seal`
(6).

## What a product must do to rebuild on the extension API

1. Depend on the rebuilt owned-scope base from `product/manifest-domain` (or rebuild the parts it
   uses), since the two were removed together (`docs/extension-api.md` §8, P3b-7).
2. One `extension.Extension` with `Spec{Markers: ["lumberjack.staged.scope/v1"], Slot: {RootKeys: [{Name: "personal_bindings"}]}, Persistence: SnapshotOnly}`.
3. Write the ledger with `Tx.SetSlot` in the same `Host.Change` as the nodes it describes.
4. Product archive (§6) with the 6 exports above.

## State it owns in existing stores

| Key | Level | Without this extension registered |
|---|---|---|
| `personal_bindings` | root | preserved byte-for-byte as an unclaimed slot key; never projected (already true) |
| owned personal roots (`command_receipts["lumberjack.staged.scope/v1"]`) | node marker | hidden and guarded by the built-in rule |

## When it left `main`

`finalize/split` commit `bf5040b` (P3b-7), together with `product/manifest-domain`, whose
owned-scope base it depends on, except `internal/core/personal_binding.go`, which held
`core.Node.PersonalBindings` until `7386fc6` (P3b-8, deviation D7). From then on
`personal_bindings` is a root slot key, kept as its bytes.

## Tests that left from shared files

None beyond the test files listed above; the shared ones are listed in
`product/manifest-domain`'s handoff.

## Shared files it depends on

The owned-scope base, owned by `product/manifest-domain` (listed in full in that branch's handoff):

| Path | Lines |
|---|---:|
| `internal/activation_source_fence.go` | 416 |
| `internal/activation_source_legacy.go` | 71 |
| `internal/activation_source_session.go` | 431 |
| `internal/staged_candidate.go` | 398 |
| `internal/staged_clone_structured.go` | 63 |
| `internal/staged_guard.go` | 254 |
| `internal/staged_receipt.go` | 189 |
| `internal/staged_reconcile.go` | 404 |
| `internal/staged_reopen.go` | 26 |
| `internal/staged_scope.go` | 263 |
| `internal/staged_snapshot.go` | 427 |
| `internal/staged_types.go` | 169 |
| **total** | **3111** |

## Files and lines

19 non-test Go files, 5294 lines; 10 test files and test data, 928 lines. Tests leave with the code they test. `sha256` is of the file at the cut, in the format of `docs/activity-source-import.jsonl`.

### Source

| Path | Lines | sha256 |
|---|---:|---|
| `embedded/personal_source.go` | 98 | `53918a4ad2c97d44d7fbfed2d22d9d8c890964810744c037c7986a4ba445683d` |
| `embedded/personal_source_lifetime.go` | 145 | `18781b5b2177a63c45df24832c602d591ef751074e15e2f4f2f7926e4031bbca` |
| `ffi/personal_source.go` | 114 | `3eae36b1ffd55813151c47e171d665d7f2f6e7ceb08aacf63f0679b635cec91d` |
| `internal/activation_canonical_mapping.go` | 371 | `015451aa99c27379b9fb55674b32618eece0dd93f3bf509a69b539139fac376c` |
| `internal/activation_canonical_mapping_persistence.go` | 444 | `c3f63c3c381aecc1014eedc9688e591e42cbf3e8efa43bd2e79540e3f00748a9` |
| `internal/activation_canonical_mapping_seal.go` | 372 | `c5cfb0ee742bb81939d45780f852b485a44bb53ad483fb4181bfaee0182f80ab` |
| `internal/activation_canonical_mapping_session.go` | 281 | `b543995024c90db2338c560990ac260875230a72cd322d9d97a16a117a346ebd` |
| `internal/activation_canonical_mapping_values.go` | 300 | `60c3738f980d69d8d6bc8353d07a057aa52fe811ef70fe19a18295368c2dbc76` |
| `internal/activation_identity_control.go` | 159 | `35aa770a87362a3a1d2ace5c3e1e21f04d6494428ab45da1c1f3148b115b32ea` |
| `internal/activation_identity_evidence.go` | 279 | `f1f2814c8a957630e23c16d8e784244b5d6d4be95008a6a396f1fdd936f137e6` |
| `internal/activation_identity_values.go` | 294 | `d29d1f94f6145fbaa2e816e5a18e2761950caa912f7fb07665ee386d007cc9de` |
| `internal/activation_native_control_binding.go` | 438 | `208f57794f67217df08e10625254f223a18448c80251ab3b7d26880b42a2db99` |
| `internal/activation_native_control_config.go` | 114 | `5734fd53ff1333adb0e8abb6f45aacda5e34463d31c7dafb0ad2dc192fb2f168` |
| `internal/activation_owned_context.go` | 220 | `9d5dcf6adce7ececb9fbe2255c8244e476458889d5efa1dfa819b22da03e5631` |
| `internal/activation_personal_provision.go` | 426 | `f2f5296b1563d2317fc91053b6d7ce1296715dce23f4702407dd30e3f4ddceac` |
| `internal/activation_personal_provision_proof.go` | 343 | `123a01c1571f6d3535759651401fe8c3fe5a463d3f2f91791ce25c37f8e0e57d` |
| `internal/activation_personal_registry.go` | 377 | `d8db093ed8e08e96e615f75451f34fb027ffb03cf4e328a1b30fc982c0aa60b3` |
| `internal/activation_personal_source_wire.go` | 386 | `9f5731b699acfe1b3163c7f719541016a4b7b6157a6314f6b4191789e51a7ced` |
| `internal/core/personal_binding.go` | 133 | `cb1c8cb4b9065a8e38f9011b9e11efa6f7be3311100478c236c3a97b41e29d04` |

### Tests and test data

| Path | Lines | sha256 |
|---|---:|---|
| `embedded/personal_source_test.go` | 51 | `d53b5f1062f0fadbb2b59299884c3b85a3797707f0053e5059639b70c3628e66` |
| `ffi/personal_source_test.go` | 24 | `6a2e1071d40ce2992a2d5c68c0053878b997b9837f0f3e5131e503cea88d4ba3` |
| `internal/activation_canonical_mapping_test.go` | 215 | `f4f79be7e392c8131520e1d62a1340cda92d606eb0c576c3f60a6338f7678990` |
| `internal/activation_identity_control_test.go` | 22 | `61efbfa29b0707bde706d8a78a66e9d3783ab14431f082a45ba8c0a9a41f767b` |
| `internal/activation_identity_evidence_test.go` | 37 | `e382d57fc2b17ce5ec07d6f109daeeb009fcc4a2adb0fd9955355aea8a77fa74` |
| `internal/activation_native_control_binding_test.go` | 193 | `76ac34768d4fc77f4757ef6203ebbc73ad0e093463469d980dec8a91fed914c5` |
| `internal/activation_native_control_config_test.go` | 143 | `91bfb5ea494f4a0e18fd4845415240cfed7d9840e4fc308f2d8c48969943ef8e` |
| `internal/activation_owned_context_test.go` | 37 | `7539d66c579095fb3f71ec4c8ea3de337893446293ecf4c7e1916230e02f7189` |
| `internal/activation_personal_registry_test.go` | 63 | `76704498660c688f8d4c5edecb5f907bba78dcc5ef9cebd7af23571588683990` |
| `internal/activation_personal_source_wire_test.go` | 143 | `219214158a3af30fbeea2e0fd1358aecab40bfc8eb92723bbe7650d72202e495` |

