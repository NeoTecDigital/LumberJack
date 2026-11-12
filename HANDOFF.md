<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Handoff: `product/manifest-domain` (Manifest domain engine and the owned-scope base)

This branch is LumberJack `main` at the cut commit `da93661` (`main` `d18f3e7` plus the design and the
compatibility fixtures), with this file added. The whole tree is here, unchanged, so the product
builds and its tests run exactly as they did. `main` removes this code at P3b-7
(`docs/extension-api.md` §8) and does not port, maintain or fix it. The design this hands off
against is `docs/keep-move.md` and `docs/extension-api.md` on this branch.

## What it is

The domain engine and its products: `DomainProduct`/`DomainPolicy` with seven optional capability
interfaces (`activation_domain_*`), enrollment (`activation_enrollment_*`), the domain snapshot
cache, the products `products/manifest`, `products/pngstore` and `products/momentum` (Momentum's
`DomainProduct` adapter, registered by `embedded/manifest.go:35`), the embedded and FFI domain
surfaces, **and the owned-scope base it shares with `momentum-personal`**: the owned-scope command
engine (`staged_*`: descriptors, bounds, configure/reconcile, CAS, pending receipts, the snapshot
overlay, durability pairs) and the source fence (`activation_source_{fence,legacy,session}.go`).
This branch owns that base; `product/momentum-personal` lists it as a dependency. Mindfull's Python
host calls `ic_lj_domain_*`, so it consumes this branch's archive (Q9(a)).

## Seams it used in the old engine

| Call point (at the cut) | What it did |
|---|---|
| `forest_lock.go:131-169` `changeForest` / `beginForestWrite` | `sourceFence().beginOrdinaryWrite` permit before the hold; whole-forest revision evidence; `noEffect` / `finish` outcomes |
| `forest_lock.go:220-247` `runChangeLocked` | `captureStagedProtectionLocked` / `verifyStagedProtectionLocked` around every change |
| `api_helpers.go:35,51`, `api_queue.go:83`, `query_walk.go:59,93`, `forest_projection.go:65` | `isStagedNode` hid owned nodes from generic reads |
| `staged_snapshot.go:82` `encodeSnapshotLocked`, `state_writer.go` `commitPaired` / `pairedStamp` | the snapshot overlay of pending owned nodes and paired durability witnesses |
| `state_codec.go:239` `restoreStagedNumbers` | `UseNumber` for owned nodes |
| `state_codec.go` `stateACLReferenceMark` | the STATE-3 banner when an ACL reference is stored |
| `types.go` `Server` fields | `domain`, `domainConfiguring`, `domainSnapshots`, `stagedScopes`, `sourceCoordinator` |
| `embedded/runtime.go:33-35,155-180` | `domainLifetime` close ordering |
| `persistence.go:157` | `refuseWholeStateWriterUnderTier`: refused under tiered persistence |

## Public extension seams that replace them

| Old call point | Seam (`docs/extension-api.md`) |
|---|---|
| the source fence permit | `extension.PermitProvider` / `Permit` with `WantsRevision` and `Settle(Outcome)` (§4.1); at most one per runtime |
| staged protection around a change | `extension.WriteHook.BeforeChangeLocked` returning `After` (§4.1); the built-in owned-subtree guard runs first and last |
| `isStagedNode` | built-in owned-marker rule over `Spec.Markers` plus the compat marker `lumberjack.staged.scope/v1`; `extension.VisibilityFilter` (§4.2) |
| overlay and paired durability | not a seam (§9): `Host.Change` returns `Commit{Seq, SHA256, Path}`; re-read the file it names |
| owned-node numbers | number-exact decode for every node (built in) |
| STATE-3 | sticky banner level; `BannerRequirement(data []byte) int` |
| domain close | `extension.Instance.Close` in reverse attach order |
| tier refusal | `Spec.Persistence = SnapshotOnly` |
| all writes | `Host.Change`; reads `Host.Read` (unfiltered owner view) |

## FFI exports it takes

`ic_lj_domain_configure`, `ic_lj_domain_resolve`, `ic_lj_domain_call`, `ic_lj_domain_control`,
`ic_lj_domain_enroll`, `ic_lj_domain_provision_root`, `ic_lj_domain_ack_completion`,
`ic_lj_domain_free` (8). They move to a product archive with its own header `lumberjack_domain.h`
that includes `lumberjack.h`.

## What a product must do to rebuild on the extension API

1. One `extension.Extension` named e.g. `manifest-domain`, `Spec{Markers: ["lumberjack.staged.scope/v1"], Persistence: SnapshotOnly}` plus any slot keys it adds.
2. Its `Instance` implements `PermitProvider` (if it still wants fencing; `WantsRevision` only if
   it is the exclusive provider), `WriteHook`, and `RouteProvider` if it serves routes.
3. Keep `DomainProduct` and its capability interfaces as the domain's own plug-in surface, inside
   the product.
4. Replace overlay and pairs with `Commit` from `Host.Change` (§9).
5. Build the product archive (§6): generated base wrappers, the 8 `ic_lj_domain_*` wrappers over
   `abi.Lookup`, `init() { abi.Register(...) }`, header `lumberjack_domain.h`.

## State it owns in existing stores

| Key | Level | Without this extension registered |
|---|---|---|
| `command_receipts["lumberjack.staged.scope/v1"]` | node marker | **node hidden from every generic read and its subtree guarded** (403 on ordinary writes that change it or its ancestor links) |
| `command_receipts["lumberjack.staged.receipt/v1:*"]` | node | preserved inside the typed receipt bag |
| pending overlay nodes written at a crash | nodes | loaded as ordinary marked nodes: hidden, guarded, preserved verbatim |
| ACL references (`"contractRevision":"…"`) | node metadata | preserved; the STATE-3 banner never downgrades |

## When it left `main`

`finalize/split` commit `bf5040b` (P3b-7), together with `product/momentum-personal`. At `e3affb2`
(P3b-6) the source fence and the staged-scope protection ran behind the new `PermitProvider` and
owned-subtree guard seams as temporary internal implementations, and every suite on this branch
passed against them, under `-race` too. `docs/workload-write-grant.md` (the workload contract,
tested by `TestWorkloadContractExamplesDecode`) left with it. `main` keeps the owned-marker rule and a
marker-based subtree guard, written fresh (deviation D18), and a store holding the legacy marker
still does not open tiered (D17).

## Tests that left from shared files

- `internal/persistence_fence_test.go`, whole: the fence in both modes, and `ConfigureDomain` /
  `ConfigurePersonalSource` refused under tiered persistence. `main` keeps the generic halves in
  `internal/persistence_owned_test.go`.
- `TestEnrollmentWitnessAcceptsTheReferencesBanner`, and the enrollment-fixture forms of the STATE-3
  tests, in `internal/state_references_test.go`; `main` tests the banners over a plain reference.
- `TestCompatReferenceRevisionIsTheDomainsRevision` (`internal/compat_hardening_test.go`).
- `internal/compat_fixtures_gen_test.go`, the fixture generator: it calls this branch's builders, so
  it runs here, at the cut, and nowhere else (deviation D19).
- Two calls in `internal/staged_isolation_test.go` changed signature at P3b-6 (D15); the cut has
  them as they were.

## Files and lines

103 non-test Go files, 12584 lines; 79 test files and test data, 10220 lines. Tests leave with the code they test. `sha256` is of the file at the cut, in the format of `docs/activity-source-import.jsonl`.

### Source

| Path | Lines | sha256 |
|---|---:|---|
| `docs/workload-write-grant.md` | 207 | `510c32b7ebdaa3a586a247e4ae1f57b9f316ecf061f48451df7d4d955cce6456` |
| `embedded/domain.go` | 137 | `d5d306191a3ab89ef82849c9cb98978f709bbb38d5a81f198f0d4040040c2d66` |
| `embedded/domain_completion_ack.go` | 65 | `10b8dbf9cd1f1a1867de541680db94773355ff12b3cc8f928e4d8687f15cbbf6` |
| `embedded/domain_enrollment.go` | 25 | `df825dbb7cd06ae01885436a850955502a195a864e276bcb906bd2ccf53688c8` |
| `embedded/domain_lifetime.go` | 134 | `12ed61c2f95eb7c3d604457a8d00f4d6a6f3d5757b328c101219fdfdd2da06f1` |
| `embedded/domain_owned_root.go` | 22 | `99c4ec657444aed894f89712c8fd2583678c648a7a54c3899596c26d8e6b170a` |
| `embedded/manifest.go` | 42 | `e138858a792c6a7a0a5d107410ce0fe1361ca1a97c5482a4e22b0f65ae89c4cd` |
| `ffi/domain.go` | 106 | `050612e5db626de28886a6b34105ff59b7d9a3a90179ff481258b6a4f4b57440` |
| `ffi/domain_completion_ack.go` | 28 | `f57b3349ed414f1f36b98e8de06d292cb90c0db59787a937e9a5b98b5f8b70d8` |
| `ffi/domain_enrollment.go` | 22 | `38bc12a22b0d5052a1d36833ea6b1dd873ae1f9be508a88eecdc05bb5ad05dc8` |
| `ffi/domain_owned_root.go` | 22 | `7a234ea88bc37d8b183299e5b7a207fc66978b55469ae9958e50ab54727c734a` |
| `internal/activation_domain_acl.go` | 99 | `64a0f412c7c97f323a01cb7d69a6778b603058cab3e3b66102efb57c6590f3c2` |
| `internal/activation_domain_acl_reference.go` | 147 | `3416342ed90b84b09ec6cccaa203a5a969b68f9795c4481561e81d21d1992894` |
| `internal/activation_domain_adapter.go` | 187 | `0c03bc0d730963403f954720b3de1820699cee2fe6c7c3e61862eaa861ef4b43` |
| `internal/activation_domain_associate_carrier.go` | 13 | `671800388979747f9eca384b5a15fbac848bc7165699c2fcc39aeeaf3f51c2bf` |
| `internal/activation_domain_binding.go` | 183 | `140f52017b1a6fab95408841c159f485c2cbb25888bd2608310caf41aa68cb97` |
| `internal/activation_domain_close.go` | 86 | `010d4c142db0323bd7e6ef1b39bca7cb978ba2be1a403c94ec4f8ac7d954c436` |
| `internal/activation_domain_completion_ack.go` | 31 | `4185ccc194e644c92ed5307e893002cbc8b032abe07997aaedadf46c0d3206de` |
| `internal/activation_domain_completion_ack_json.go` | 72 | `f2e8ae62d2f4ed65127fff541b090d0c6e66c88ba1a374d56a7daae441080f5c` |
| `internal/activation_domain_config.go` | 251 | `052a11f757baa77ac7fc059a07b02b7c1802e49650a2a12336b268ea4968d64f` |
| `internal/activation_domain_control_json.go` | 66 | `d757a13cf0401f26e192eecaf7a6cc0e506cd7ef2aa1b81d0f286d4b85aec7ce` |
| `internal/activation_domain_empty.go` | 19 | `48882f655789b197f1523b9954af37c8811d6c144da464bf068456e56e685fa8` |
| `internal/activation_domain_enrollment_gate.go` | 173 | `2ae2688583755d14788f801af8a2bd523b74a3a984fa07e95105f28c3bda33b1` |
| `internal/activation_domain_evaluation.go` | 105 | `1c00f5c16463e42ed32d55c32fff69a64d83f926eb9b9c1bd1b0d8e0ad4b8459` |
| `internal/activation_domain_evaluation_clone.go` | 76 | `e56cfacced378c6e6ea721bb436c98143cc018d46b7517f0a2e0e2ee2a34ee40` |
| `internal/activation_domain_gate.go` | 243 | `8379ec163c86c4dfc0ccc307f20866dd60e03c5c1082c296860923e0612384d8` |
| `internal/activation_domain_integration_actor.go` | 64 | `3424d8ca3e179fd2f06b1da9dfc72694a5466ef58c9ab228da97c5d688e44f18` |
| `internal/activation_domain_json.go` | 260 | `3ed8ed398276717f4c220d59374dc09bcb7dd82c02b0b9f596a3b20c47fddea2` |
| `internal/activation_domain_owned_root.go` | 156 | `0a1f3bd5536e20ab780ec1d33e590c54c421b89aa80df1200722aea326f834a0` |
| `internal/activation_domain_private_view.go` | 20 | `75c8f03dbd8ac8945d0587cff2015e2658850b5bcc6df13f14876eb0d4cb18f0` |
| `internal/activation_domain_proof.go` | 70 | `abb0e8922d1a94263d7d469dd6c1c85214575e288a477babdf96694a48fafaa0` |
| `internal/activation_domain_provision.go` | 203 | `f2586b22db2b5632a81fb17fb0e8cc13726aca47325757e62a7cec65a1db7474` |
| `internal/activation_domain_provision_candidate.go` | 193 | `a761e757af1a830f0304559faac19f154c484736337731482ed587314dd5dd8b` |
| `internal/activation_domain_receipt_projection.go` | 25 | `0e7b9130b2f18a552a9c02fca1256e6c6d48c7c30a3053bb1a88377aa14e653f` |
| `internal/activation_domain_registry.go` | 240 | `3cd3da3905d6f818f8d006309ceb0333198dd8363b8a0c650295dca1856ddc66` |
| `internal/activation_domain_resource_acl.go` | 185 | `1d97d228754410ac409cfbf772a75a7f87961e5b75e48ce27e4a406dce229971` |
| `internal/activation_domain_store_creation.go` | 11 | `b8fe5053d29f9431986c1a04a01b1d833505e30400cd90f42f884470f36735ce` |
| `internal/activation_domain_store_history.go` | 30 | `f98d6c446604df49645ff73ff7e29453f1f00d08aa72fbf1c685fdbdae2afaf8` |
| `internal/activation_domain_store_product_intent.go` | 167 | `dda390c52b539d0b82f4b399d116fd251a4e2db7a0110f2a25f18773566239c9` |
| `internal/activation_domain_store_product_records.go` | 35 | `3153a521e425860094c70ee740106a131dbaf854d316dcb2d611ffe031a35ec3` |
| `internal/activation_domain_store_read_grants.go` | 19 | `64ca7bb4d10d3baf4ba1043db35b400e55925ece95a91464582e304306da8f63` |
| `internal/activation_domain_store_read_templates.go` | 37 | `03d70ad803d9d96e1d7d334c99cbdfd2aad948db131e9f038afe6dbb9c91dbd5` |
| `internal/activation_domain_store_result.go` | 49 | `d635b6dacce19c712555c5e09f66fd2b299d7625f0fe96a326f972c907e972b3` |
| `internal/activation_domain_target_input.go` | 62 | `992af0d3ec294cbb1ebab169ce5cea1a88559be6cb105fc1bfe3331aa139b61f` |
| `internal/activation_domain_types.go` | 306 | `f1e3504dcde792a860a5150b1bacfc1daeaa7c335f47ad7607dd31b2cd1724e2` |
| `internal/activation_domain_workload.go` | 187 | `8a631acf2ac01f74d834bb079ad16d98f2f604d0b8e5e9b06b12255b3d146a59` |
| `internal/activation_domain_workload_delta.go` | 118 | `28db349205358bbd39ebab02d57d04b219f252bb3c5ebfb1ba8e4ce4d8972e20` |
| `internal/activation_enrollment_acl_writes.go` | 149 | `811b0d1ed918bab456161ca400cdd0196c669b5c34293224e67d954165027e40` |
| `internal/activation_enrollment_administration.go` | 162 | `9e1bb208fc5a6fbebdae71bd65a8ffb4b02f2372c72766f50a6b960e795421ed` |
| `internal/activation_enrollment_administration_acl.go` | 95 | `a57d86317f08b7ac0f9f98201e42c1cef368cc5cc1810f52205952e926b46631` |
| `internal/activation_enrollment_associate_carrier.go` | 85 | `7615a7218137159f06e592f8dadd49062a33e853d6fc5cac5bee7d98dc7de674` |
| `internal/activation_enrollment_json.go` | 148 | `97039bb0e30a76ae79af66ea28b06bc3cde3457fb65bff4eb95d16e65f2c20ed` |
| `internal/activation_enrollment_layout.go` | 190 | `cfa8565c36bb14d308360861e3b43e06be36bc2444804ae393ca637aa9a2ae04` |
| `internal/activation_enrollment_profile.go` | 162 | `1de1ae4342e9430fe404db50ac5d4905cf233197b49c9fa342d84ea941c291e0` |
| `internal/activation_enrollment_proof.go` | 153 | `3bdb13a4b19d152c02c8d5a43bd3cb76cfe454c8b56c2997d008e6b9191cc94f` |
| `internal/activation_enrollment_record.go` | 170 | `bc1713c17c3fe93e17f32ed48a3557fff4e7d7231b49c5a5083deda3b903b951` |
| `internal/activation_enrollment_recovery.go` | 54 | `570e582f4c1ae1489b8e5c12e61be2029665fc9fe39ed649e5a3e8755e07ec62` |
| `internal/activation_enrollment_shared.go` | 46 | `b67871ec0a8dc8d61ac72503a72a233cf37bf2b8c86c67271297eba9dc4b9874` |
| `internal/activation_enrollment_types.go` | 120 | `0d96f01d83ef3895c0d4801bc520e4802351fe1c0146b2aa394a5eaaad2c25a3` |
| `internal/activation_enrollment_workload.go` | 210 | `ad0a236a2fb202c10ce71fe5681de706524821b8902b50db574550b22bf46f1b` |
| `internal/activation_source_fence.go` | 416 | `be06852f67616b7b9e2a961181670ea908d37d4d680eb2dd6ff38f036e156596` |
| `internal/activation_source_legacy.go` | 71 | `123ea5ac9d7d9054c33dda3e35d30c46cea9d096b6d9c0323c310d72167ec3bf` |
| `internal/activation_source_session.go` | 431 | `0011f01508eb8d7a51137ef12e73d4fe53768b1f78adbd8d8e18eb2d7ab30dee` |
| `internal/domain_snapshot_cache.go` | 80 | `aa9bd69e7f1e0b039b29b2b345b0c512cbb5ca14b92674902ef71d6dc48ba009` |
| `internal/staged_candidate.go` | 398 | `aef1b990c3808eb4d3c61738abeb8344f44aaeefd715b42370421e1f95357542` |
| `internal/staged_clone_structured.go` | 63 | `5286af41f3da4ad2dd1c4deda46be62bfd7c6d4f5014d05e9ff0317bdc0e567e` |
| `internal/staged_guard.go` | 254 | `fb4868560746c88e21144ed89b8474e77d0087073711b7c1fd655a561fc71df6` |
| `internal/staged_receipt.go` | 189 | `cc9539ca510e685b045cd89b30988186d2ba0349e261e30e49d5c131e7a0b386` |
| `internal/staged_reconcile.go` | 404 | `589c70337eb6013b2d89a254c8a3e45f21d5f1d2b5aeb97cd5b9d3ab41811bbe` |
| `internal/staged_reopen.go` | 26 | `0ece426275ef7ef2c7c8aeda51f9a5ef20413e2098f7121c996fd251bd83d9dd` |
| `internal/staged_scope.go` | 263 | `b65f393802ab419083fdbd54e98941dd12613315c0bf86745ef234510676d9cb` |
| `internal/staged_snapshot.go` | 427 | `3a55f88323ce84c45fd9f161e53a8b0bf9024b7a48f56b5eb907033997aef3ce` |
| `internal/staged_types.go` | 169 | `a25b8296e9b406bfafed34b83083c8921dbd7254bd052190a062a44554dad2ad` |
| `products/manifest/contract.go` | 214 | `a190e55187480137f359a7b9ef8135af4efcddc7d8f1e52c711b7426b87d15f0` |
| `products/manifest/delta.go` | 143 | `be51042f5e6682481b57a6a7fa1d44aa1a2e93080729f5cf30e55a6fbc0d5bea` |
| `products/manifest/intent.go` | 152 | `d5d2afdfbfaa997eee0874b4d36ae2ace36f25e40105250f313a97d275643c54` |
| `products/manifest/pngstore.go` | 101 | `3be649518b6dbb03d9558924a0ebcf697b65c41f29fb00529c6a6c9c98cf5fb8` |
| `products/manifest/projection.go` | 193 | `18e639eb676aa7be890ecb2d87b824ce22af4b26796682a8e4a507e6d8eebec9` |
| `products/momentum/contract.go` | 71 | `e4aa6876e9b8a1c06a4b33813e06ba50b9ac47e99bc7877c7b5cc8c7dab88db8` |
| `products/momentum/decode.go` | 78 | `7f68a22e34a7f48d96fee074a42aab0c504f5e113ef56e085146b12d06844318` |
| `products/momentum/delta.go` | 75 | `09a5fb035aa208698170ac9d2a01d116af5b34145bd9e347198d636ea0f7caf2` |
| `products/momentum/initialize.go` | 51 | `661673defd842f7b29a8256ad062ae7020c50f0b2fb94eff8859c133ce4d4313` |
| `products/momentum/intent.go` | 81 | `206c7d310fc8edce14836188b0ff5d0450743e90a2ae9364bbc607c10f08e2b4` |
| `products/momentum/layout.go` | 95 | `0cdd3b96999f1357f00ad31307ba400402bb92dc56c975eb7b46d8570798da2e` |
| `products/momentum/projection.go` | 96 | `5904a0483e95be81de2e4447cbd0b3b3df8b8ad0b82a56c2ff8b30fd2f68fc88` |
| `products/momentum/result.go` | 53 | `0be6f1aa41892ce8079896329a100bfda68ef92743cb43fe1088e1e97257a9b8` |
| `products/pngstore/associate_intent.go` | 59 | `a87fd749e6326e039f17bb8a72c28afe399c4ec868a13b922e421917d4a5d6e2` |
| `products/pngstore/associate_mutations.go` | 46 | `4881b8815d902b85526092ba140c3835fdd0dccc9640bfb2469e491ba2b18435` |
| `products/pngstore/associate_policy.go` | 57 | `fd76f255288ce62bd2390d840af486e8fa427e78a8c041c7c297df0d088b6cb8` |
| `products/pngstore/associate_records.go` | 62 | `7da0ec593709036d2a40f6e8e83b0aa173e5e7d84be64c4bd65498bcb3ac19af` |
| `products/pngstore/carriers.go` | 67 | `a790566040bce0b0bf628c35ed88a148b80760200489002cd135992a2d606afc` |
| `products/pngstore/ceiling.go` | 29 | `1ad0cc6ab24026dddfee462302188c8cde068f1d48b178d0c9a09109f93d168c` |
| `products/pngstore/defaults.go` | 67 | `087a44686a501139755b089a08376dc9b62353ab0fe3cf50ccabaa30bcf0b762` |
| `products/pngstore/delta.go` | 200 | `59d9a525279a454db87617f0f4b21249afce631018dec93c4ec54b5549ba37c1` |
| `products/pngstore/families.go` | 36 | `6e5c8a2234a85cb1fa3a006194194a4525626cd8957bba6a56c874416c497801` |
| `products/pngstore/history.go` | 49 | `bdf08ece765d471a41e679e2ce94f407f9f4a129b60c351babd07c2b41188000` |
| `products/pngstore/intent.go` | 169 | `5c3fdc9c4450de0098a5cff0cc9fc0e7d0f54b2421f3c28d4ee9de91c8c66dc6` |
| `products/pngstore/masks.go` | 107 | `8d7762d2f54f9b18b1bc9e9bfccaec676bfa61f2b81171a335b7175a3b02a0b4` |
| `products/pngstore/query.go` | 157 | `5612ba4b61090611cd131e4d0f85de57d7f5f2687a66a4d506e23f1280884639` |
| `products/pngstore/receipt_projection.go` | 12 | `6360ddc1862f2aee508a580d6cdf9f72133b47ad061f2750a70f35c10cd4e4ba` |
| `products/pngstore/records.go` | 113 | `4609952ddd89b916c9030449e64cdebdc357c83f882a7aadcfb492caff286716` |
| `products/pngstore/target_input.go` | 35 | `3fe6087d4a93eed19a7eaaf04022e7151411ca509841e8c580ac4a2354e601d6` |
| `products/pngstore/targets.go` | 80 | `befffbb5bbfd08a890161c2299fc0eb4c9b8b0f89bdf3f332a74dd59a9c8ef26` |
| `products/pngstore/types.go` | 110 | `5953e5a7ca9be78cd893c18dd4960a1d664433161d782dd9a8f9352ab0ba27f3` |

### Tests and test data

| Path | Lines | sha256 |
|---|---:|---|
| `embedded/domain_fixture_environment_test.go` | 36 | `56cbe2bda71d2aaebcf9b4d0fa545ec03c8dca6751fd1d71c4cb66d061b1e033` |
| `embedded/domain_fixture_test.go` | 130 | `987723c1395f3c2361572c7a49182966a47f3acb26200e87e8426b56a4ed08da` |
| `embedded/domain_lifetime_test.go` | 135 | `5476b050a03b378c745266df9048d599c481bb516b86dab501af16f75cd6a793` |
| `embedded/momentum_fixture_test.go` | 139 | `7e359bdc17af27ac19088eeee31429b4583b2459d54e998bf2ff1a2962071728` |
| `embedded/momentum_owned_root_test.go` | 128 | `4b51c8fad86214fd1d84ec5cc8618cb3e020b7c66eafee6aacadb1313615f61b` |
| `embedded/momentum_workspace_test.go` | 131 | `730090e444eb799e6468e118805f9d27f564759f7e1a7419ada156c9ba0e6be3` |
| `embedded/pngstore_acl_fixture_test.go` | 286 | `fbf936d6bce65e707edc62e47b7e327505fa3156dccb6b208db186374be2dca4` |
| `embedded/pngstore_acl_measure_test.go` | 162 | `082f41348aa431b29e8accfd3a7459208170c3c33458d8e56de1cd7c0c2aa976` |
| `embedded/pngstore_acl_reference_test.go` | 107 | `dedf33f4482056c7fcf874b525e6741cd58fd1de1c4ef9382f118e97415db563` |
| `embedded/pngstore_acl_rollback_test.go` | 115 | `e7152afae160a71980dda8cbbdaa6000864ad0648e070a88e3466fb67577c116` |
| `embedded/pngstore_acl_transcript_test.go` | 190 | `9950d6ab4dc3aeac46e58f99045d65b664775bd23eb1c1f945588ed45632691e` |
| `embedded/pngstore_associate_carrier_test.go` | 288 | `2668198fb7f435376d53adbb42bbd8d44aeb7abe7231261a94268710f30cb31c` |
| `embedded/pngstore_authority_test.go` | 72 | `87f0f17ffc77d71a9a05a6cab05732184318626019d1a51073030715f71b5e08` |
| `embedded/pngstore_enrolled_associate_carrier_test.go` | 86 | `d02b28b8692620b76447163626e4de1b683ce8af1483755d71dcebf2b0164038` |
| `embedded/pngstore_enrolled_authority_test.go` | 78 | `97eed4357ec7dc8fd320f038cecbbaf0c9bea232ee4a49fd0e403d8d8d766a91` |
| `embedded/pngstore_enrolled_graph_test.go` | 95 | `23d4cf7236a4ce65120a4e45a3e98cf7dd77553153c6170b758ad6bd6abcdaa0` |
| `embedded/pngstore_exchange_test.go` | 76 | `de4f2d13bf8c2ee51b24253d9876a9026475865854ad922ea66bfeb1ed0379e8` |
| `embedded/pngstore_export_test.go` | 32 | `2cf6489d23b575f6fa894ed3994c993fc92515e646d5bcfdebe2ee08b5ed5bf5` |
| `embedded/pngstore_fixture_test.go` | 110 | `3e37bcec46d5f6323bf85a7a5057dbf2ecd945dadb6eaef1b3dee1569e988b95` |
| `embedded/pngstore_import_performance_test.go` | 59 | `db4d58f0b7572474650e4bea841842ae7da8e7fbcde5be0915bf52567881f231` |
| `embedded/pngstore_profile_test.go` | 56 | `e8438e140d61c17662bcbd13b90a56aeda9f30e354eaabcfef201b745a01038e` |
| `embedded/pngstore_read_templates_test.go` | 71 | `63960f6a0c8d4f0a3ea1c47560fc66fe5ab7794b063c8deb8979a2a43884db5a` |
| `embedded/pngstore_runtime_test.go` | 101 | `286cefd1bd5d708a43f0a7ac54139f264455b2f3de88f65336a4101d98cf23c7` |
| `embedded/pngstore_workload_fixture_test.go` | 174 | `e066e15fd55f7b099c6dacb956d5cff66651fd292bd766f623541a3165a723c1` |
| `embedded/pngstore_workload_steps_test.go` | 89 | `08e026708a1fc7cad6994515999533f84b3204697109a87047baec4346d164eb` |
| `embedded/pngstore_workload_test.go` | 290 | `49b398573030f14ae9a41ea4b2f3c90bd11ad93b2bc84b5d9b8387e5494b3d55` |
| `embedded/testdata/workload_profile.json` | 1 | `8f3f575d694900f1d6b2c4780bad57bf55292727d896c8c26d72733ba8816de3` |
| `ffi/domain_owned_root_test.go` | 21 | `7c04d60b1d4c286445d23da17096940b87d602fbd903eef9da14435167fc2117` |
| `internal/activation_domain_acl_differential_test.go` | 484 | `d3974baa62907257fa57ef9992e2d99caa26861f644668c6dcb8a12a33a9a235` |
| `internal/activation_domain_acl_oracle_test.go` | 177 | `808e86dcedffd1f472563e148a0af3a811b879ac9e168195c5dc8e5c20514888` |
| `internal/activation_domain_acl_reference_test.go` | 208 | `1c0ecf78d5513609f37f6740ff52ff8df63e00b759f2dff9141c2c75b2819f93` |
| `internal/activation_domain_close_test.go` | 55 | `1e97a4ad9868d8b3a68ce249667bbd5ae5c256bb768596e159f97a2c6fe56aa6` |
| `internal/activation_domain_empty_test.go` | 28 | `83ce315b4e446ae19c20e9198fd29f93bdad531e8c29777358aae0e6455373ac` |
| `internal/activation_domain_engine_test.go` | 175 | `76605aa9a05689d34c908b15967caaaa8da6bcb0c334fe195b7d0098622f0509` |
| `internal/activation_domain_evaluation_clone_test.go` | 74 | `6ffd96ed050afbc4100db467089f36fcf786d080335097ad91ef20803d3a3c70` |
| `internal/activation_domain_evaluation_fields_test.go` | 36 | `2992555b95116f32b028c6e8a77ad782c7d7b70469eb8a6d32887e216493c1f2` |
| `internal/activation_domain_evaluation_fixture_test.go` | 118 | `b28dc3a07b0d147cc1699977152ffee7c7c2fa5971e56ca515df4eee54563ef1` |
| `internal/activation_domain_evaluation_guards_test.go` | 97 | `b91b231901d6067e24a418e89e5d173c67642ca7f23d55345d5859da8aa87d0b` |
| `internal/activation_domain_evaluation_test.go` | 117 | `a674f7c30a86748a811ab95083d1f3cfbafed489a052cc93f0063027836612e9` |
| `internal/activation_domain_fixture_test.go` | 178 | `262b99bd23b4d3b5329cb67a07e711aea604b065ea4b67412c124e634c5aa6da` |
| `internal/activation_domain_private_view_test.go` | 45 | `b1af22340e1ef572a734a2a8171866a876e37331eadbaf2a255fd9810822da1b` |
| `internal/activation_domain_receipt_projection_test.go` | 86 | `51b9b6cea89f088845a8137d5164e67796e77cbc97776d538f64271d22b3f6e4` |
| `internal/activation_domain_store_product_intent_test.go` | 69 | `8d557afa2a7dff38a4d42748aa73558edc8349355a64ae1c609a42a3ec73b7c8` |
| `internal/activation_domain_target_input_test.go` | 79 | `0a513596181d7993c267b88d473e308c9672a94125fbf8d085153a6ac614e97d` |
| `internal/activation_domain_workload_actor_test.go` | 181 | `629beb16d6b6b76609a2381db3a3181d3e690e048ad876863577b7e7c212b376` |
| `internal/activation_domain_workload_contract_test.go` | 65 | `1a8cb3654b4e0832f3c16000559f280dd2df670649580501f70a85d43eaf7d7a` |
| `internal/activation_domain_workload_delta_test.go` | 131 | `e7652f4cf3de560fd0b0993e9f65ffff36d44ec647769cc881737889e3b0f104` |
| `internal/activation_domain_workload_fixture_test.go` | 160 | `f64478da4ad041bc0acd3dfef446acefd5fc3b9b997067689270060a003afa25` |
| `internal/activation_enrollment_acl_reference_test.go` | 378 | `c896b9054cce52e66d873f97c8f8efd9f04fcaa40a6055d7ffb75c2648efc493` |
| `internal/activation_enrollment_administration_security_test.go` | 172 | `065ae694341886616c31ba93641bf4064e8989dbfa6d7189503d63e3b4d0e897` |
| `internal/activation_enrollment_administration_test.go` | 145 | `072c137373b3497f6eb3dd27ad0926ee2916caa493c3f5f81b4313db49f49b1f` |
| `internal/activation_enrollment_associate_carrier_test.go` | 250 | `510527089b871154f114730eadeaab11d9c78cbe3f558238dbcfc0d6ce344af1` |
| `internal/activation_enrollment_contract_test.go` | 126 | `4937916bb011678495605f12ba22b5f926ddb78c416a06492d9312f5f15aeea7` |
| `internal/activation_enrollment_fixture_test.go` | 226 | `cd9f42b0eeab7ff612f9cdc443f51afd90189761e9fbc833ab13d7d6539acaa8` |
| `internal/activation_enrollment_flow_test.go` | 131 | `bf498f152b4b0e9d61706cf35f6ee39db2c79d2b364b0368d384db087ceea9c7` |
| `internal/activation_enrollment_recovery_test.go` | 141 | `47c209df0a84d65d1a2f8f5de7ca1c3513064f6d91a59a59a6b583cf802c4583` |
| `internal/activation_enrollment_security_test.go` | 96 | `8424ffa8ad7efb7e4a1834527de7368f5c9896e97c72e5e9457d7a866cef0ce3` |
| `internal/activation_enrollment_session_test.go` | 70 | `5cec7e193f64826ba03a9927a9766c8b133306cfa1a9fbf198045d399c8ef3fe` |
| `internal/activation_enrollment_workload_admin_test.go` | 134 | `e7632b27e86fff32423bc390a24060b64bf6c030610acfca61e0c13fc414bc99` |
| `internal/activation_enrollment_workload_test.go` | 472 | `9009ebdceae61fdb9bf6e6e4f4937b50365f4227b47ed4884690f52fcb5ccc89` |
| `internal/activation_source_fence_test.go` | 98 | `e86566b97a51c3885578d6f52432ecb5b949220b576f34f1e198b52dfc24b84f` |
| `internal/activation_source_legacy_test.go` | 148 | `f3935da5ca7b95902df73e0101703c56087af0c1d1e6d3df64952592f75bf016` |
| `internal/domain_fixture_owner_test.go` | 154 | `51ed142d72036b657765cee7779e7709c7399333aeecb2f720845f43feffc4b6` |
| `internal/domain_snapshot_cache_race_test.go` | 60 | `2b48aab6985e5a311134ea7c15ff845469f138e75e50a7a600388e346cfcbaa0` |
| `internal/domain_snapshot_cache_receipts_test.go` | 34 | `802682c29da25c53d8fe783bc5ef9ae059edc3439d9b28ef73303bb0760ff349` |
| `internal/domain_snapshot_cache_test.go` | 126 | `6bdea300780654dbe94ffb36cb99127c9d0a30c34699190e225a1259e75f804c` |
| `internal/domain_snapshot_cache_views_test.go` | 114 | `945718e23f9592f9bcf80a254540656a1ba5b5176cad0417122c0004205ce0f2` |
| `internal/staged_clone_structured_test.go` | 50 | `701d1c68ec7411a4bc3fa5a2601228a5bb3e0e5524b55e7ef5362d931c5b2111` |
| `internal/staged_durability_test.go` | 143 | `d0e4b2fc4a084496f034f3ff51e567532c107f79d95561af603e23f429b90e69` |
| `internal/staged_engine_test.go` | 186 | `efcb9cc6c90c148cfe9e7761bf5bc41a091b6fa56aa6517c406e67609a5a2765` |
| `internal/staged_isolation_test.go` | 193 | `45035c3fe2c9481bd2a1c7730ff518e313665938f31e0b81f06433af54115b2d` |
| `internal/staged_reopen_bounds_test.go` | 99 | `6c64650d4d0bfd6c295f09df730e59f6c3bdcc9be97ef9b1e2412f5c0584d85d` |
| `internal/staged_restart_test.go` | 81 | `d13025d97880093de1d9eadaf20a61c1ec29b6469d348c698c988819f1c1fab0` |
| `internal/staged_test_helpers_test.go` | 124 | `08a6f533eb2a49f91afd0389fad55c37b6ef8909e9f2419ae79d8570f083db70` |
| `products/manifest/receipt_projection_test.go` | 23 | `d4fc345afb160480be3699da8001f94602a1cc67ba00628a5272f27999b5fabb` |
| `products/pngstore/associate_carrier_test.go` | 241 | `9998d617dc04d82127b032651a0f5efc3073f1bf3de45cdba9b0b3327eb0dd2c` |
| `products/pngstore/receipt_projection_test.go` | 30 | `d3ea6bf8b52c3b3546c4edb5c877f480508d71eb6ac2e706b9e7c33616e50a65` |
| `products/pngstore/store_test.go` | 106 | `33aeb22303e2154ca4d2e60d402a42b8abb7dff6e480a05f1ae22f7eeae39b68` |
| `products/pngstore/target_input_test.go` | 48 | `b859ee1a054ca7ae72ad73cb03a61a74f0ab7f2e36ed65ae55e4322ecf0d43f2` |

