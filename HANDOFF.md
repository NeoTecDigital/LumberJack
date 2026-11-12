<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Handoff: `product/activity-runtime` (Activity runtime)

This branch is LumberJack `main` at the cut commit `da93661` (`main` `d18f3e7` plus the design and the
compatibility fixtures), with this file added. The whole tree is here, unchanged, so the product
builds and its tests run exactly as they did. `main` removes this code at P3b-3
(`docs/extension-api.md` §8) and does not port, maintain or fix it. The design this hands off
against is `docs/keep-move.md` and `docs/extension-api.md` on this branch.

## What it is

Activity's runtime inside the engine: the Activity header verifier (`activation_*` request
authentication against an Activity authority endpoint), signed session admission (`/session/admit`,
`internal/admission/`, issuer `activity-personal`, audience `momentum-personal`, products
`momentum|manifest` at `admission/verifier.go:141`), the business-scope gate, and the Raft packages
(`replication/`, `peertransport/`, `businessruntime/`), which nothing outside themselves imports
and which encode Activity admissions and products (`replication/types.go:63`). Owner decision Q11(a):
Raft leaves with Activity; a future generic replication is designed fresh.

## Seams it used in the old engine

| Call point (at the cut) | What it did |
|---|---|
| `api_auth.go:347` `authMiddleware`, activation branch | claimed requests carrying Activity headers before the bearer check |
| `application.go:143-153` `ApplicationCall` | `invalidActivationHeaders` / `isActivationRequest` refused malformed Activity headers 401 on the application transport |
| `activation_application.go:30-60` `dispatchApplication` | hardwired `/session/admit` and `/activation/probe` |
| `application_hub.go:300` via `activation_actor.go:17` | `/principal` projection of an Activity actor |
| `ffi/activation.go:19-45`, `embedded.ConfigureApplication` | the `activation` and `admission` parts of `ic_lj_application_configure` |
| `types.go` `Server.activation`, `Server.sessionAdmission` | per-server verifier and admission state |
| root `admitted_commands` | single-use ledger of admitted command ids, written in the same snapshot as the session it paid for |

## Public extension seams that replace them

| Old call point | Seam (`docs/extension-api.md`) |
|---|---|
| header claim in `authMiddleware` | `extension.RequestAuthenticator.AuthenticateRequest` returning `NotMine` / `Accepted` / `Refused` (§4.4); a `Refused` claim never falls through |
| application-transport header refusal | `RequestAuthenticator.MalformedHeaders` |
| `/principal` actor projection | `extension.Principal.Projection` |
| `/session/admit`, `/activation/probe` | `extension.RouteProvider` routes with `Transport: Application` (§4.3) |
| `activation` / `admission` config parts | `extension.Spec.ConfigParts` + `extension.Configurable.Configure` (§4.7); an undeclared part is refused `LJ_INVALID` |
| minting the admitted session | `extension.Sessions.Issue` (§4.4) |
| `admitted_commands` | a root slot key declared in `Spec.Slot.RootKeys`, read and written only through `ReadTx.Slot` / `Tx.SetSlot` inside `Host.Change` (§4.5) |

## FFI exports it takes

None of its own. It consumed two parts of `ic_lj_application_configure` (`activation`, `admission`).
A product archive that links Activity registers it with `abi.Register` so those parts are accepted.

## What a product must do to rebuild on the extension API

1. Implement `extension.Extension` with `Spec{Name: "activity-runtime", ConfigParts: ["activation", "admission"], Slot: {RootKeys: [{Name: "admitted_commands"}]}}`.
2. Return an `Instance` that implements `RequestAuthenticator`, `Configurable` and `RouteProvider`.
3. Verify the signed admission in the route handler; record the command id with `Tx.SetSlot` in the
   same `Host.Change` that calls `Sessions.Issue`, so a restart cannot reopen a replay window.
4. Build a product archive (`docs/extension-api.md` §6): the generated base wrappers, plus
   `init() { abi.Register(activity.Extension()) }`.
5. Raft is not rebuilt: it is designed fresh if replication is wanted again.

## State it owns in existing stores

| Key | Level | Without this extension registered |
|---|---|---|
| `admitted_commands` | root | preserved byte-for-byte as an unclaimed slot key; inert (no admission is accepted) |

## When it left `main`

`finalize/split` commit `03645b9` (P3b-3), except three files the domain engine built its verifier
from — `internal/activation_config.go`, `internal/activation_protocol.go`, `internal/activation_json.go`
— which stayed, trimmed of Activity's engine API, until `bf5040b` (P3b-7), and
`internal/application_business_scope.go`, which the workspace's message operations read until
`254c0be` (P3b-5). `endApplicationSessionLocked` (sign-out ends a delegated session's family) was
generic and moved to `internal/application_session.go`. Deviations D4, D5 in
`docs/extension-api.md` §11 on `finalize/split`.

## Tests that left from shared files

None beyond the test files listed above.

## Files and lines

23 non-test Go files, 2570 lines; 20 test files and test data, 2837 lines. Tests leave with the code they test. `sha256` is of the file at the cut, in the format of `docs/activity-source-import.jsonl`.

### Source

| Path | Lines | sha256 |
|---|---:|---|
| `embedded/activation.go` | 30 | `c3a04071c629f21610ec0ae55ce297904feaf7378d91aabd593cd5f550a772c8` |
| `embedded/session_admission.go` | 28 | `6d768b32ef3763dd1357dfef2e83bc0c4b7bd4613bf41bcd4ca5230ec7bbfdf2` |
| `internal/activation_actor.go` | 39 | `fb8b98da73add5f5b54ed2ab85b812c16d5413e8756a6d4e1adde67b0ca21084` |
| `internal/activation_auth.go` | 114 | `2a75044d561d7029a5ce8b31a4fa7f8a82061c6d7b5369f5f7585340109c1b7a` |
| `internal/activation_config.go` | 133 | `19eaf37d11207b62606e5f9600c86892be1ad542e8b311fc8f8e2c25b577c350` |
| `internal/activation_json.go` | 106 | `cc6e689fa63af0565962e7da376ab513507502c515df9458f45f1063fa6de262` |
| `internal/activation_protocol.go` | 121 | `2460ca08908bef0620866c5b464eef413211b576b467d0a1abf688238f31d11b` |
| `internal/admission/session.go` | 41 | `cb857e95de06230d1960ea1c931a9cb4df175b0bd21f44afbbe16b85eaf2d15a` |
| `internal/admission/verifier.go` | 196 | `1603b06698766646f4379ef35033831edbe324e5206c7c9fd6f1331a22e4b0d5` |
| `internal/application_business_scope.go` | 30 | `d2523de211030df8db48d94b5a78d2544051441b03ab20c26b89128573db7fd5` |
| `internal/application_session_admit.go` | 317 | `6f71185c6d6549e7032d7fb23690ac3a5bc77f3af4208ae9e17cc85e4996c8f3` |
| `internal/businessruntime/README.md` | 55 | `9463b48b325a93a9b4fe9fddf83359d9fce02bb1e66943b89a5196542fdc6244` |
| `internal/businessruntime/barriers.go` | 96 | `a96592ae2c244f511107829dbaaeb808c237704d60615c0915de2753498265ed` |
| `internal/businessruntime/runtime.go` | 115 | `1cbf015c80c1f74695eee8328520695b4bbbe1b9bded47bab7e311c025233a63` |
| `internal/businessruntime/types.go` | 73 | `1442decefec93bdbc1bcfd5ff9f607c3475f0de50d0c437dd161176f70636a6d` |
| `internal/peertransport/README.md` | 62 | `a472836ef4da850b9b9af680fc58443b668891577fcad433c623a8ca2294e271` |
| `internal/peertransport/config.go` | 149 | `b1aae78d3a4fff79867af9bf18e0d3691125d0cf7dab038d8756444fbee61e93` |
| `internal/peertransport/stream.go` | 164 | `270693d9c8d9ada7acdc40d99fc56a367431bf7fc862c9c0dd67dda1233bd5c4` |
| `internal/peertransport/transport.go` | 92 | `e21f879dc0aacf46c178223129e707ca113cbe32e26e435e43441fe6cdd735e8` |
| `internal/replication/README.md` | 30 | `36a4e7d8001d8e53bbc767965c222781aac75ca49276b99d7e1f626e01edebf4` |
| `internal/replication/fsm.go` | 157 | `9152f77855d262d5a359b7624cddaf6bfee268644efff2082dd72af71400b09a` |
| `internal/replication/lock.go` | 29 | `38f828d759e94f7c6c58cf20cf68e3ae9441a169971b460084eb29bcfdc6f320` |
| `internal/replication/node.go` | 175 | `951d062c5f143f2ac280e419f1a00bba7cffb117167ca2a63778bfb47aec6d10` |
| `internal/replication/snapshots.go` | 93 | `75a3e86b7817757dc22fecf1c22ee9515acf726e8c46a2fe855cbc5b8c4fb11d` |
| `internal/replication/storage.go` | 190 | `ef39555688969aea5289dfa992c464efbc7e657db0c348b719d76c5e9a79d6c0` |
| `internal/replication/types.go` | 82 | `299415de8c9d43ed79d7ac78afe5df5866992fefe0cb0822c9d1890784a180bc` |

### Tests and test data

| Path | Lines | sha256 |
|---|---:|---|
| `embedded/activation_test.go` | 48 | `dbffaf43b3845e923b9bfba9fbcb2374ce0ccc6d3c64f8d9942211edeea206b7` |
| `embedded/momentum_session_admit_test.go` | 118 | `f3185b4fd94e23c695a2cdaa28c1a35e9341bf9e6f7f7b051d8c251434db3f61` |
| `ffi/activation_admission_test.go` | 44 | `2592d8c0002570ebcccc178c7134d9236d599589fe6a4120a460543de7e70dc6` |
| `internal/activation_auth_test.go` | 141 | `f6c34b47226426e4df63194aee971b9cc576d1f5af6a1175b9a7c20a974f2221` |
| `internal/activation_fixture_test.go` | 109 | `abedfefabb560735988a275b9bbe8b735e2e7e8d470ebf28477c3181db82d6d4` |
| `internal/activation_local_human_test.go` | 140 | `bcc48f6a5bd65b572d3b87c9f2db6808740bd6c5e00c3f0a2714781c59935388` |
| `internal/activation_security_test.go` | 190 | `da4cb87481a64fecf7833bc112079dbf8a23a7bc7ec37dde3f4cb5934ca9f372` |
| `internal/activation_tls_test.go` | 41 | `744b2ba84a360d1ed2fef36377753efb4f8793366cb84e546fd86a29dcdfdd67` |
| `internal/admission/session_test.go` | 186 | `a32ffda6a82120e3ec7da310900c796572e8196a5cb0c4f05e63ec7a40a7b66c` |
| `internal/admission/testdata/session_vector.json` | 74 | `03452aef0f97a3b16bd8eb7cbfd47792eeac806e2ef134d510b2e15895a6923f` |
| `internal/admission/verifier_test.go` | 124 | `9559728948d2120c35027f64ca4f53d6b3d443ad51784081174b3e4c0ad4f809` |
| `internal/application_activity_atomic_test.go` | 113 | `bd5761c521673da1cd6a4e1722c7ad5bce8e308b73d441a00fdcb2a1ff1ab5b4` |
| `internal/application_session_admit_profile_test.go` | 272 | `e721a7dce30475b48618beafb0a13787d2c0a265d68683dcc9c5ea9af6cb2c8a` |
| `internal/application_session_admit_test.go` | 489 | `59f55d67f61ffb05ccacad7df1796f7794fecef91d1d0e1b638d46f28c7c88c3` |
| `internal/businessruntime/runtime_test.go` | 148 | `8e8bcd82c808e3cc474825b0085458c7cb6dc39016838f3bff9f4ce19dc30258` |
| `internal/peertransport/config_test.go` | 83 | `483c62c5906e00324fe23286b83ee7641a8d6cc55ce8475373e851deb8bb6d60` |
| `internal/peertransport/fixtures_test.go` | 117 | `be50a90bf8dc74d737f38b236294f56cf60cef037cf59f3a2f8c8d7bd705bcd9` |
| `internal/peertransport/lifecycle_test.go` | 67 | `90935b3618c6defc7e240499c6347b57a473516eae534093fac5a14e308a210e` |
| `internal/peertransport/transport_test.go` | 169 | `44e420950756dd9f2e01ab625ff92498d83b6b43f7684e372e1c6bb64b18c3c8` |
| `internal/replication/replication_test.go` | 164 | `750ccea21ec86283d0f2b954b6cc5317b4c8547be9fb666afe307e781be1998c` |

