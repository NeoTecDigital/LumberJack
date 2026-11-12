<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Handoff: `product/momentum-auth` (Momentum second factor)

This branch is LumberJack `main` at the cut commit `da93661` (`main` `d18f3e7` plus the design and the
compatibility fixtures), with this file added. The whole tree is here, unchanged, so the product
builds and its tests run exactly as they did. `main` removes this code at P3b-4
(`docs/extension-api.md` §8) and does not port, maintain or fix it. The design this hands off
against is `docs/keep-move.md` and `docs/extension-api.md` on this branch.

## What it is

Momentum's second factor: TOTP, WebAuthn passkeys, QR login, verified email and recovery
(`account_security*`), SMS codes with delivery and resend (`application_mfa*`), the admin MFA route
(`api_user_mfa.go`), the `core.AccountSecurity` and `core.MFAChallenge` types, every `MOMENTUM_*`
variable (`account_security.go:18`, `account_security_passkey.go:40-41`,
`account_security_handlers.go:165`) and the `momentum:login:` QR literal.

## Seams it used in the old engine

| Call point (at the cut) | What it did |
|---|---|
| `api_auth.go:142` `beginAccountLogin` | after a verified password, minted a challenge instead of a session |
| `api_auth.go:347` middleware | `/account/*` and recent-authentication checks |
| `api_auth_lockout.go:106-118` | the phone-last4 gate, `securityMethods`, `requireAccountMFA()` (true unless `MOMENTUM_REQUIRE_MFA=false`) |
| `application_session.go` | `handleApplicationSessionMFA` and the browser MFA branch of POST `/session` |
| `api.go` routes | `/mfa/verify`, `/mfa/start`, `/mfa/delivery`, `/auth/factor`, `/auth/webauthn/finish`, `/auth/qr`, `/auth/qr/poll`, `/account/security` (GET, POST), `/account/webauthn/begin`, `/account/webauthn/finish`, `/account/qr/approve`, `/users/mfa`, application `/session/mfa` |
| `application_hub.go` `outbound_ack` / `outbound_failed` | wrote delivery marks onto `MFAChallenges` |
| `CorrespondenceState.Outbound` | enqueued SMS codes for the hub's outbound forwarder |
| `application_credential_epoch.go` | retired sessions when the factor changed |

## Public extension seams that replace them

| Old call point | Seam (`docs/extension-api.md`) |
|---|---|
| `beginAccountLogin`, the browser MFA branch, the lockout-file factor checks | `extension.SecondFactor.Required` / `AfterPassword` returning a `Challenge` (§4.4) |
| `phone_last4` and other login body fields | `extension.Login.Extras` |
| issuing the session after the factor | `extension.Sessions.Issue`; failures through `RecordLoginFailure` / `ClearLoginFailures`; epoch bump through `RetireCredentials` |
| the MFA and account routes | `extension.RouteProvider` (`Access: Public` for the pre-session exchanges, `BackpressureExempt` for credential exchanges) |
| SMS enqueue | `extension.Tx.EnqueueOutbound` (§4.6) |
| delivery marks | `extension.OutboxListener.OutboundSettledLocked` |
| `account_security`, `mfa_challenges` | root slot keys (§4.5) |

Built into `main` (Q1(a)): with no `SecondFactor` registered, a password login of an account with
`users[].mfa_enabled`, or whose id is a key of the root's preserved `account_security`, answers 401
`second factor required` and is not counted as a failure.

## FFI exports it takes

None. Its routes are reached through `ic_lj_application_call`.

## What a product must do to rebuild on the extension API

1. Implement `extension.Extension` with `Spec{Name: "momentum-auth", Slot: {RootKeys: [{Name: "account_security"}, {Name: "mfa_challenges"}]}}` and codecs that decode with `UseNumber`.
2. Its `Instance` implements `SecondFactor`, `RouteProvider` and `OutboxListener`.
3. Read `MOMENTUM_*` settings in the product's own configuration; the engine reads none.
4. Link it into the product archive with `abi.Register`.

## State it owns in existing stores

| Key | Level | Without this extension registered |
|---|---|---|
| `account_security` | root | preserved as an unclaimed slot key; **password login refused** for every user id present |
| `mfa_challenges` | root | preserved; inert |
| `users[].mfa_enabled` | user field (stays typed in `core.User`) | **password login refused** |
| `correspondence.outbound` items it enqueued | outbox (generic) | still drained by the hub; no listener marks them |

## When it left `main`

`finalize/split` commit `5799df4` (P3b-4), except `internal/core/account_security.go` and
`internal/core/mfa_challenge.go`, which held `core.Node`'s typed fields until the slot codec replaced
them in `7386fc6` (P3b-8, deviation D7). From then on `account_security` and `mfa_challenges` are
root slot keys, kept as their bytes.

## Tests that left from shared files

These were in files that stay on `main`; they test this product and are here, at the cut:

- `internal/application_credential_epoch_test.go`, whole: enrolment through `/users/mfa` retiring
  sessions, refresh tokens and live challenges.
- `internal/application_hub_delivery_test.go`, whole: delivery marks on `MFAChallenges`.
- `TestHubOutboundFullPathLoginToAck` in `internal/application_hub_outbound_test.go`.
- `TestPhonePromptPreservesFailureBudget` in `internal/application_idle_test.go`.
- `applicationMFALogin` in `embedded/application_auth_fixture_test.go` (the TOTP enrolment a bare
  engine forced); `main` signs in with a password (`applicationLogin`).
- The `MOMENTUM_REQUIRE_MFA=false` setting in `internal/api_test.go`'s `TestMain`.

## Files and lines

11 non-test Go files, 1912 lines; 9 test files and test data, 1763 lines. Tests leave with the code they test. `sha256` is of the file at the cut, in the format of `docs/activity-source-import.jsonl`.

### Source

| Path | Lines | sha256 |
|---|---:|---|
| `internal/account_security.go` | 266 | `809b9e4f02d273ef6da9600f9e80217a45f988690108a69a9ba07748c8d541b2` |
| `internal/account_security_handlers.go` | 334 | `e925e2a06745ecc8464d3979737ae2482a67f82c10f0a33df0ab8eb43edb525e` |
| `internal/account_security_passkey.go` | 211 | `64deaa91773043fde83a584cbd605d67d80851a707048394397f388bf234d5cc` |
| `internal/account_security_qr.go` | 119 | `e55e0664540d2887b5884779e35a52a7f6495a13010d8c954b9fe9b9a1330d3c` |
| `internal/account_security_recent.go` | 30 | `383dde70dfb814f70f03dd922eae07f163093eb90bf34136c46955b5739f4fbc` |
| `internal/api_user_mfa.go` | 127 | `85593c8ef0cdb680aa36c18d0ab159432d92d50cc3cf612b2226415f90844681` |
| `internal/application_mfa.go` | 466 | `2e100585cd0b3a5b74e41f14943014cbedd26cf5c3eaf5a7a8db38e652ca87bb` |
| `internal/application_mfa_delivery.go` | 151 | `b6cb3ae515bda479e2979f9231765ce26438af41ef9c8aa65db79d9c9ec895ef` |
| `internal/application_mfa_resend.go` | 135 | `890bdc2a8fd201c1a48bbafbbfdb2ecd65688ad5c0dc1aa7524ec017acca609f` |
| `internal/core/account_security.go` | 22 | `18fa36de92ba224aa0641906755d0a74c07da85050f47568c653cd707978f0ce` |
| `internal/core/mfa_challenge.go` | 51 | `ba357aefd9eaea7b8de3c299637cfbc8fa368b12358b0822883a60ee0934d3bf` |

### Tests and test data

| Path | Lines | sha256 |
|---|---:|---|
| `internal/account_security_boundaries_test.go` | 69 | `c7e45cfc7e9ea272fbe8654b70b7cef6e1de5f40118e02489b79e2f2b8aff867` |
| `internal/account_security_reauthentication_test.go` | 79 | `cf98d41c5695b6bb212cea3051da34792146d6f325641cdc0ba3c46852dc3820` |
| `internal/account_security_test.go` | 41 | `aed4042d416526a41712907108a7432cd26ce4875950bb339bb91b2beb06bba6` |
| `internal/api_user_mfa_test.go` | 239 | `fc7c78c6f29c8d457b89610def84a13b7e1bbe4d6a7d04b0615b614009288d25` |
| `internal/application_mfa_delivery_test.go` | 170 | `59b5f5e55e714900cd5228ba8ceb5df5a43ab52b453d8bd2bd50add88407c34a` |
| `internal/application_mfa_resend_test.go` | 376 | `b94ad3570016f4873c222ba101a097ccdb5d6398b91f319b9389c1cbda613691` |
| `internal/application_mfa_test.go` | 439 | `947c5249bf4d20ef2a6b4b5bf903f7d741f6d235e129c86f0e706a5a989baa6a` |
| `internal/application_session_mfa_test.go` | 226 | `d5974b005ff378db6d5a0baa9d112127481b1d8a8d2905fffe069c41900859b7` |
| `internal/seed_mfa_outbox_test.go` | 124 | `5a4bcff530bc8359ab9e5ce64cea183bd8f755a59ab2ebe56a077ce4aeaf95fb` |

