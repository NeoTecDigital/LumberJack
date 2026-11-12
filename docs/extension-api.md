<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Public extension API

Status: design for owner review, against `main` at `d18f3e7`. No source has changed. The
classification it serves is in [keep-move.md](keep-move.md).

## 1. Scope

LumberJack `main` keeps the generic store and exposes the seams products can later rebuild on. A
seam is admitted only if:

- the generic engine itself needs it or exercises it;
- it has a generic test that uses no product code;
- it carries no product logic.

Products are not ported. Each is preserved on its `product/*` branch with an inventory.

What is not a seam (§9): the owned-scope snapshot overlay, durability pairs, `DomainProduct` and
the Activity wire protocol. Products rebuild these on top of the seams below if they still need them.

The extension set is known at Open and fixed for the life of a runtime. That makes it static
configuration, not runtime discovery ("know it early, lock it down").

## 2. Packages

| Package | Visibility | Contents |
|---|---|---|
| `github.com/NeoTecDigital/LumberJack/core` | **public** (promoted from `internal/core`; Q2) | the data model: `Node`, `Event`, `Entry`, `User`, `Attachment`, `Permission`, `AccessGrant`, `ApplicationSession`, `Outbox`, `OutboxChange`, `OutboundMessage`; the record codec (§7.1) |
| `github.com/NeoTecDigital/LumberJack/extension` | **public** | the interfaces below; it imports only `core` and `types` |
| `github.com/NeoTecDigital/LumberJack/embedded` | public (exists) | adds `OpenWith(config, principal, exts...)` |
| `github.com/NeoTecDigital/LumberJack/ffi/abi` | **public**, cgo | base export implementations on Go types, the handle table, `Register(exts...)` (§6) |
| `internal` | internal | the engine; it imports `extension` and calls it at the call points below |

`internal` importing `extension` creates no cycle, because `extension` never imports `internal`.

## 3. Registration and lifecycle

```go
package extension

// Extension is registered at Open. Spec is read once. Attach runs once per runtime (per forest),
// after the state is loaded and before the first request, with no forest hold.
type Extension interface {
	Spec() Spec
	Attach(host Host) (Instance, error)
}

type Spec struct {
	Name        string      // stable, [a-z0-9-]+; namespaces grant ids, config parts, errors
	Slot        SlotSpec    // persisted keys this extension owns (§4.5)
	Markers     []string    // CommandReceipts keys that mark a node as owned by this extension
	ConfigParts []string    // application_configure parts it consumes, e.g. "admission"
	Persistence Persistence // AnyPersistence | SnapshotOnly (refused under tiered persistence)
}

// Instance is the per-forest object. It may implement any of the optional capability interfaces
// in §4. The engine type-asserts each one once, at Attach.
type Instance interface {
	Close(ctx context.Context) error // forest unheld; after it returns, no Host call may arrive
}
```

```go
package embedded

func OpenWith(config Config, principal string, exts ...extension.Extension) (*Handle, error)
```

Rules enforced at Open, each with a generic test:

- Names are unique.
- Slot keys, markers and config parts are disjoint across extensions and from engine keys.
- At most one `PermitProvider` (§4.1).
- A `SnapshotOnly` extension under tiered persistence is refused. This generalises
  `refuseWholeStateWriterUnderTier` (`persistence.go:157`).
- A runtime is shared per canonical state path (`embedded/runtime.go`). A second `OpenWith` of the
  same path with a different extension set is refused with `LJ_CONFLICT`.

Close replaces `domainLifetime`/`sourceLifetime` (`embedded/runtime.go:33-35,155-180`):

1. Mark the runtime closing.
2. Release `registryMu`.
3. Call each `Instance.Close` in reverse attach order.
4. `server.Shutdown`.
5. Release the flock.
6. Delete from the registry and signal waiters.

## 4. Seams

### 4.1 Write path: permit provider and write hook

Today `changeForest` (`forest_lock.go:131`) calls `sourceFence().beginOrdinaryWrite` (`:158`), and
`runChangeLocked` (`:220`) brackets the change with staged protection, outbox capture and the grant
refresh. Both are hardwired.

```go
// PermitProvider is consulted on EVERY write, ordinary or extension-issued, before the forest is
// taken. At most one per runtime.
type PermitProvider interface {
	Acquire(ctx context.Context, op WriteOp) (Permit, error) // error: write refused, no effect
}

type Permit interface {
	// WantsRevision asks the engine to compute the whole-forest revision before the change and
	// again after a refusal. Only an exclusive provider may ask: Unchanged means nothing if
	// another writer could interleave.
	WantsRevision() bool
	Settle(Outcome) // exactly once, with no forest hold and no writer mutex held
}

type WriteOp struct {
	Key    string // the caller's operation identity, e.g. a command hash; engine writes: "engine/<id>"
	Origin string // "" for engine routes, else the issuing extension's Name
}

type OutcomeState uint8

const (
	Refused OutcomeState = iota // the change returned an error under the hold
	Unknown                     // the change was staged but could not be made durable
	Durable                     // on disk (snapshot) or in the hot log (tiered)
)

type Outcome struct {
	State     OutcomeState
	Unchanged bool   // Refused only, and only when WantsRevision: the revision is as before
	Commit    Commit // Durable only
	Err       error
}

type Commit struct {
	Tiered bool
	Seq    uint64   // snapshot sequence, or hot-log sequence when Tiered
	SHA256 [32]byte // the durable snapshot's payload hash (zero when Tiered)
	Path   string   // the state file
}

// WriteHook brackets every change under the exclusive hold, in both persistence modes.
type WriteHook interface {
	BeforeChangeLocked(tx Tx, op WriteOp) (After, error)
}

// After is called with the change's own error, even when that error is non-nil. A non-nil return
// vetoes the change (answered 403 unless it carries an *Error). The hook must restore whatever it
// protects before vetoing; the engine does not roll back.
type After func(tx Tx, changeErr error) error
```

The new `changeForest`, using today's names, with every step mapped to the current line:

```go
func (s *Server) changeForest(op extension.WriteOp, change func() error) (extension.Commit, error) {
	permit, before, err := s.acquirePermit(op)   // :131-169: no hold; revision under RLock if asked
	if err != nil { return extension.Commit{}, err }
	land, err := s.stageChange(op, change)       // takes and releases the exclusive hold
	if err != nil {
		permit.Settle(refused(err, permit.WantsRevision() && before == s.revision()))
		return extension.Commit{}, err
	}
	commit, err := land()                        // disk, with no hold
	if err != nil { permit.Settle(unknown(err)); return extension.Commit{}, err }
	permit.Settle(durable(commit))
	return commit, nil
}

func (s *Server) runChangeLocked(op extension.WriteOp, change func() error) error { // :220
	guards, err := s.ownedGuard.captureLocked()      // built-in (was captureStagedProtectionLocked)
	if err != nil { return err }
	afters, err := s.beforeHooksLocked(op)           // registration order
	if err != nil { guards.restore(); return err }
	outbox := s.captureOutboxLocked()                // was captureCorrespondence, when hub enabled
	changeErr := change()
	if err := s.afterHooksLocked(afters, changeErr); err != nil { guards.restore(); return err }
	if err := guards.verifyLocked(); err != nil { return forbidden(err) } // restores on violation
	if changeErr != nil { return changeErr }
	s.refreshGrantsLocked()                          // GrantSource, §4.4
	s.recordOutboxChangesLocked(outbox)
	return nil
}
```

When no `PermitProvider` is registered, the default permit is a no-op. Today's legacy counter
(`activation_source_legacy.go:27-35`) exists only so the fence can wait out legacy writers, so it is
not kept.

Extensions write only through `Host.Change` (§4.7). That routes into this same `changeForest`, so
the domain or personal-source paths that called `beginWrite` + `encodeSnapshotLocked` +
`commitPaired` directly have no equivalent in `main`.

Generic tests:

- `TestPermitAcquiredBeforeHoldAndSettledAfterDurable`: a test provider records `forestMutex` state
  at `Acquire` and `Settle`, and the `Commit.Seq` against the writer's durable sequence.
- `TestRefusedChangeReportsUnchangedOnlyWhenAsked`.
- `TestFailedPersistSettlesUnknown`: uses the existing failing-writer hook from
  `TestChangeForestReportsAPersistThatCouldNotLand`.
- `TestHookVetoRestoresAndIsNotPersisted`.
- `TestHooksRunInBothPersistences`.
- `TestProviderErrorIsNoEffect`.

### 4.2 Read visibility

```go
// VisibilityFilter hides nodes from every GENERIC read. Extension reads through ReadTx are not
// filtered: the owner sees its own nodes.
type VisibilityFilter interface {
	HiddenLocked(n *core.Node) bool // under a shared or exclusive hold; pure, deterministic, O(1)
}
```

`s.hiddenLocked(n)` is true if the built-in owned-marker rule matches or any registered filter
returns true. The built-in rule: `n.CommandReceipts` holds a key in `markers`, where `markers` is
the compat table (`lumberjack.staged.scope/v1`) plus every `Spec.Markers`. It replaces
`isStagedNode` at all seven points:

| Call point | Today |
|---|---|
| `getNodeFromPath`, root | `api_helpers.go:35` |
| `getNodeFromPath`, resolved | `api_helpers.go:51` |
| `getFromCache` | `api_queue.go:83` |
| `walkScope` | `query_walk.go:59` |
| `childrenByName` (free function; now takes the filter) | `query_walk.go:93` |
| `forestProjector.project` (projector gains a `hidden` field) | `forest_projection.go:65` |

The built-in **owned-subtree guard** is the write-side twin. It is the product-free part of
`staged_guard.go`:

- closure clone, encoded hash, ancestor links, alias removal, restore;
- keyed by marker-bearing roots, with bounds taken from the marker value when present and an engine
  cap otherwise.

It runs first in Before and last in After (§4.1). An extension's own `Host.Change` is exempt for
the markers it declared, and only for those.

Invariants:

- Pure and deterministic for a given forest state. `getFromCache` trusts `lastHash`, so a filter
  that depends on anything else would make the cache disagree with the walk.
- Never encodes, never allocates per call beyond a map lookup.
- Applied uniformly. Any new generic read path must call `hiddenLocked`, and a sweep test enforces it.

Generic tests:

- `TestHiddenNodeIsAbsentFromEveryGenericRead`: one marker-bearing node, then assert it is absent
  from `/nodes/{path}`, the cache path, `/forest`, `/forest/tree`, `/query`, `/aggregate`, `/events`,
  `/entries`, `/changes` `visible`, the outbox capture walk and `/access` previews. This is the
  generic form of `TestStagedLegacyCacheWalkAndProjectionCannotDiscloseScope`.
- `TestOrdinaryWriteCannotChangeOwnedSubtreeOrItsAncestors`: rename, unlink, delete-ancestor and
  alias cases, each restored and refused 403.
- `TestDeclaringExtensionMayWriteItsOwnMarkedNodes`.

### 4.3 Routes and application routes

```go
type RouteProvider interface {
	Routes(r Router) error
}

type Router interface {
	Handle(route Route) error // refuses a method+pattern the engine or another extension holds
}

type Route struct {
	Method, Pattern    string           // gorilla/mux pattern
	Handler            http.HandlerFunc // principal via extension.PrincipalFrom(r.Context())
	Access             Access           // Session (default) | Public
	Transport          Transport        // HTTP | Application | Both (default Both)
	BackpressureExempt bool             // a credential exchange that must not be stranded
}

// Error is how a handler or a Change answers a status. It mirrors internal apiError, which the
// engine maps it to (forest_lock.go:44-81).
type Error struct {
	Status     int
	Message    string
	RetryAfter string
}
```

Call points:

- `routes()` (`api.go:345`) registers in a fixed order:
  1. the engine's fixed routes;
  2. extension routes;
  3. the engine's catch-alls `/nodes/{path:.*}` (GET, PATCH `/metadata`, DELETE) and `/stream`.

  Gorilla matches in registration order, and today's comments (`api.go:445-458`) pin why the
  catch-alls go last.
- `dispatchApplication` (`activation_application.go:30`) becomes a table:
  - the engine's application routes (`/session`, `/session/activity`, `/principal`,
    `/notifications`, `/changes`);
  - plus every `Transport: Application|Both` route;
  - then the HTTP mux.
- Backpressure (`application.go:165-171`) exempts routes flagged `BackpressureExempt`, plus the
  engine's `/session`, `/login`, `/refresh` and `/changes`.

Invariants:

- Session access by default: a route is behind `authMiddleware` unless it says `Public`.
- No shadowing of engine routes.
- Application-only routes never appear on the HTTP mux.
- Writes go through `Host.Change`, so a 2xx is never answered for a change that is not durable.

Generic tests:

- `TestRouteTableIsUnchangedWithNoExtensions`: a golden list of method+pattern+access from
  `routes()`.
- `TestExtensionRouteCannotShadowOrPrecedeCatchAll`.
- `TestApplicationOnlyRouteAbsentFromHTTP`.
- `TestPublicFlagAndBackpressureFlag`.

### 4.4 Authentication and permission

```go
// RequestAuthenticator claims requests carrying its own credential type, BEFORE the engine's
// bearer check (api_auth.go:347). Activity's header verifier is one.
type RequestAuthenticator interface {
	AuthenticateRequest(r *http.Request) (Principal, Claim)
	MalformedHeaders(headers map[string]string) bool // the application transport refuses these 401
}

type Claim uint8

const (
	NotMine  Claim = iota // engine continues with its own bearer check
	Accepted              // Principal is authenticated
	Refused               // the credential is this authenticator's and invalid: 401, no fall-through
)

type Principal struct {
	UserID     string         // what handlers see as the caller, as user_id is today
	Projection map[string]any // what GET /principal answers; nil = the engine's {id, username, admin}
}

// SecondFactor runs after the engine has verified the password and counted the attempt.
type SecondFactor interface {
	Required(tx ReadTx, user core.User) bool
	AfterPassword(ctx context.Context, user core.User, login Login) (*Challenge, error)
}

type Login struct {
	Transport string                     // "bearer" (/login) or "browser" (POST /session)
	Extras    map[string]json.RawMessage // body fields the engine does not read, e.g. phone_last4
}

type Challenge struct{ Body any } // answered verbatim with Cache-Control: no-store; nil = issue now

var ErrInvalidCredentials = &Error{Status: 401, Message: "Invalid credentials"} // engine counts it

// Sessions is how an authenticator finishes a login. It is the engine's registry, epochs and
// lockout, unchanged.
type Sessions interface {
	Issue(tx Tx, userID string, o SessionOptions) (TokenPair, error)
	RecordLoginFailure(userID string)
	ClearLoginFailures(userID string)
	RetireCredentials(tx Tx, userID string) // the credential-epoch bump
}

// GrantSource materialises access grants onto nodes, under the exclusive hold, in the same change.
// The engine's /access policies are the built-in source "access".
type GrantSource interface {
	GrantsLocked(tx ReadTx, now time.Time) (map[string][]core.AccessGrant, error) // nodeID → grants
}
```

Call points:

| Today | Becomes |
|---|---|
| `authMiddleware` (`api_auth.go:347`) | authenticators in registration order, then `serveLegacyAuth` (renamed bearer path) |
| `ApplicationCall` header check (`application.go:143-153`) | `MalformedHeaders` |
| `handleLogin` (`api_auth.go:142`) and POST `/session` (`application_session.go`) | `authenticateCredential` (generic: lockout, constant-cost miss), then the built-in fail-closed rule, then `SecondFactor.AfterPassword`, then `Sessions.Issue` |
| `api_auth_lockout.go:106-118` (phone gate, `securityMethods`, `requireAccountMFA`) | inside the second factor |
| `/principal` (`activation_actor.go:17` → `application_hub.go:300`) | `Principal.Projection` |
| `refreshAccessGrantsLocked` (`access.go:99`) | loops over sources. Grant ids are namespaced `<source>:<id>`, so a source can only replace its own. `CheckPermission` (`core/node_fn.go:232-253`) is unchanged and stays pure |

The built-in **fail-closed rule**: with no `SecondFactor` registered, refuse the password login of
any account with `MFAEnabled`, or whose id is a key in the root's preserved `account_security`
slot. The answer is 401 with body `second factor required`, and it is not counted as a failure.

Invariants:

- A `Refused` claim never falls through to another credential type.
- A second factor never mints a session except through `Sessions.Issue`, so registry, idle deadline
  and epoch rules hold.
- Grants are additive. Revocation and expiry are honoured at read time by `CheckPermission`.
- Sources may not take the hold or do I/O.

Generic tests:

- `TestLoginWithoutSecondFactorIssues`.
- `TestEnrolledAccountFailsClosedWithoutSecondFactor` (both triggers).
- `TestAuthenticatorRefusalDoesNotFallThrough`.
- `TestSecondFactorChallengeThenIssue`: a test factor holding a code in its slot.
- `TestGrantSourceMaterialisesAndRevokes`.
- `TestBuiltinAccessPoliciesAreASource`: the existing `access_*_test.go` stay green unchanged.

### 4.5 Per-forest extension slot

```go
type SlotSpec struct {
	RootKeys   []SlotKey // top-level keys on the root's node record, e.g. "account_security"
	NodeKeys   []SlotKey // top-level keys any node record may carry
	OutboxKeys []SlotKey // keys inside the root's "correspondence" object, e.g. "feed"
}

type SlotKey struct {
	Name  string
	Codec Codec // nil: the extension sees json.RawMessage
}

// Codec decodes once on first access and encodes only when the value was set since load.
type Codec interface {
	Decode(raw json.RawMessage) (any, error) // must preserve numbers (decoder.UseNumber)
	Encode(v any) (json.RawMessage, error)
}
```

The storage is unexported in `core.Node` (`ext slots`) and `core.Outbox`. Each key holds either
the raw bytes read from the file or a decoded value marked dirty. Keys nobody claims stay raw. The
codec in §7.1 is the only writer.

Extensions reach slots only through `ReadTx.Slot` and `Tx.SetSlot`/`DeleteSlot`, so a slot change
is always part of a `Change` and lands in the same snapshot as the data it describes.

Invariants:

- Bytes of a key not set since load are re-emitted verbatim.
- Keys are declared statically, and they are disjoint across extensions and from engine keys.
- Encoding happens under the exclusive hold, in `encodeDocument` as today.
- In-memory product state that is not persisted (registries, leases) lives on the `Instance`, not
  in a slot.

Generic tests:

- `TestUnclaimedKeyRoundTripsVerbatim`.
- `TestClaimedKeyDecodesLazilyAndEncodesOnlyWhenDirty`.
- `TestSlotKeyCollisionRefusedAtOpen`.
- `TestOutboxSlotKeyPreserved`.

### 4.6 Outbox

```go
// On Tx (§4.7). The same snapshot as the change.
//   Enqueue(c core.OutboxChange) error        // was enqueueCorrespondence(actor, WorkCommand, path)
//   EnqueueOutbound(m core.OutboundMessage) error

// OutboxListener learns an outbound item's fate from outbound_ack / outbound_failed, under the
// exclusive hold of that op. This is how a second factor marks its challenge "sent".
type OutboxListener interface {
	OutboundSettledLocked(tx Tx, item core.OutboundMessage, outcome OutboundOutcome)
}

// OutboxEntitlement lets an extension vouch that a recipient is still entitled to a notification
// the generic rule would hide (records without Direct, written before the flag existed).
type OutboxEntitlement interface {
	EntitledLocked(tx ReadTx, n core.OutboxNotification, userID string) bool
}
```

`core.OutboxChange` gains `Direct bool` (`omitempty`), so old records decode as `false`.

The generic `/notifications` rule:

- the recipient still has read permission; and
- `Direct`, or `Operation == "share"`, or subscribed, or an `OutboxEntitlement` vouches.

Generic tests:

- `TestEnqueueLandsWithItsChange`.
- `TestOutboundAckNotifiesListener`.
- `TestDirectFlagReplacesProductLiterals`.
- `TestLegacyRecordWithoutDirectNeedsSubscriptionOrVouch`.

### 4.7 Host

```go
type Host interface {
	Read(fn func(ReadTx) error) error                                          // shared hold
	Change(ctx context.Context, op WriteOp, fn func(Tx) error) (Commit, error) // §4.1, the one write path
	Publish(kind, path string)                                                 // mutation stream; call only after Change returned
	Sessions() Sessions
	Logger() types.Logger
}

type ReadTx interface {
	Root() *core.Node
	NodeByID(id string) (*core.Node, bool)
	NodeByPath(path string) (*core.Node, error) // unfiltered; the owner's view
	Slot(nodeID, key string) (any, bool)
	Permits(n *core.Node, userID string, want core.Permission) bool
}

type Tx interface {
	ReadTx
	SetSlot(nodeID, key string, v any) error
	DeleteSlot(nodeID, key string)
	Enqueue(c core.OutboxChange) error
	EnqueueOutbound(m core.OutboundMessage) error
}

// Configurable receives its named parts of application_configure before the application opens.
type Configurable interface {
	Configure(part string, raw json.RawMessage) error
}
```

`ffi/activation.go:19-45` and `embedded.ConfigureApplication` dispatch each non-empty part to the
extension that declared it. An undeclared part is refused, never ignored, and the FFI answers
`LJ_INVALID`.

A `*core.Node` obtained from a `ReadTx` or `Tx` must not outlive the callback. This is today's
`readNode` rule (`forest_lock.go:267-268`).

## 5. Invariants every seam preserves

| Invariant | Statement | How it is held |
|---|---|---|
| Durability | Nothing is acknowledged, published to `/stream` or answered 2xx before the change is durable (snapshot fsynced, or hot-log record synced). A failed persist is `Unknown`, never `Refused` | `Host.Change` returns only after `land()`; `Publish` is documented as after-`Change`; `Settle(Durable)` precedes the caller's acknowledgement; routes cannot write except through `Change` |
| Permit ordering | `Acquire` happens before `forestMutex` is taken and never under it. Exactly one `Settle` per `Acquire`, after the outcome is known, with neither `forestMutex` nor `stateWriter.mutex` held. At most one provider | `changeForest` shape in §4.1; one-provider check at Open; `TestPermitAcquiredBeforeHoldAndSettledAfterDurable` |
| One write path | Every mutation, engine or extension, in snapshot or tiered mode, passes `runChangeLocked` | `Host.Change` is the only extension write; the tier path already shares `runChangeLocked` (`persistence.go:221`) |
| Lock discipline | `forestMutex` is the one forest lock, taken only by the engine. Hooks, filters, sources, codecs and listeners run under it and must not take it, block, do I/O or call `Host`. Go's RWMutex deadlocks a nested `RLock` behind a waiting writer (`forest_lock.go:36-38`) | documented contract, plus a test build tag that panics on `Host` reentry from a locked callback |
| Disk outside the hold | No seam callback runs inside the disk write | `land()` and `Settle` run unheld, as in `forest_lock.go:131-148` |
| Visibility | A hidden node is absent from every generic read, uniformly | the sweep test in §4.2 |
| Fail closed | Data whose owner is absent is preserved and, where it is security-bearing, closes the door it guarded | §4.2 marker rule, §4.4 login rule, §4.7 config refusal |

## 6. FFI: per-product cgo archives

The header's rule (`ffi/lumberjack.h:16-18`) is one Go runtime per binary. It applies to `dlopen`'d
`c-shared` libraries in one process too. So a product cannot link a second archive beside the
generic one. It links one archive, a **superset**: base exports plus its own.

Build layout:

- `ffi/abi` (public, cgo) holds what `ffi` holds today, on Go types:
  - the handle table (`handles.go`), `take`/`answer`/`guard` (`main.go:91-167`);
  - the codec;
  - the base export bodies as Go functions (`abi.Open(req []byte) (uint64, Status)`, …);
  - `abi.Lookup(h) (*embedded.Handle, bool)`, so product exports resolve the same tokens;
  - `abi.Register(exts ...extension.Extension)`, called from a product archive's `init()`. Every
    later `ic_lj_open` uses `embedded.OpenWith` with that set.
- `ffi` (package `main`) remains the generic archive. Intercessor's `build.rs` and Corresponder's
  `make lumberjack` keep building `./ffi` unchanged. Its `//export` functions become thin wrappers
  over `abi`.
- A product archive is a `main` package in the product's repo, e.g. `manifest/ffi`. It contains:
  - the same base wrappers, generated by `go run github.com/NeoTecDigital/LumberJack/ffi/gen`;
  - its own `//export ic_lj_domain_*` wrappers;
  - `init() { abi.Register(manifest.Extension()) }`.

  It is built with `go build -buildmode=c-archive` (or `c-shared` for Mindfull's Python), giving one
  Go runtime. Its header `lumberjack_domain.h` includes `lumberjack.h` and declares the product
  exports.

Why the wrappers live in each `main` (checked with Go 1.27.2 in a scratch module). An `//export`
in an imported non-main package does reach the archive's symbol table, as `T ic_base_ping`. But the
cgo-generated header lists only the main package's exports. So `make header-check`, which compiles
the hand-written header against the generated one (`Makefile:47-49`), would stop checking
signatures for anything exported from `abi`. Wrappers in `main` keep that check. The alternative
(exports in `abi`, checked only by `nm` and a smoke link) is Q7.

ABI version. Base signatures and statuses are unchanged, so `LJ_ABI_VERSION` stays 2. A caller
built against the old 33-export header that uses a domain export fails to link against the generic
archive, not at run time. That is the header's own rule for "additive" changes run in reverse (Q8).

Checks per archive:

- `header-check` (spec header against generated header);
- `nm-check`: the generic archive exports exactly the 19 base names, and none of the 14;
- `smoke`;
- a `product-archive-example` test under `ffi/testdata/example` that builds base plus one dummy
  export with a test extension. It proves the composition, and that `abi.Lookup` sees handles
  opened by `ic_lj_open`.

## 7. State-file compatibility

The goal: a store written today opens under generic LumberJack and round-trips, with its product
data preserved byte-for-byte. A store written today contains product fields on `core.Node`, product
sections, the STATE-3 banner, staged pairs and `momentum/` sealing labels.

### 7.1 Record codec: legacy key order plus slots

A plaintext state file is `banner ‖ sha256 ‖ gzip(document)`. Each `nodes[id]` is today's
`nodeRecord{*core.Node; Children []string}` marshalled by `encoding/json`. Embedded fields come
first in struct order and the outer `children` comes last. This was checked:
`{"personal_bindings":1,"id":"x","metadata":{…},"created_by":"u","children":["c"]}`.

`core.EncodeRecord`/`DecodeRecord` replace that marshal with a hand-written codec:

- **Decode.** Scan the record's top-level keys, keeping each value as raw bytes:
  - a generic key decodes into its typed field;
  - `correspondence` decodes into `core.Outbox`, with the same scan for its own unknown keys;
  - every other key goes into the node's slot storage as raw bytes.
- **Encode.** Emit keys in the **legacy order table**:

  `personal_bindings, id, type, kind, name, parents, events, planned_events, users, entries,
  attachments, metadata, command_receipts, correspondence, application_sessions, subscriptions,
  conversations, access_policies, access_grants, account_security, mfa_challenges,
  admitted_commands, created_by, created_at, modified_by, modified_at`

  then any other slot keys sorted, then `children`.
  - A typed field is encoded with `encoding/json`, exactly as today, including `omitempty`.
  - A slot key not set since load is written as its raw bytes.
  - A dirty key is written through its codec.
  - The outbox uses its own table: `feed, pending, inbox, delivered, last_delivery, outbound`.

The table is a list of key names and positions. It is product-free in mechanism, and it is the
whole of the compatibility knowledge the codec needs.

Result: an untouched store re-encodes to **identical document bytes**, so the sha256 header is
unchanged too. The writer's unchanged-skip then means the file is not even rewritten.

### 7.2 Numbers

Every interface bag in every node is decoded with `UseNumber`: `Metadata`, event and entry
metadata, and `CommandReceipts`. Today only owned-scope nodes are, or all nodes when the root holds
`personal_bindings` (`restoreStagedNumbers`, `staged_snapshot.go:194-243`).

`json.Number` re-emits its literal, so this is never less byte-preserving than float decoding.
Float decoding is what changes `1.50` to `1.5`, as checked above.

The only generic consumer of numeric metadata is `query_predicate.go:183`, which must also accept
`json.Number`; `%v` already prints its text. Generic tests that assert `metadata["x"] == 1.0` after
a reload will need `json.Number`.

The same codec is used inside `secure_storage.go`, which fixes F1 (keep-move.md §2(f)).

### 7.3 Banners

STATE-2 and STATE-3 (`state_codec.go:58-90`) and the encrypted envelope versions are rollback
guards. On write, the level is:

```
level = max(level read at open, compat requirement, extension requirement)
```

- The compat requirement is the existing byte mark: `"contractRevision":"<domainACLReferenceRevision>"`
  means 3. It is kept as a constant in the compat table, so `main` no longer imports the domain.
- The extension requirement is an optional `BannerRequirement(data []byte) int` an extension may
  implement.

A store never downgrades under generic LumberJack. That is stricter than today, which drops back to
STATE-2 when the last reference goes. The nested pre-banner format is still read (`readNestedState`).

### 7.4 Staged pairs and the overlay

Pairs (`stagedPairsFromBytes`, `state_writer.go` `pairs`/`durablePairs`) are derived from bytes.
They are never stored separately, so dropping them loses nothing on disk. The writer's
unchanged-skip becomes hash-only.

The overlay (`encodeSnapshotLocked`'s `stagedOverlayLocked`) writes pending owned nodes that the
live forest does not show. A store written today with a pending command is a file whose bytes
contain those nodes. Generic LumberJack loads them as ordinary marked nodes: hidden and guarded,
preserved verbatim. That is the state a crash at that moment would also leave.

### 7.5 Encrypted state and the sealing-label table

| Artefact | Selector | Label (AAD prefix) | Read | Write |
|---|---|---|---|---|
| encrypted state | envelope `version` 3 (no references), 4 (references) | `momentum/storage/v3/<id>/` | yes | only while `Storage.WriteLabel = legacy` (default for the transition release) |
| encrypted state | `version` **5**, **6** (references) | `lumberjack/storage/v5/<id>/` | yes | when `WriteLabel = neutral` |
| account key wraps (`accounts`) | envelope version of the file | same as above | yes | rewrapped under the neutral label on the first neutral write (one KMS wrap per account) |
| object key file | `version` 1 | `momentum/objects/v1/<id>/` | yes, forever | never written for new stores once neutral |
| object key file | `version` **2** | `lumberjack/objects/v2/<id>/` | yes | new stores when neutral; an existing v1 file is rewrapped only on an explicit rewrap |
| object record | flag 1 (`objectSealed`) | the key file's label | yes, forever (append-only) | legacy mode |
| object record | flag **2** | `lumberjack/objects/v2/<id>/` | yes | neutral mode |

Purposes under the prefix are unchanged:

- state: `snapshot`, `account/<uid>`, `resource|backend|grant/node/<id>[/<uid>]`,
  `…/conversation/<id>`, `…/message/<cid>/<mid>`;
- objects: `master`, `key/<oid>`, `object/<oid>`.

Older builds refuse versions 5/6 ("unsupported encrypted state format"). They index flag-2 records
as corrupt and never serve them (`object_store_scan.go:129-131,172-177`). Both fail closed. Q3 is
when to make `neutral` the default, because that is a one-way door for rollback.

The `conversations` section:

- **On read**, each header and message is opened with the backend key and reassembled, in `Order`,
  into the root's `conversations` slot.
- **On write**, the slot is sealed inside the backend-only root resource, and the section is not
  written. Nothing reads the per-member `account_keys` today (`AccountKeys` is written at
  `secure_storage.go:123` and never read), so nothing observable is lost.
- **Rolling back** to the cut build works: it decodes `conversations` from the root body when the
  section is empty (`secure_storage.go:303-305`). Q4.

The test bar for encrypted stores is semantic equality per node record, not file bytes: keys and
nonces are fresh on every write.

### 7.6 Tiered persistence

Hot-log records carry node records produced by the same walk and codec (`change_set.go`), so slots
survive replay. Domain and owned-scope writers were already refused under tier, so a tiered store
holds no pending overlay.

### 7.7 Fixtures

No state fixture exists in the repo. `*.dat` is gitignored (`.gitignore:3-4`), and there is no
state file under any `testdata/`. Corresponder's `corpus/` and Intercessor's
`tests/fixtures/minimal.img` are not LumberJack state.

The only tracked vectors are `internal/admission/testdata/session_vector.json`, which leaves with
Activity, and `embedded/testdata/workload_profile.json`, which leaves with pngstore.

So P3b-0 generates the fixtures at the cut, with the builders that already exist, and commits them
under `internal/compat/testdata/` as `*.ljstate`. That avoids the `*.dat` ignore rule. A
`MANIFEST.jsonl` records the sha256 of each and what it contains.

| Fixture | Builder today |
|---|---|
| `plain-state2-all-fields`: every `core.Node` field plus outbox `feed`/`pending`/`inbox`/`outbound` | `populatedNode` (`state_codec_test.go:13`) |
| `plain-state3-acl-reference` | domain ACL-reference fixtures (`embedded/pngstore_acl_reference_test.go`, `domain_fixture_test.go`) |
| `plain-owned-scope-numbers`: metadata `12345678901234567890`, `1.50`, a pending command | `stagedTestConfigured` (`staged_test_helpers_test.go`) |
| `plain-personal-bindings`: the root-ledger `restoreAllNumbers` path | `embedded/personal_source_test.go`, `momentum_owned_root_test.go` |
| `enc-v3`, `enc-v4`: conversations with messages, accounts, a local-test key | `encryptedDocumentForTest` (`access_expiry_test.go:14`) |
| `nested-legacy`: pre-banner | the `readNestedState` tests |
| `tiered`: snapshot plus hot log | `persistence_test.go` |
| `objects-sealed-v1`: key file v1 plus a segment with flag-1 records | `object_store` tests |

### 7.8 Compatibility tests (land with the steps in §8)

1. **Plaintext byte identity.** Every plaintext fixture: decode → encode gives a document
   byte-identical to the fixture's decompressed payload, with the header hash equal.
2. **Per-key preservation.** For every slot key in every fixture, the raw value bytes are equal
   before and after a forced write of an unrelated change.
3. **Numbers.** Exact literals survive plaintext, encrypted and tiered round trips.
4. **Encrypted.** v3/v4 fixtures, written legacy, give equal records. Written neutral (v5/v6), they
   give equal records. `conversations` is reassembled into the slot.
5. **Banner.** STATE-3 stays STATE-3. STATE-2 stays STATE-2 unless a reference mark appears.
6. **Rollback.** A CI job builds the cut commit (any `product/*` branch) and opens the stores
   generic LumberJack wrote from each fixture. Plaintext and legacy-label stores open with all
   product fields intact; v5/v6 and flag-2 fail closed.
7. **Fail closed.** `account_security` or `mfa_enabled` without a second factor gives 401. A marked
   node is hidden and guarded.
8. **Objects.** Flag-1 records are read; new records use flag 2 in neutral mode.

## 8. Implementation order (P3b)

Each step lands green on its own: `go test ./...`, `make all` (header-check, nm-check, smoke,
canon-check) and the §7.8 tests that exist so far.

The order does every compat hardening **before** any product code is removed. Removal steps can
then be checked against the fixtures, and none of them can drift bytes.

| Step | Content | Tests added | Size (non-test lines) |
|---|---|---|---|
| **P3b-0** Cut | Generate and commit the fixtures and `MANIFEST.jsonl` from today's code. Cut the five `product/*` branches from this commit, each with `PRODUCT-INVENTORY.md`. | fixture-manifest hash test; today's code re-encodes each plaintext fixture byte-identically (the baseline for §7.8.1) | +~350 generator (build tag `compatgen`), 8 fixtures; no engine change |
| **P3b-1** Compat hardening | Number-exact decode everywhere, including `secure_storage` (fixes F1). Sticky banner level with the compat mark. Label table read side (v5/v6, key file v2, flag 2 readable; writes still legacy). | §7.8.1–3, 5, 8 (read side) | +~250 / −~60 |
| **P3b-2** Public packages | Promote `internal/core` → `core` (101 non-test and 72 test importers; mechanical). Add `extension` package, `Host` over `changeForest`/`readForest`, the registry, `OpenWith`, Open-time validation. No seam is called yet. | Open-time validation tests (§3) | +~450 new; ~175 files with a one-line import change |
| **P3b-3** Activity out | Remove the `activity-runtime` files (2,570 lines). Add `RequestAuthenticator`, `Principal.Projection`, `Configurable`, and refusal of undeclared config parts. | `TestAuthenticatorRefusalDoesNotFallThrough`, config-part refusal, `/principal` projection | −2,570 / +~250 |
| **P3b-4** Second factor out | Remove `momentum-auth` (1,912 lines) and its routes. Add `SecondFactor`, `Sessions`, the fail-closed rule, `OutboxListener`. | §4.4 login tests, `TestOutboundAckNotifiesListener`, §7.8.7 (login half) | −1,912 / −~200 from KEEP-NEUTRALISE / +~300 |
| **P3b-5** Workspace out | Remove `momentum-workspace` (4,018 lines). Add `RouteProvider` (HTTP and application table, backpressure flag), `Tx.Enqueue`, `Direct`, `OutboxEntitlement`, generic `notificationRevision`, generic revoked-timer stop. | §4.3 route tests including the golden table, §4.6 tests | −4,018 / +~400 |
| **P3b-6** Write and read seams, product still in tree | Add the `PermitProvider`, `WriteHook`, `Commit` and `VisibilityFilter` call points (§4.1, §4.2). Plug today's source fence and staged protection/visibility into them as **temporary internal implementations**. This is about 80 lines of glue that wraps the existing functions; it is not a port. | §4.1 and §4.2 generic tests, **plus every existing domain, personal and staged suite, unchanged and green**: the seams are proven under real product traffic before the product leaves | +~450 |
| **P3b-7** Owned-scope subsystem out | Remove `momentum-personal` and `manifest-domain` **together** (17,878 lines, including `staged_*` and the fence) and their 14 exports. They cannot be split without editing product code: 6 domain/staged/fence files reference personal-source symbols, 11 personal files reference enrollment or domain symbols, and the shared close path lives in `embedded/personal_source_lifetime.go:117`. The built-in owned-marker rule and owned-subtree guard (lifted from `staged_guard.go`) replace the glue. Re-home the overlay-free `encodeSnapshotLocked`. Drop pairs from the writer. Generic extension-instance lifecycle in `embedded`. Header without the 14 declarations. | §7.8.7 (marker half), §7.8.1 still byte-identical, nm-check: exactly 19 exports | −17,878 / +~450 |
| **P3b-8** Slot codec | Remove the five product fields and `Outbox.Feed` from `core`. Add `core.EncodeRecord`/`DecodeRecord` with the legacy order table and slot storage; `SlotSpec`, `ReadTx.Slot`/`Tx.SetSlot`; the encrypted `conversations` reassembly. | §4.5 tests, §7.8.1–4 against the slot (not typed fields), §7.8.6 rollback job | +~550 / −~120 |
| **P3b-9** Neutralise | `Config.Storage` with `LUMBERJACK_*` and deprecated `CORRESPONDER_*` aliases. `reconcile` config. `cmd/serve.go` defaults. Drop the canvas const. Make the label write switch available, default legacy. | env-alias tests, §7.8.4 neutral write, §7.8.8 write side | +~200 / −~80 |
| **P3b-10** Product archives | `ffi/abi`, the wrapper generator, `ffi` as wrappers, `ffi/testdata/example` product archive, Makefile `product-archive-example`. | header-check, nm-check, smoke, example-archive build and call | +~500 |

**Highest risk: P3b-8.** It is the only step that changes how every state byte is produced, on every
load and write path: plaintext, nested, encrypted and tiered log. A mistake there is silent,
permanent data loss of product fields in stores that are opened by `main` and then handed back to a
product.

It is placed last among the engine steps for three reasons:

1. The P3b-0 fixtures and the P3b-1 number fix already pin the bytes.
2. By then only generic code touches the fields.
3. Its gate is a whole-document byte-identity test, which either passes exactly or fails.

The rollback CI job (§7.8.6) must be green before P3b-8 merges.

P3b-6 is the largest change to concurrency: the write path's permit and hook ordering. It runs
while the fence and the staged guard still exist, so the existing product suites exercise the new
ordering, including `staged_durability_test.go` and the fence's unknown-outcome tests. Its gate is
those suites, plus its own §4.1 ordering tests and the existing `forest_lock`/`state_writer` tests.

P3b-7 is the largest deletion. After P3b-6 it is low risk, because the seams it relies on are
already proven, and §7.8.1 must stay byte-identical across it.

The same seam-first pattern (introduce the seam with the product as a temporary implementation,
then remove the product) can be applied to P3b-3 through P3b-5 if the owner wants extra assurance.
It costs one extra step each.

## 9. Deliberately not seams

- **The snapshot overlay and durability pairs.** The engine never needs either. A product needing a
  durability witness gets `Commit{Seq, SHA256, Path}` from `Settle`/`Change`, and can re-read the
  file it names, as `inspectSourcePair` does today.
- **`DomainProduct`, `DomainPolicy` and the 7 optional capability interfaces**
  (`activation_domain_types.go:182-199`, `DomainInputProjector`, `DomainCommandResultProjector`,
  `DomainCreationResolver`, `DomainTargetFields`, `DomainReceiptProjection`, `DomainTargetInput`,
  `DomainTargetInputBinder`). These are the domain engine's plug-in surface for its own products.
  They leave with it; when it is rebuilt it becomes one `extension.Extension`.
- **The Activity verifier wire protocol, the signed admission format and the Raft packages.**
- **A generic subscription route.** See Q5.

## 10. Open questions for the owner

| # | Question | Options | Recommendation |
|---|---|---|---|
| Q1 | A `main`-only build no longer forces a second factor. Today `MOMENTUM_REQUIRE_MFA` unset means TOTP enrolment is forced. | (a) accept, with the fail-closed rules for already-enrolled accounts; (b) keep a minimal TOTP factor in `main` | (a). The second factor is a product policy; deployments that want it link `momentum-auth` |
| Q2 | Promote `internal/core` to public `core`? | (a) promote; products keep writing `*core.Node` under `Tx`; (b) an opaque node API | (a). The model is already product-free once five fields leave, and (b) means a rewrite of every product |
| Q3 | When does the neutral sealing label become the write default? | (a) legacy default for one release, neutral opt-in; (b) neutral immediately | (a). Neutral writes cannot be opened by the cut build |
| Q4 | Encrypted `conversations` section | (a) fold into the backend-only root and read the section for compatibility; (b) a `SealedSection` seam to keep per-member wraps | (a). Nothing reads `account_keys`; (b) would be a seam the engine never exercises |
| Q5 | A `main`-only outbox is fed only by `/access` share notices | (a) accept; (b) add generic `POST /subscriptions` | (a). It is still a correct, idle dispatch |
| Q6 | Owned scopes | (d1) keep the whole owned-scope engine in `main`; (d2) keep only the marker rule and subtree guard | (d2) |
| Q7 | Base exports in product archives | (a) generated wrappers in each `main`, keeping header-check; (b) exports in `ffi/abi`, checked by nm plus smoke only | (a) |
| Q8 | ABI version after 14 exports leave the generic archive | (a) stay 2: base unchanged, the loss is a link error; (b) bump to 3 | (a) |
| Q9 | `product/mindfull-app` | (a) none; (b) create it for the canvas key and copyright | (a) |
| Q10 | `CORRESPONDER_STORAGE_*`, `CORRESPONDER_ADMIN_RECONCILE` | (a) explicit config plus `LUMBERJACK_*`, old names as deprecated aliases for one release; (b) rename hard | (a) |
| Q11 | Raft (`replication/`, `peertransport/`, `businessruntime/`) leaves with Activity | (a) yes; a future generic replication is designed fresh; (b) keep `replication/` | (a). It encodes Activity admissions and products |
| Q12 | `ms_` bearer prefix | (a) keep as an opaque wire constant; (b) mint a new prefix and accept both | (a). It is wire-visible, and the stored session key is its hash |

## 11. Deviations

What the implementation (`finalize/split`) does differently from the text above, and why. Each keeps
the invariants of §5.

| # | Step | Design said | Done instead | Why |
|---|---|---|---|---|
| D1 | P3b-0 | each product branch adds `PRODUCT-INVENTORY.md` | the file is `HANDOFF.md` | the owner's execution brief names it so; the content is the inventory §3 of keep-move.md asks for, plus the rebuild steps |
| D2 | P3b-0, P3b-1 | "today's code re-encodes each plaintext fixture byte-identically" | it does not: 3 of 5 plaintext fixtures drift. A product stores a receipt as a Go struct, the load reads it back as a map, and the map re-marshals with its keys sorted. The P3b-0 test pins what the cut build wrote back (`reencode_sha256` in `MANIFEST.jsonl`). P3b-1 makes the byte identity true: a node whose encoding is unchanged since load is written back as the bytes it was read from (`core/node_loaded.go`, `nodeRecord.MarshalJSON`) | §7.1's result, "an untouched store re-encodes to identical document bytes", is what the fixtures gate on; without this the legacy order table alone cannot deliver it for typed values inside `command_receipts` |
| D3 | P3b-1 | label read side only; writes stay legacy | a store keeps the label its envelope or key file was read under; a new store is written legacy | a neutral (v5/v6, key file v2) store written back as legacy would need every account wrap re-wrapped and would reopen the rollback door the neutral label closed. The opt-in switch for legacy stores is P3b-9 |
| D4 | P3b-3 | remove all 2,570 Activity lines | `activation_config.go`, `activation_protocol.go` and `activation_json.go` stay until P3b-7, trimmed of Activity's engine API (`ConfigureActivation`, `ValidateActivationConfig`, `DecodeActivationConfig`); `application_business_scope.go` stays until P3b-5 | the domain engine builds its verifier from `ActivationConfig`, `activationVerifier.validActor` and `strictActivationJSON`, and the workspace's message operations read `AuthenticatedContentScope`. Removing them first would mean editing product code; they leave with their last user |
| D5 | P3b-3 | – | `endApplicationSessionLocked` (sign-out ends a delegated session's family) moved from `application_session_admit.go` to `application_session.go` | it is the generic session registry's, and `/session` DELETE calls it |
| D6 | P3b-3 | an undeclared part is refused | a part whose value is `null` counts as present | the cut build refused a `null` part too; ignoring it would be the silent path §4.7 rules out |
| D7 | P3b-4, P3b-5, P3b-7 | the product `core` types (`AccountSecurity`, `MFAChallenge`, `Conversation`, `FeedState`, `FeedPreferences`, `PersonalBindingLedger`) leave with their products | they stay until P3b-8 | `core.Node` and `core.CorrespondenceState` keep those typed fields until the slot codec replaces them (P3b-8); the types are data only and leave in the same step as the fields |
| D8 | P3b-4 | `OutboundSettledLocked(tx, item, outcome)` | it answers a `bool`: whether the listener recorded the outcome against something it owns | `outbound_failed` answers `recorded`, which HubRuntime's forwarder reads; the engine cannot know it without the listener saying so |
| D9 | P3b-4 | – | the session registry no longer refuses a session minted without a second factor (`requireAccountMFA` in `registeredSessionLocked`) | that check was the second factor's policy, not the registry's. The fail-closed rule is at the password exchange, as §4.4 states; sessions minted by a product before the cut carry `MFAAt` and stay valid by the registry's own rules (idle, absolute, epoch, lock) |
| D10 | P3b-5 | "minus metadata keys an extension declares as presentation-only" (no declaration given) | `Spec.PresentationMetadata []string` | it is static knowledge about the extension, so it belongs in `Spec` with its other declarations |
| D11 | P3b-4, P3b-5 | the existing `access_*_test.go` and other shared suites stay green unchanged | their fixtures change; their assertions about the engine do not. They set up with workspace commands (`/workspace/commands` create, log, subscribe) and the default TOTP enrolment; those fixtures are re-expressed over the engine's own write path (`access_fixture_test.go`, `entryLog`, `applicationLogin`, a test extension in the embedded hub test). Assertions that are about the product itself leave with it, and are listed in the product's `HANDOFF.md` | the fixtures used product routes that no longer exist on `main`; keeping the engine assertions is what keeps the access, stream and persistence coverage |
| D12 | P3b-5 | `Transport: HTTP` | an HTTP-only extension route is not served on the application transport either | the application transport falls through to a mux; without this, `HTTP` would mean the same as `Both` |
| D13 | P3b-5 | `embedded/momentum_workspace_test.go` listed with momentum-workspace | it moves with manifest-domain at P3b-7, with `momentum_fixture_test.go` and `momentum_owned_root_test.go` | it tests `products/momentum`, the Momentum `DomainProduct`, through the domain engine; it never touched the workspace routes |
| D14 | P3b-6 | `OutcomeState` constants `Refused`, `Unknown`, `Durable` | `WriteRefused`, `WriteUnknown`, `WriteDurable` | `Refused` is also a `Claim` (§4.4) in the same package; Go cannot hold both |
| D15 | P3b-6 | the product suites run "unchanged" | two calls in `staged_isolation_test.go` pass the server's visibility rule to `newNodeView` | `childrenByName` and the projector take the filter (§4.2), so the free function's signature changed; the assertions are untouched |
| D16 | P3b-6 | §4.2's guard tests (`TestOrdinaryWriteCannotChangeOwnedSubtreeOrItsAncestors`, `TestDeclaringExtensionMayWriteItsOwnMarkedNodes`) with P3b-6 | they land with P3b-7 | at P3b-6 the guard slot is still the staged-scope protection, which guards configured scopes, not markers; the marker-based guard those tests describe is P3b-7's |
| D17 | P3b-7 | – | a store holding the compatibility owned-scope marker still does not open under tiered persistence (`refuseLegacyOwnedScopeUnderTier`) | the cut build refused it; the marker's owners run under snapshot persistence only, and a store handed back to them must not have acquired a hot log they do not replay. Extension markers follow their own `Spec.Persistence` |
| D18 | P3b-7 | the guard is "the product-free part of `staged_guard.go`" | written fresh over markers (`owned_guard.go`, `owned_guard_verify.go`): the same mechanism (closure clone, subtree hash, ancestor links, alias removal, restore), plus two rules the scope-keyed guard got from its scope registry: a change that puts a marker on a node outside every guarded subtree is refused and the marker taken off, and an edge into a guarded subtree from outside is a violation. The bound is the marker value's `bounds.maxNodes`, else 100,000 | the staged guard was keyed by configured scopes and validated them with product code; without the registry, the marker set itself is what must not change |
| D19 | P3b-7 | – | the fixture generator (`compat_fixtures_gen_test.go`) leaves `main` with the products whose builders it calls; it stays on every `product/*` branch, which is the cut | the fixtures are generated at the cut only; on `main` they are read, never written |
| D20 | P3b-8 | `ReadTx.Slot(nodeID, key)` for root, node and outbox keys | an `OutboxKeys` key is addressed with the node id `extension.OutboxSlots` | §4.5 declares outbox keys but not how a Tx names them; a root key and an outbox key may share a name, so the root's id cannot address both |
| D21 | P3b-8 | slot storage "unexported in `core.Node`" | the storage type lives in `internal/slots` and `core` hands it out only for a `slots.Token`, which no code outside the module can name | an unexported field alone would keep the engine out too; the token keeps the engine in and extensions out, so they reach slots only through `ReadTx`/`Tx` |
| D22 | P3b-8 | – | `TestAccessWallClockExpiry…` no longer asserts per-member conversation wraps | owner decision Q4(a): the conversations section is no longer written, so there are no per-member wraps to keep; the slot is sealed inside the backend-only root |
| D23 | P3b-8 | the rollback job opens the stores with "all product fields intact" | its baseline is the cut build's own result of the same unrelated write, compared record by record, key by key | the engine recomputes some keys on every write (materialized access grants, entry ids) in both builds; comparing against the fixture's raw records would blame the codec for the engine's own rules. The job is `make rollback-check`, part of `make all` |
| D24 | P3b-8 | the label write switch at P3b-9 | `secureStorage.relabel` (rewrap every account key under the new label) lands at P3b-8 | the rollback job needs neutral-label stores to prove the cut build refuses them; P3b-9 adds the configuration that selects it |
| D25 | P3b-9 | "`LUMBERJACK_STORAGE_*` read by `cmd`/`ffi`" | `types.StorageFromEnvironment` reads them (and, for one release, the `CORRESPONDER_STORAGE_*` aliases, each logged as deprecated) whenever `ServerConfig.Storage` is nil — the path the CLI, the C ABI and `embedded` all take. A non-nil `Storage` is explicit and the environment is not read. The label switch is `storage.write_label` / `LUMBERJACK_STORAGE_WRITE_LABEL` (`legacy` default, `neutral` opt-in), and `ServerConfig.AdminReconcile` / `LUMBERJACK_ADMIN_RECONCILE` replaces `CORRESPONDER_ADMIN_RECONCILE` | one reader for every entry point, so the three cannot drift; the engine itself never reads a variable name directly |
| D26 | P3b-10 | `abi.Open(req []byte) (uint64, Status)`, … | the entry points take the C arguments as Go values — each pointer an `unsafe.Pointer`, each length an `int64` — and answer the status as an `int32` | a cgo type belongs to the package that declares it, so a product's `main` cannot hand `abi` its `C.lj_cstr`; passing pointers keeps the whole buffer convention (bounds, truncation, no partial document, the panic guard) inside `abi`, once, for every archive |
| D27 | P3b-10 | – | the example product archive's C driver is `ffi/ctest/example.c`, not inside `ffi/testdata/example` | cgo compiles every `.c` file in a package's directory into the package |
