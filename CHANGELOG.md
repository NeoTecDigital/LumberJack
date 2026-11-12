<!-- Written by Richard Christopher, Copyright 2026 Richard Christopher -->

# Changelog

All notable changes to Lumberjack. The version the engine answers with is on `GET /health`.

## Unreleased

### The split: a generic store with public extension seams

LumberJack is now the generic store, and the seams a product rebuilds on are public. Product code
has left `main`; each product is preserved whole on its own branch, with a `HANDOFF.md`:
`product/manifest-domain` (the domain engine, its products, the owned-scope engine and the source
fence), `product/momentum-personal`, `product/momentum-workspace`, `product/momentum-auth` and
`product/activity-runtime` (with the Raft packages). See `docs/keep-move.md` and
`docs/extension-api.md`.

- **Public packages.** `core` (was `internal/core`) is the data model and the record codec.
  `extension` is the seams: `Extension`, `Host` and its one write path `Host.Change`,
  `PermitProvider`, `WriteHook`, `VisibilityFilter`, `RouteProvider`, `RequestAuthenticator`,
  `SecondFactor`, `Sessions`, `OutboxListener`, `OutboxEntitlement`, `Configurable`, and
  per-forest slots. `embedded.OpenWith(config, principal, extensions...)` attaches a fixed set per
  runtime. `ffi/abi` and `ffi/gen` build product C archives.
- **Routes removed** with their products: `/workspace`, `/workspace/commands`, `/conversations*`,
  `/feed*`, `/assets/index`, `/mfa/*`, `/auth/*`, `/account/*`, `/users/mfa`, `/session/mfa`,
  `/session/admit`, `/activation/probe`. A product registers its routes through `RouteProvider`.
- **Signing in (breaking).** With no `SecondFactor` registered a password login issues a session;
  `MOMENTUM_REQUIRE_MFA` is no longer read. An account already enrolled in a second factor —
  `mfa_enabled`, or its id under the root's preserved `account_security` — is refused
  `401 second factor required`, and the refusal is not counted against it.
- **`application_configure` parts.** `username`, `password` and `secret` are the engine's; every
  other part goes to the extension that declared it. A part no extension declared — `activation` or
  `admission` on the generic archive — is refused `LJ_INVALID`.
- **C ABI.** The generic archive exports exactly the nineteen base functions; the fourteen
  `ic_lj_domain_*`, `ic_lj_personal_source_*` and `ic_lj_native_*` exports are in product archives.
  `LJ_ABI_VERSION` stays 2. The archive is about 37.7 MB (was 50.5 MB).
- **Outbox.** `CorrespondenceState`/`CorrespondenceChange` are `core.Outbox`/`core.OutboxChange`;
  the JSON is unchanged. A change records `direct` when its recipients were chosen for it;
  `/notifications` shows a record that is direct, a share, subscribed to, or vouched for by an
  `OutboxEntitlement`.
- **Storage configuration.** `ServerConfig.Storage` is explicit; without it the engine reads
  `LUMBERJACK_STORAGE_*`, and for this release the deprecated `CORRESPONDER_STORAGE_*` names.
  `LUMBERJACK_ADMIN_RECONCILE` replaces `CORRESPONDER_ADMIN_RECONCILE` (also still read).
  `lumberjack serve` defaults to `--admin-org LumberJack --admin-email admin@lumberjack.local`.
- **Sealing labels.** Legacy stays the write default; `LUMBERJACK_STORAGE_WRITE_LABEL=neutral`
  writes envelope 5/6, object key file 2 and object flag 2, which a build from before the split
  refuses. Both are read.
- **State files.** A store written by the builds that carried product fields round-trips byte for
  byte: an unchanged node is written back as the bytes it was read from, keys nobody now types are
  kept as their bytes and written in their old place, and every number keeps its literal (`1.50`
  stays `1.50` — which also fixes an encrypted store rounding numbers on every write). A store that
  reached the STATE-3 banner keeps it. An encrypted store's `conversations` section is read into the
  root and sealed inside it from then on. Nodes carrying the legacy owned-scope marker are hidden
  from generic reads and guarded against ordinary writes, and such a store does not open tiered.
- **Checks.** `internal/compat/testdata` holds state files written by the cut build;
  `make rollback-check` has the cut build open what this build writes from them, and
  `make product-archive-example` builds and drives a product archive.


### Tiered persistence

What a write puts on the disk is now the size of the change, not the size of the store. Opt in
with `mode: tiered` in the `persistence` block of `config.yaml`; the default, `snapshot`, is
exactly what every earlier build did.

- **Hot layer.** Every commit appends one record to an append-only log beside the state file
  (`<name>.dat.log.<sequence>`): a sequence number, the nodes it changed as the state codec
  encodes a node, the ids it deleted, a length and a checksum. `hot_sync` says when the record is
  synced: `commit` before the write is acknowledged, `interval` in the background every
  `hot_sync_interval_ms`, `none` whenever the operating system gets to it. Concurrent commits
  share one write and one fsync.
- **Cold layer.** A background writer rewrites the whole state file, with the same atomic writer
  as before, every `cold_every_commits` commits or `cold_every_seconds` seconds, and on a clean
  shutdown. The state file names the last log sequence it contains, inside the document, so it is
  written atomically with it. Log segments are deleted only once a durable state file wholly
  covers them. The forest is held only for the encode, so a commit during a snapshot waits for
  one encode and not for the disk.
- **Recovery.** The state file is loaded and the log is replayed past its sequence, in order. A
  torn tail in the last segment is cut. Damage anywhere else, an intact record out of sequence, or
  a log that begins past the state file refuses to open, naming the segment and offset.
- **A record is the write's change set**: the nodes a comparison of the whole forest against its
  last encoding finds new or changed, each whole, and the ids it no longer reaches. A log holding a
  partial node (`entries_before`, `children_kept`), which only a build with pdl's graph engine
  wrote, is refused at open instead of being read as whole nodes.
- **The change sequence is durable.** The mutation stream's numbering continues from the log's
  last record after a restart instead of starting again at one. A write that publishes more than
  one mutation per record (a workspace command publishes two) can leave it below what a client
  saw; the stream's epoch says the process restarted.
- **A sync hook** receives every record after its local append. `sync.role` accepts `single`,
  `primary` and `replica`; only `single` runs in this build, and the others are refused at open
  with an error that says so.
- **An encrypted store refuses `mode: tiered`**: the log would hold plaintext beside the sealed
  state file.
- **Owned scopes, the domain engine and the personal source refuse `mode: tiered`.** They publish
  whole paired snapshots through the state writer, which the log and the cold writer do not carry;
  `ConfigureDomain` and `ConfigurePersonalSource` answer an error under tiered, and a state file
  that already holds an owned scope does not open in it. Snapshot mode is unchanged.
- **Every tiered commit holds the source-fence permit** and runs inside the staged-scope
  protection, the access-grant refresh and the hub's record, as every snapshot-mode write does.
- **The application feed is unavailable in tiered mode.** Its durability check compares the forest
  with the state writer's last durable snapshot, which tiered commits never update, so `/feed`, its
  marks and preferences, refusal recording and reminders answer 503. A tiered counterpart (every
  staged record durable and nothing in memory unstaged) is not defined yet.
- **A failed write is retried, and nothing after it is acknowledged first.** A record that could
  not be appended goes back to the front of the queue; a later commit retries it ahead of its own
  record and is answered 5xx while it still fails. In either mode the store knows when the forest
  in memory is ahead of its disk (a failed flush, a failed append, or a failed background sync
  under `interval`) until a write, or that sync, lands.
- The embedded runtime reads the two blocks from `<database_path>/config.yaml`; the CLI reads
  them from its own `config.yaml`.

### Object log

An append-only, content-addressed store for bytes that are history rather than working set: file
contents, trees, commits. It lives beside the state file in `<name>.objects/`, and writing an
object never rewrites `.dat`, takes no forest lock and announces nothing on `/stream`.

- **Routes.** `POST /objects` stores the body and answers `{"id","size","existed"}`;
  `GET /objects/{id}` answers the bytes as `application/octet-stream`; `HEAD /objects/{id}` answers
  the same headers without the body. The permission is the forest root's: Write to put, Read to get.
  The same routes run through the in-process `call` path (`ic_lj_application_call`,
  `embedded.ApplicationCall`), with the body as standard base64.
- **The id is the BLAKE3-256 of the bytes**, as lowercase hex. The same bytes put twice are one
  object, and the second put writes nothing and answers `existed: true`. There is no delete.
- **Segments, not an index file.** Numbered segments (`00000001.seg`, …) of records carrying the id,
  an encoding flag, a length, the payload and a CRC-32C, rolled over at 256 MiB. Every open rebuilds
  the index by scanning them.
- **A put is acknowledged only once it is on the disk**: the segment is synced after every record.
  A torn last record is cut on open. A bad record followed by others is kept and reported as
  corrupt (`500`), not dropped. Every read re-hashes the bytes against the id.
- **`max_object_bytes`** in the process configuration caps one object, 64 MiB when unset. An
  oversized object is refused `413` and nothing is stored.
- **Sealed under encrypted storage** (`kms`, `local-test`): each object is sealed under its own key,
  wrapped under a store master key in `<name>.objects/key`. The id stays the BLAKE3 of the plaintext.
  A plaintext object store under an encrypted mode, or a sealed one under none, is refused.

## 0.3.2

The last release before the changelog. See the git history.
