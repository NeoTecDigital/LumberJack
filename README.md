# LumberJack API Documentation
![lumberjack500](https://github.com/user-attachments/assets/1f1c2f9e-a550-47eb-8f18-a11abbc1cf58)
## Overview
The LumberJack API provides a hierarchical event tracking system where nodes can have multiple parents and events can be tracked across different organizational paths.

## A generic store, and the seams products build on

LumberJack is the generic store: the forest, events and entries, queries, the object log, the
session registry, `/access` sharing, the hub's outbox, and storage encryption. Product code — the
domain engine and its products, Momentum's personal source, workspace and second factor, and
Activity's runtime — is not in it. Each product is preserved, whole and unchanged, on its own
`product/*` branch with a `HANDOFF.md` that says what it used and how to rebuild it
(`docs/keep-move.md`).

What a product builds on is public:

- **`core`** — the data model: `Node`, `Event`, `Entry`, `User`, `AccessGrant`, `Outbox`,
  `OutboxChange`, `OutboundMessage`, and the record codec.
- **`extension`** — the seams: `Extension`/`Spec`/`Instance` and `Host` (one write path,
  `Host.Change`); `PermitProvider` and `WriteHook` around every write; `VisibilityFilter` and
  ownership markers; `RouteProvider` for HTTP and application routes; `RequestAuthenticator`,
  `SecondFactor` and `Sessions`; `OutboxListener` and `OutboxEntitlement`; `Configurable` for
  `application_configure` parts; per-forest slots (`SlotSpec`, `ReadTx.Slot`, `Tx.SetSlot`).
- **`embedded.OpenWith(config, principal, extensions...)`** — the set is fixed for the life of a
  runtime; a second open of the same path with a different set is refused.
- **`ffi/abi`** and **`ffi/gen`** — a product's C archive is a superset of the generic one: the
  generated base wrappers, its own exports, and `abi.Register` in `init`.

The design is `docs/extension-api.md`; what the implementation did differently is its §11.

**Signing in without a second factor.** A store with no `SecondFactor` registered signs a user in
with a password. An account that was enrolled in a second factor before the split — `mfa_enabled`
on the user, or its id under the root's preserved `account_security` — is refused with
`401 second factor required` until a product that implements one is linked. `MOMENTUM_REQUIRE_MFA`
is no longer read.

**Data a missing product owns is kept.** Keys a product wrote on a record (`personal_bindings`,
`conversations`, `account_security`, `mfa_challenges`, `admitted_commands`, the outbox's `feed`) are
kept as the bytes the file held and written back in place. A node carrying an ownership marker is
hidden from every generic read, and an ordinary write that would change its subtree is refused 403.

**The C ABI** exports the nineteen base functions `ffi/lumberjack.h` declares, and no others
(`make nm-check`). The ABI version is still 2. A caller that used an `ic_lj_domain_*`,
`ic_lj_personal_source_*` or `ic_lj_native_*` export links its product's archive instead.

## Installation & Usage

### Using as a Package
```bash
go get github.com/NeoTecDigital/LumberJack
```

### Building from Source
```bash
git clone https://github.com/NeoTecDigital/LumberJack.git
cd lumberjack
go build
```

### Getting Started
Starting LumberJack is as simple as running the following command:
```bash
./lumberjack
```

To create a new server configuration:
```bash
./lumberjack create
```

To start the server:
```bash
./lumberjack start

# Or with dashboard
./lumberjack start -d
```

To list current configuration:
```bash
./lumberjack list
```

To delete configuration:
```bash
./lumberjack delete
```

### Configuration: `config.yaml`

The CLI keeps its databases in `/etc/lumberjack/config.yaml`. Two optional blocks say how a
forest reaches the disk; left out, both are the defaults, which is exactly what every earlier
build did:

```yaml
persistence:
  mode: snapshot          # default: the whole state file per write. "tiered": hot log + cold snapshot
  hot_sync: commit        # when the hot log is synced to disk: commit | interval | none
  hot_sync_interval_ms: 20
  cold_every_commits: 2000
  cold_every_seconds: 60
sync:
  role: single            # single | primary | replica — only single runs in this build
  listen: ""              # primary: address replicas connect to
  primary: ""             # replica: the primary's address
  ack: local              # when a commit is acknowledged: local | one | quorum
```

**The embedded runtime reads the same two blocks from `<database_path>/config.yaml`**, beside the
state file, when the config it was opened with leaves them empty. A host that opens a forest
through `embedded.Open` or the C ABI opts into tiered persistence by writing that file. `lumberjack
serve --data-dir DIR` reads `DIR/config.yaml` the same way. A block that names something this
build does not do — a misspelt mode, `role: replica` — refuses to open rather than running as
something else.

## The state file

Everything the engine holds lives in one file, `<name>.dat`, in the configured database path. It is
a sha256 header over a gzip stream, and **as of v0.3.0-alpha the shape inside that stream changed.**
This is the one change in the project with **no undo**, so read this before upgrading.

### What changed

The forest is a **DAG** — a node can have several parents — and JSON is a **tree**. Serializing the
root wrote every node once *per path to it*, so a chain of shared nodes cost 2^n: 50 nodes came to
149 MB and 353 ms on every mutation, under the exclusive forest lock. The file is now a **flat table
of nodes keyed by id**, each naming its children by id — one entry per node however many parents it
has. The same 50 nodes are 29,930 bytes and 86 µs, and the shared structure survives the round trip
exactly instead of being flattened and rejoined by guesswork.

A file in the new shape begins with a **banner**, in front of the sha256 header:

```
LUMBERJACK-STATE-2
this file is a flat node table
```

### Rolling back to an older build

**An older build cannot read the new file, and it will say so.** That is deliberate. It reads the
first 32 bytes as the hash and opens a gzip stream at byte 32, which lands inside the banner, so it
fails at the reader:

```
error loading compressed data: gzip: invalid header
```

This is the **safe** failure. Without the banner, an older build would parse the new document with
`json.Unmarshal`, which ignores fields it does not know, see no node table, silently load an empty
forest, and **write that back over your database on the next mutation**. A file it refuses is better
than a file it quietly empties.

**There is no downgrade converter.** The rollback path is to **restore a backup taken before the new
build first wrote**:

```bash
# Before upgrading, with the engine stopped:
cp /path/to/database/<name>.dat /path/to/database/<name>.dat.pre-v0.3.0

# To roll back, with the engine stopped:
cp /path/to/database/<name>.dat.pre-v0.3.0 /path/to/database/<name>.dat
```

Any work recorded after the migration is in the new file only, and an older build cannot read it.

### Rolling back past shared access lists

A record created from its type's template stores a small reference to that template on its root
instead of a copy of the list. A build from before references reads one as an invalid list, so it
could not revoke a member: the revoke aborts at the first reference and the member keeps read on
every stored copy. So once a forest holds any reference, that build must not open it at all.

A forest holding a reference is written with the banner `LUMBERJACK-STATE-3`, the same flat node
table in every other way, and an older build fails at the reader as above. An encrypted forest says
the same with envelope version 4, which an older build refuses as `unsupported encrypted state
format`. A forest holding no reference keeps `LUMBERJACK-STATE-2` or envelope version 3, and an older
build opens it as before.

**Rollback past the first reference is restoring a backup taken before it was written.**

### Storage encryption: configuration and sealing labels

A store is sealed when its storage mode is `kms` or `local-test`. The configuration is explicit in
`ServerConfig.Storage`; when that is not set, as for the CLI and the C ABI, it is read from the
environment:

| Variable | Meaning |
|---|---|
| `LUMBERJACK_STORAGE_MODE` | `kms`, `local-test`, or empty for plaintext |
| `LUMBERJACK_STORAGE_KMS_KEY` | the Cloud KMS CryptoKey resource, for `kms` |
| `LUMBERJACK_STORAGE_LOCAL_KEY_FILE` | a private 32-byte key file, for `local-test` |
| `LUMBERJACK_STORAGE_MIGRATE_LEGACY` | `1` lets a plaintext store be sealed on open |
| `LUMBERJACK_STORAGE_REWRAP_KEYS` | `1` wraps every account key again on open |
| `LUMBERJACK_STORAGE_WRITE_LABEL` | `legacy` (the default) or `neutral` |
| `LUMBERJACK_ADMIN_RECONCILE` | `1` lets `application_configure` reset the configured admin's password |

The `CORRESPONDER_STORAGE_*` and `CORRESPONDER_ADMIN_RECONCILE` names are still read, for this
release only, when the new name is not set; each use is logged as deprecated.

**Sealing labels.** Every store sealed so far carries the legacy label (envelope versions 3 and 4,
object key file version 1, object record flag 1), and that stays the default for this release.
`LUMBERJACK_STORAGE_WRITE_LABEL=neutral` writes the product-free label instead: envelope 5 or 6,
key file version 2 for a new object store, flag 2 for new objects. The first neutral write wraps
every account key again under the new label. It is a one-way door: a build from before the split
refuses a neutral envelope and does not serve a flag-2 object. A store read under the neutral label
stays neutral. Both labels are read forever.

### Migrating an existing database

Files written by any earlier build have **no banner**, and they are still read: the loader
recognises the absence of the banner and reads the old nested shape, and a node that was written out
once per path to it is rejoined into the single object it was serialized from.

**Loading does not rewrite the file — loading is a read.** The file is converted by the **first
mutation** after the new build starts. So a new build that is only ever read from leaves the old
file exactly as it found it, and the point of no return is the first write, not the first start.

### What a 200 promises, and when a write is on the disk

A mutating request is not answered until the state file **contains** the change. The engine holds
one exclusive lock over the forest for the mutation and for the **serialization** of the forest, and
lets go of it there; the write, the fsync of the temporary file, and the fsync of the directory that
publishes the rename all happen with the lock **released**. Before v0.3.0-alpha the fsync was inside
the exclusive hold, so every other request — reads included — queued behind the disk, and a
congested host turned a working engine into one that answered `/health` in 25 ms while timing out
every write.

Concurrent writers are **coalesced**. Each write serializes the whole forest, so a newer
serialization already contains every change in an older one: a caller waiting behind an in-flight
flush is answered by the next flush rather than by one of its own. Forty concurrent writes cost two
flushes, not forty. Serializations are numbered under the exclusive hold, and the writer never
publishes a lower number after a higher one, so the file cannot be rolled back by a slow writer.

**After a 200, the change is lost only if the storage lied about fsync** — a disk or virtual disk
with a volatile write cache it does not honour, or a filesystem mounted `nobarrier`. A crash at any
other moment loses only writes that were never acknowledged. A write that fails to reach the disk is
answered **500**, and the change stays in memory: the process is then serving a forest newer than
its file, and it must be restarted, which drops back to the last state that was acknowledged.

### Tiered persistence: `mode: tiered`

Rewriting the whole file per write costs the size of the store, and the store grows with every
write ever made because receipts and history accumulate. `mode: tiered` makes what a write puts on
the disk the size of the change.

- **Hot layer.** Every commit appends one record to an append-only log beside the state file,
  `<name>.dat.log.<sequence>`: a sequence number, the nodes it changed (each encoded as the state
  codec encodes a node), the ids it deleted, a length and a checksum. **A 200 means the record is
  as durable as `hot_sync` asks**: `commit` syncs it before answering; `interval` answers once it
  is written and syncs in the background every `hot_sync_interval_ms`; `none` leaves the sync to
  the operating system. Concurrent commits share one write and one fsync. A record that fails to
  reach the disk is retried ahead of the next commit, and no later commit is acknowledged until it
  lands.
- **Cold layer.** A background writer rewrites the full state file with the same atomic writer as
  snapshot mode every `cold_every_commits` commits or `cold_every_seconds` seconds, and on a clean
  shutdown. The document carries `log_sequence`, the last record it contains, so it is written
  atomically with the forest. Segments are deleted only once a durable state file wholly covers
  them. **The forest is held only for the encode**: a commit during a snapshot waits for one
  encode of the forest, not for the hash, the gzip, the write or the fsyncs.
- **Recovery.** Load the state file, replay the log past its sequence, in order. A torn tail in
  the last segment — a record left short or unverifiable by a crash mid-write, with nothing
  intact after it — is cut; it was never acknowledged. Anything else refuses to open with an error
  naming the segment and the offset: a damaged record followed by an intact one, an intact record
  out of sequence, or a log that begins past what the state file covers.
- **A record is the change set the write produced**, found by comparing every node with its
  last encoding: the nodes that are new or differ, whole, and the ids no longer reached. Correct for
  every route whatever it changed; finding it costs one encode of the forest under the lock, and
  the disk is written only the change. A log holding a *partial* node — one carrying
  `entries_before` or `children_kept`, which only a build with pdl's graph engine wrote — is
  refused at open rather than read as whole nodes.
- **The change sequence survives a restart.** The mutation stream numbers from the log's last
  record on open, so `/changes` and `/stream` cursors do not restart at one. A write that publishes
  more than one mutation per record can leave the restarted numbering below what a client saw; the
  stream's epoch is what tells that client the process restarted.
- **An encrypted store refuses `mode: tiered`**, with an error that says why: the sealed state
  file would have a plaintext log beside it.
- **A store holding an owned scope written before the split refuses `mode: tiered`**: the
  products that own it run under snapshot persistence only, so a store handed back to them must not
  have acquired a hot log. An extension that declares `Persistence: SnapshotOnly` is refused under
  tiered persistence at Open.

The version the engine answers with is on `GET /health`, which needs no credentials:

```bash
curl http://localhost:8080/health
# {"status":"ok","version":"0.3.0-alpha"}
```

### The object log

Beside the state file is `<name>.objects/`, an **append-only, content-addressed** store for bytes
that are history rather than working set: file contents, trees, commits. The state file holds the
whole forest — rewritten on every mutation in snapshot mode, and on every cold snapshot in tiered
mode — which is the right shape for the forest and the wrong shape for a record that only ever
grows, and the object log is where that record goes. **Writing an object never rewrites `.dat`** or
appends to its log, takes no forest lock, and announces nothing on `/stream`.

An object is an immutable byte string. Its **id is the BLAKE3-256 of its bytes**, as lowercase hex —
the same hash `ffi/canon` derives identities with — so the same content put twice is one object, an
id names bytes and not a place, and a put of bytes already held is a no-op that answers the same id
with `"existed": true`. **There is no delete.**

The directory holds numbered segments, `00000001.seg`, `00000002.seg`, …, each beginning with the
banner `LUMBERJACK-OBJECTS-1`. A record is the 32-byte id, a one-byte encoding flag, an 8-byte
little-endian payload length, the payload, and a CRC-32C over all of it. A segment rolls over at
256 MiB; a record is never split. **The index is derived, not stored**: every open rebuilds it by
scanning the segments, so the segments are the truth and there is no index file to disagree with
them.

**A put is not acknowledged until the record is on the disk** — the segment is synced after every
record, and a new segment and its directory entry are synced before the first record enters it,
the same discipline the state writer keeps. Because of that, at most **one** record can ever be
partial: the last one in the last segment. On open, a record the file does not have all of, or one
whose CRC fails and after which there is nothing but the end of the file or zeros, is a **torn
tail** — it was never acknowledged, and it is cut off. A record whose CRC fails and which is
**followed by more records** is corruption of something that was acknowledged: it is **not** cut
off, because the objects after it were acknowledged too. It is indexed as corrupt and `GET` answers
`500` naming the object as corrupt rather than `404`. Every read **re-hashes** the bytes against the
id, so a payload altered after the index was built is refused the same way.

**The per-object cap is `max_object_bytes`** in the process configuration, **64 MiB** when unset,
and deliberately far above the 10 MiB attachment limit. An oversized object is refused `413`
naming the cap and nothing is stored.

**Under an encrypted storage mode (`kms` or `local-test`), objects are sealed.** `<name>.objects/key`
holds a store id and a master key wrapped by the same KMS or local-test wrapper that wraps the state
file's keys; each object is sealed under its own random key with AES-GCM, that key sealed under the
master, with the object id in the additional data — the shape `secure_storage.go` gives a resource.
The plaintext is nowhere in the segment. **The id stays the BLAKE3 of the plaintext**, in the clear in
the record header, because content addressing requires the same bytes to have the same id in every
store; it follows that a sealed store discloses whether it holds a known file, which the sealed state
file does not. Objects are not re-keyed per snapshot and carry no per-account grants: an appended
record is never rewritten, and read access is the route's permission check. A plaintext object store
under an encrypted mode, or a sealed one under none, is **refused** — there is no object migration in
either direction, as there is none for the state file without the explicit opt-in.

## TODOS:
 - [ ] Improved Testing
    - [ ] Fix Testing Logging and Scoping to create Run directives
    - [ ] Remove redundant tests
    - [ ] Finish incomplete tests
 - [X] Refactor CLI types to work with the Core for directory structure
    - [X] Ensure logger is logging to the correct file
    - [X] Ensure the dat file is created and updated in the correct directory
    - [X] Move cli types to top level
 - [X] Add Core Logger
    - [X] Integrate debug logging into log file
 - [ ] Improve CLI
   - [X] Allow Multiple Databases and configs
   - [X] Add proper linux directory structure
   - [ ] Ensure delete commands require admin confirmation
   - [X] Update `list` command to use the proper ID
   - [X] Fix `delete` command to not delete all databases
   - [X] Test ALL commands
   - [ ] Test all Help commands
   - [X] have CLI daemonize API and Dashboard
   - [X] Remove Admin from Config
   - [ ] Add Windows Support
 - [ ] Test Dashboard Data Display and Interaction
    - [ ] Improve Top Bar integration
    - [ ] Add User Profile and Server Settings (if permissioned)
    - [X] Add Dashboard Login
    - [ ] Add API Event Logging
    - [ ] Add Node Level User Access Scoping
    - [ ] LogOut
    - [ ] MFA
    - [ ] Third Party Integration (Slack, Google Calendar, etc.)
 - [ ] Create Typescript module for direct API integration
 - [ ] Security
    - [ ] Add TLS
    - [ ] Improve Session Authentication for Database & Dashboard
    - [ ] Remove Session Token from frontend Cookie 
    - [ ] Remove Sensitive Data from logs
    - [X] Add JWT
    - [ ] Integrate for Certificate Authentication
    - [ ] Add Session Expiration
    - [ ] Add Session Refresh
  - [ ] Refactor
  - [ ] Create Proper Documentation

## Core Concepts

### Nodes
- **Branch Node**: Can contain other nodes
- **Leaf Node**: End points for tracking events
- Each node can have multiple parents, enabling flexible organizational structures

### Node paths
A path names a node by the sequence of names from the forest root down to it, and every route
EMITS the same form: rooted at the forest's own name, `forest/work/project-alpha`. It is rooted
because the root is a real node — it holds every user and is what a permission is granted on — and
a path that leaves it out has to call it the empty string, which no client can group on or link to.

The root-relative form is still ACCEPTED wherever a path is taken, so `work/project-alpha` and
`forest/work/project-alpha` name the same node, `forest` alone names the root, and
`forest/forest` names a child of the root that happens to be called `forest`.

### Events
An Event represents a tracked activity with start/end times and associated entries.

#### Attributes:
- `StartTime`: When the event begins
- `EndTime`: When the event concludes
- `Entries`: List of timestamped records
- `Metadata`: Custom event data
- `Status`: pending/ongoing/finished

### Entries
Timestamped records within an event.

#### Attributes:
- `Timestamp`: Creation time
- `Content`: Entry data
- `Metadata`: Additional entry info
- `UserID`: Creator identifier

## API Endpoints

### Authentication

#### Login
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password"
  }'
```

### Authentication Response
```json
{
  "session_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Attachments

An upload is stored **by its contents**: the bytes are read, hashed with sha256, and the hash is the
attachment's `id`. The same file uploaded twice is one stored attachment, and `GET /attachments/{id}`
returns exactly the bytes that went up.

**An id resolves without knowing where the file is kept.** A node holds attachments in more than one
place — its own store, its own entries, and the entries of each of its events and plans — and
`GET`/`DELETE /attachments/{id}` search all of them. The caller supplies the **node** (`path`) and the
**id**; which entry of which event the file was hung on is the engine's bookkeeping. Because the id
is the hash of the contents, an id names bytes rather than a place, so this cannot be ambiguous.

`DELETE /attachments/{id}` removes the file from **every** holder on that node that carries the id,
which is what keeps it consistent with the lookup. An id that is not on the node is `404`.

**The limit is 10,485,760 bytes (10 MiB) per file.** A larger upload is refused with
`413 Request Entity Too Large` and nothing is stored — it is not accepted and truncated. Both upload
routes below enforce it identically.

#### Upload Attachment
```bash
curl -X POST http://localhost:8080/attachments/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@/path/to/file.jpg" \
  -F "path=work/projects/project-alpha"
```

#### Get Attachment
Works for a file uploaded to the node and for one uploaded to an event entry alike.
```bash
curl -X GET http://localhost:8080/attachments/{id} \
  -H "Authorization: Bearer <token>" \
  -G --data-urlencode "path=work/projects/project-alpha"
```

#### Delete Attachment
```bash
curl -X DELETE http://localhost:8080/attachments/{id} \
  -H "Authorization: Bearer <token>" \
  -G --data-urlencode "path=work/projects/project-alpha"
```

#### Add Entry Attachment
```bash
curl -X POST http://localhost:8080/events/{eventId}/entries/{entryIndex}/attachments \
  -H "Authorization: Bearer <token>" \
  -F "file=@/path/to/file.jpg" \
  -F "path=work/projects/project-alpha"
```

### Attachment Response
The receipt never carries the file's bytes. `id` and `hash` are the same sha256, and `size` is the
number of bytes actually stored, not the size the upload declared.
```json
{
  "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "name": "document.pdf",
  "type": "application/pdf",
  "size": 1048576,
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "uploaded_by": "user-123",
  "uploaded_at": "2024-01-15T10:30:00Z"
}
```

### Objects

Raw bytes in, raw bytes out, addressed by their BLAKE3-256 — see *The object log* above for what is
on the disk. The permission is the **forest root's**: an object belongs to no node, so `POST` asks
for Write on the root and `GET`/`HEAD` for Read on it. A session granted only deeper than the root
is refused `403`. A malformed id is `400`; an unknown one `404`; an object whose stored bytes no
longer hash to their id is `500` and the message says so.

#### Put Object
The body is the object. The receipt's `size` is what was stored, and `existed` says the bytes were
already there — in which case nothing was written.
```bash
curl -X POST http://localhost:8080/objects \
  -H "Authorization: Bearer <token>" \
  --data-binary @/path/to/file
# {"id":"af13…","size":1048576,"existed":false}
```

#### Get Object
Answers `application/octet-stream` with `Content-Length`, verified against the id before a byte is
sent.
```bash
curl http://localhost:8080/objects/{id} -H "Authorization: Bearer <token>" -o file
```

#### Head Object
The same headers and no body; the size without the read.
```bash
curl -I http://localhost:8080/objects/{id} -H "Authorization: Bearer <token>"
```

**Through the in-process `call` path** (`ic_lj_application_call`, `embedded.ApplicationCall`) the
request and response are JSON envelopes whose `body` is a `[]byte`, which Go encodes as **standard
base64**: a binary object goes up as base64 in the request `body` and comes back as base64 in the
response `body`. The path's 64 MiB cap applies to the **decoded** bytes in each direction, so the
effective per-object limit through `call` is the smaller of `max_object_bytes` and 64 MiB, and the
envelope a C caller hands over is bounded by `LJ_MAX_IN_LEN` (256 MiB), which the base64 of a 64 MiB
object fits inside.

### Node Management

#### Create Node
Events are tracked on leaves, so a client creates the leaf it is going to track on. Missing
ancestors are created as branches, `type` defaults to `leaf`, and creating the same path twice
returns the same node.
```bash
curl -X POST http://localhost:8080/nodes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "type": "leaf"
  }'
```

### Create Node Response
```json
{
  "id": "user-1786229776411046621",
  "name": "project-alpha",
  "path": "forest/work/projects/project-alpha",
  "type": "leaf"
}
```

#### Get Forest

Filtered by the caller's permissions: a node the session may not read is not in the answer, and
neither are its own users, events or entries. A node granted DEEPER than the root still appears —
the projection descends through the ancestors the caller may not read rather than pruning at the
first refusal, which is the same rule `POST /query` applies.

The forest is a multi-parent DAG, so a node can be reached by more than one path. Each node's body
appears exactly ONCE in the document. Every later reach of it carries `"ref": true`, its id, its
name, its type and its parents, and empty `children`, `events`, `planned_events`, `users` and
`entries`; the body is elsewhere in the same document under the same id. A forest without shared
nodes is unaffected, because nothing in it is ever reached twice.

```bash
curl -X GET http://localhost:8080/forest \
  -H "Authorization: Bearer <token>"
```

#### Get Tree

The same projection over one subtree. A path the caller may not read is refused with 403, and a
path that does not exist with 404.

```bash
curl -X GET http://localhost:8080/forest/tree?path=work/projects \
  -H "Authorization: Bearer <token>"
```

#### Assign User
```bash
curl -X POST http://localhost:8080/users/assign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "assignee_id": "user123",
    "permission": "write"
  }'
```

### Event Management

#### Start Event
```bash
curl -X POST http://localhost:8080/events/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-1",
    "metadata": {
      "type": "sprint",
      "duration": "2 weeks"
    }
  }'
```

#### Plan Event
A plan is for an event that has **not started**. Planning over an `event_id` that is already a live
event on that node is refused with `409 Conflict` and nothing is written — one id is one event, and a
plan stored under a live id is invisible to `GET /events` and `POST /query`, which report the live
event for that id. Re-planning something that is still only a plan is allowed and moves it.
```bash
curl -X POST http://localhost:8080/events/plan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-2",
    "start_time": "2024-01-15T09:00:00Z",
    "end_time": "2024-01-29T17:00:00Z",
    "metadata": {
      "type": "sprint"
    }
  }'
```

#### Append to Event
```bash
curl -X POST http://localhost:8080/events/append \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-1",
    "content": "Completed user authentication feature",
    "metadata": {
      "type": "milestone"
    }
  }'
```

#### End Event
```bash
curl -X POST http://localhost:8080/events/end \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-1"
  }'
```

### Time Tracking

#### Start Time Tracking
```bash
curl -X POST http://localhost:8080/time/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha"
  }'
```

#### Stop Time Tracking
```bash
curl -X POST http://localhost:8080/time/stop \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha"
  }'
```

#### Get Time Tracking
**A scope is a subtree**, as it is on `/query`, `/aggregate`, `/entries` and `/events`: asking a branch
reports every span tracked on it and on everything beneath it, and each span names the node it was
tracked on in `node_path`. `scope` and `path` are the same parameter under two names. `depth` bounds
the walk — `depth=0` is the named node alone, an absent `depth` is unbounded.
```bash
curl -X GET http://localhost:8080/time \
  -H "Authorization: Bearer <token>" \
  -G --data-urlencode "scope=work/projects" --data-urlencode "depth=2"
```

### User Management

#### Create User

Administrative. Requires a session belonging to a user with Admin permission on the root of the
forest — there is no self-registration: an anonymous caller is refused with 401, and a
non-administrative session with 403.

```bash
curl -X POST http://localhost:8080/users/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin token>" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure_password"
  }'
```

#### Get Users

Administrative, like creating one: the list of every account in the install, their names, their
emails and what each of them may reach. A non-administrative session is refused with 403.

```bash
curl -X GET http://localhost:8080/users \
  -H "Authorization: Bearer <admin token>"
```

#### Get User Profile
```bash
curl -X GET http://localhost:8080/users/profile \
  -H "Authorization: Bearer <token>"
```

### Settings

#### Get Server Settings
```bash
curl -X GET http://localhost:8080/settings/ \
  -H "Authorization: Bearer <token>"
```

#### Update Server Settings
```bash
curl -X POST http://localhost:8080/settings/update \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "organization": "MyOrg",
    "server_port": "8080",
    "dashboard_url": "http://localhost:3000"
  }'
```

## Response Formats

### Event Summary Response
```json
{
  "event_id": "sprint-1",
  "status": "finished",
  "start_time": "2024-01-01T09:00:00Z",
  "end_time": "2024-01-14T17:00:00Z",
  "entries_count": 15,
  "metadata": {
    "type": "sprint",
    "team": "alpha"
  }
}
```

### Time Tracking Summary Response
`duration` is in **NANOSECONDS**. The same span is reported in **MILLISECONDS** as `duration_ms` by
`POST /query` with `"select": "time"`, and in **SECONDS** as `duration_sum` by `POST /aggregate`.
Three units for one quantity: each is named where it is returned, and none of the three wire values
has been changed.
```json
[
  {
    "node_path": "forest/work/projects/project-alpha",
    "start_time": "2024-01-04T09:00:00Z",
    "end_time": "2024-01-04T17:00:00Z",
    "duration": 28800000000000
  }
]
```

### Aggregate Bucket Keys
`POST /aggregate` answers with buckets, and a bucket's `key` **carries only the dimensions that
bucket has a value for**. Three different facts used to share one wire value — the empty string —
and a consumer reading the answer could not tell them apart:

| the fact | how the answer says it |
|---|---|
| the members carry no value for that dimension | the dimension is **absent from `key`** |
| the value is genuinely the empty string | the dimension is **present and `""`** |
| the selected kind has no such field at all | **400**, before any bucket is built |

An event that has not ended has no `end_time`, so bucketing on it puts that event in a bucket whose
`key` has no `day` — not in one named `""`. An event with no category has a category, and it is
`""`, so its bucket keeps the key. And a node has no status, no category and no event, so
`{"select": "nodes", "group": ["status"]}` is refused with
`cannot group nodes by "status": a node has no status` rather than answered with every node in one
nameless bucket. The same rule applies to `bucket_field`: a node carries no `start_time`, so asking
for one is a 400 and not an answer whose every bucket is blank.

Nothing was added to the wire to say this. A dimension with no value is the **absence of the key**,
which is what JSON already has a way to express and what a client that reads only the response can
already see.

## Error Handling
All endpoints return standard HTTP status codes:
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 409: Conflict (a plan for an event id that has already started)
- 413: Request Entity Too Large (an upload over the attachment size limit, or an object over `max_object_bytes`)
- 500: Internal Server Error

Error responses include a message:
```json
{
  "error": "Invalid event ID format"
}
```
