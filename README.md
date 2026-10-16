# LumberJack API Documentation
![lumberjack500](https://github.com/user-attachments/assets/1f1c2f9e-a550-47eb-8f18-a11abbc1cf58)
## Overview
The LumberJack API provides a hierarchical event tracking system where nodes can have multiple parents and events can be tracked across different organizational paths.

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

Rewriting the whole file per write costs the size of the store: measured through the graph
engine, 101 ms per command at 2,000 records and 527 ms at 10,000, growing with every write ever
made because receipts, journal and history accumulate. `mode: tiered` makes a write cost the size
of the change.

- **Hot layer.** Every commit appends one record to an append-only log beside the state file,
  `<name>.dat.log.<sequence>`: a sequence number, the nodes it changed (each encoded as the state
  codec encodes a node), the ids it deleted, a length and a checksum. **A 200 means the record is
  as durable as `hot_sync` asks**: `commit` syncs it before answering; `interval` answers once it
  is written and syncs in the background every `hot_sync_interval_ms`; `none` leaves the sync to
  the operating system. Concurrent commits share one write and one fsync. A record that fails to
  reach the disk is retried ahead of the next commit, and the engine refuses new graph commands
  until it lands.
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
- **The graph engine hands the log its changed nodes.** A command logs the nodes it wrote: the
  record's node with its new history entry, the receipt, and the graph root with the one journal
  entry it appended — not the whole journal, and not the root's child list when no entity moved.
  Every other write route logs what a comparison of the whole forest against its last encoding
  finds changed; correct, and the size of the forest.
- **The change sequence survives a restart.** The mutation stream numbers from the log's last
  record on open, so `/changes` and `/stream` cursors do not restart at one.
- **An encrypted store refuses `mode: tiered`**, with an error that says why: the sealed state
  file would have a plaintext log beside it.

### Where the graph lives

The command engine behind `/graph` (see **Graph** under API Endpoints) keeps **no file of its own**.
Everything it holds is in the forest, under one child of the root named `graph`, written by the
same lock and the same writer as every other change — so a `200` from `POST /graph/commands` is the
same promise as every other `200` above, and a restart loses nothing it acknowledged.

- **Each entity is a node** under `graph`. Containment is parentage: an entity with an occurrence
  in a scope is a child of that scope's node, and one in no scope hangs from `graph` itself.
- **Occurrences, edges, views, aliases and command receipts** are nodes under `graph/_occurrences`,
  `graph/_edges`, `graph/_views`, `graph/_aliases` and `graph/_commands`.
- A record is stored on its node as **JSON text** under `metadata["graph.record"]`, byte for byte,
  so integer geometry and revisions never pass through a float.
- **Every command appends one journal entry** to the `graph` node — revision, command id, actor,
  time and the list of changes — which is what `GET /graph/events` pages, so the journal survives a
  restart. **Every put appends one history entry** to the record's own node, holding the prior
  value, the command id and the actor. **Receipts never expire**: a retry replays, years later.
- **A delete keeps the node.** The record text is replaced by a **tombstone** under
  `metadata["graph.tombstone"]` — the record's last revision, its kind and the value it held — and a
  history entry records the delete, so nothing the node's history held is lost. A bucketed record's
  tombstone stays in its bucket; a deleted entity leaves the containment tree for
  `graph/_tombstones`. Re-creating the id takes the same node up again.
- **Only the engine writes beneath `graph`.** Every generic write route — `POST /nodes`,
  `PATCH /nodes/{path}/metadata`, `DELETE /nodes/{path}`, `/nodes/link`, `/entries`, `/events`,
  `/time`, `/attachments`, `/workspace/commands` — answers **403** for a target that is `graph` or
  anything under it, whoever asks. The generic *read* routes still show it.
- **The `graph` node is created by the first command, for the principal that sent it and no one
  else.** It does not inherit the forest root's users: holding Write on the forest root is not
  holding anything on the graph. Its creator is its Admin and grants others through `/access`.
- The engine keeps the graph **decoded in memory** between commands and checks each command against
  what it touches, so a command costs what it changes rather than what the graph holds. The forest
  is still the only store: the copy is rebuilt from it on open.
- Node ids are namespaced by collection (`graph:entities:<id>`, `graph:occurrences:<id>`, …) because
  the state file keys its node table by id and an entity and an occurrence may share one.

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

### Graph

The command engine: a graph of **entities**, **occurrences** (an entity placed in a scope, with
fixed-point geometry), **edges**, **views** and **aliases**, changed only through **all-or-nothing
commands** that name the revisions they replace. The routes sit on the main router behind the same
session as everything else. A command needs **Write** on the `graph` node and the reads need
**Read**; until the first command creates that node the check is on the forest root, and the
principal whose command creates it becomes its only member. State lives in the forest — see *Where
the graph lives* above.

#### Read the graph
```bash
curl http://localhost:8080/graph -H "Authorization: Bearer <token>"
# {"revision":3,"entities":{...},"occurrences":{...},"edges":{},"views":{},"aliases":{}}
```

#### Commit a command
Every entity write names the revision it replaces (`0` to create); every membership or edge change
names the `topology` revision of each scope it touches. An entity is `id` (64 lowercase hex) and a
nonblank `kind`, both immutable after creation; `revision` and `topology_revision` are the engine's
and a put that omits them does not erase them. A put's `value.id` may be left out; one that is
present and differs from the operation's `id` is refused `400`, naming both. A batch is applied
whole or not at all. The body takes exactly `id`, `fingerprint`, `actor`, `expected` and
`operations` — any other field is `400`.
```bash
curl -X POST http://localhost:8080/graph/commands \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{
    "id": "cmd-1", "fingerprint": "sha256-of-the-intent", "actor": "agent:planner",
    "expected": {"entities": {"<scope>": 0, "<task>": 0}, "occurrences": {"<occ>": 0}, "topology": {"<scope>": 0}},
    "operations": [
      {"op": "put", "collection": "entities", "id": "<scope>", "value": {"id": "<scope>", "kind": "scope"}},
      {"op": "put", "collection": "entities", "id": "<task>", "value": {"id": "<task>", "kind": "task"}},
      {"op": "put", "collection": "occurrences", "id": "<occ>", "value": {"id": "<occ>", "entity_id": "<task>", "scope_id": "<scope>",
        "geometry": {"x": 0, "y": 0, "width": 1000, "height": 1000, "scale": 1000000}}}
    ]
  }'
# {"command_id":"cmd-1","revision":1,"changes":[{"collection":"entities","id":"<scope>","revision":1,"op":"put"},...],"replayed":false}
```
Resending the same `id` with the same payload **replays** the stored result with `"replayed": true`
— after a restart too. The same `id` with a different payload is `409`. "The same payload" is the
body as it was sent: an `actor` that was left out is compared as left out, whichever session
retries, and it is recorded as that session's user. A stale revision is `409` and names what
disagreed:
```json
{"error":{"code":"conflict","message":"occurrences \"<occ>\" expected 0, current 1","collection":"occurrences","id":"<occ>","expected":0,"actual":1}}
```

**Deleting and re-creating.** A deleted record is in no collection of `GET /graph`, but its id is
not new again: it stays at the revision it was deleted at. Re-creating it names that revision as
`expected` (naming `0` is the `409` above, whose `actual` is the revision to name), continues the
count from there, and — for an entity — must keep the kind it had. A writer that last saw the
record before it was deleted therefore cannot write over what replaced it.

**A `5xx` means the outcome is unknown: retry the same command `id`.** The command may have been
applied in memory and not reached the disk. Retrying the same `id` is always safe — a command that
was applied is replayed and flushed again, and one that was not is simply a new command — and is
how the caller finds out. While a failed write is outstanding every command first tries to write
the forest again, so once the disk has recovered a new command succeeds and takes the earlier one
to the disk with it — a caller that no longer knows the failed `id` needs nothing else. Only while
that write still fails is every *other* command refused `503` (`"code":"unavailable"`), changing
nothing.

#### Page the journal
```bash
curl "http://localhost:8080/graph/events?since=0&limit=500" -H "Authorization: Bearer <token>"
# {"events":[{"revision":1,"command_id":"cmd-1","actor":"agent:planner","at":"...","changes":[...]}],"next":500}
```
`limit` defaults to 500 and is capped at 5000; `next` is present when there is more, and is the
`since` that fetches it.

#### Read a receipt
```bash
curl http://localhost:8080/graph/commands/cmd-1 -H "Authorization: Bearer <token>"
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
