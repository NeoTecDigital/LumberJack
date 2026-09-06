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

The version the engine answers with is on `GET /health`, which needs no credentials:

```bash
curl http://localhost:8080/health
# {"status":"ok","version":"0.3.0-alpha"}
```

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
- 413: Request Entity Too Large (an upload over the attachment size limit)
- 500: Internal Server Error

Error responses include a message:
```json
{
  "error": "Invalid event ID format"
}
```
