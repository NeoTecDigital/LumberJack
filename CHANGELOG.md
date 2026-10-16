<!-- Written by Richard Christopher, Copyright 2026 Richard Christopher -->

# Changelog

All notable changes to Lumberjack. The version the engine answers with is on `GET /health`.

## Unreleased

### Tiered persistence

A write now costs the size of the change, not the size of the store. Opt in with `mode: tiered`
in the `persistence` block of `config.yaml`; the default, `snapshot`, is exactly what every
earlier build did.

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
- **The graph engine hands persistence its changed nodes**, so a command on a ten-thousand-entity
  graph logs the nodes it wrote and not the graph. A journal entry on the graph root is logged as
  the entry appended, and an unchanged child list is not logged at all. Other writers log what a
  whole-forest comparison finds changed.
- **The hub is told from the change set.** The two walks of the whole forest that bracketed every
  write when the application hub was enabled no longer run for a graph command, in either mode.
- **The change sequence is durable.** The mutation stream's numbering continues from the log's
  last record after a restart instead of starting again at one.
- **A sync hook** receives every record after its local append. `sync.role` accepts `single`,
  `primary` and `replica`; only `single` runs in this build, and the others are refused at open
  with an error that says so.
- **An encrypted store refuses `mode: tiered`**: the log would hold plaintext beside the sealed
  state file.
- The embedded runtime reads the two blocks from `<database_path>/config.yaml`; the CLI reads
  them from its own `config.yaml`.

### Graph command engine

Routes under `/graph`: `POST /graph/commands` commits one atomic batch of `put` and `delete`
operations over entities, occurrences, edges, views and aliases, validated against expected
revisions and topology revisions; `GET /graph` is the whole graph; `GET /graph/events` pages the
journal; `GET /graph/commands/{id}` reads a receipt.

- The graph lives in the forest under the `graph` root, written by the same lock and the same
  writer as every other change. Only the engine writes beneath it: every generic write route
  answers 403 for a target there.
- A deleted record keeps its node as a **tombstone**, with its history; re-creating the id
  continues from the tombstone's revision and kind.
- **Receipts never expire.** A command retried with the same id replays its first result; the
  same id with different content is a conflict. A 5xx means the outcome is unknown and the caller
  retries the same id; a new command is refused with 503 while a failed write is still
  outstanding, and any command first retries that write.
- **A replay is never acknowledged before the command is durable.** A retry of an id whose write
  failed first makes that write durable under the configured policy — the state file in snapshot
  mode, the log in tiered mode — and is answered 5xx again if that fails, rather than `200` with
  `replayed: true` on the strength of a receipt the disk does not yet hold. Pinned in both modes
  by a test that refuses the disk, retries, restores it and reopens.
- **The reads show nothing the disk does not hold.** `GET /graph`, `GET /graph/events` and
  `GET /graph/commands/{id}` first retry an outstanding failed write — or, in tiered mode, a
  failed append or sync — and answer 503 `unavailable` while the store is still behind, instead of
  serving a receipt, a revision or a journal entry held only in memory.
- The engine keeps the graph decoded between commands and checks each command against what it
  touches, so a command costs what it changes.

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
