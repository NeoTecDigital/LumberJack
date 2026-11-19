<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Record commands: C interface, version 1

Use one Go archive per executable. The generic archive exports this family in addition to the unchanged base ABI v2. To include the optional family in a custom archive, run the same wrapper generator a second time, e.g. `go run ./ffi/gen -records -include /../ffi > record_exports.go` from the module with output directed to the archive's main package; set the include directory relative to the generated file. The normal generator output is unchanged. Do not link the generic archive alongside a custom archive.

This implementation is **single owner, plaintext, local sync**. Its acknowledgement survives a successful local durability barrier, not loss of the machine. Do not use it where replicated durability, sealed storage, shared grants or extension hooks are required. Registered base extensions conflict rather than being silently bypassed. Use a fresh dedicated directory: a pointer store, an existing store configuration or an incompatible storage mode is refused. No conversion takes place. The trusted embedding host authenticates the caller, authorizes the selected directory and name, and supplies the principal at open. These are not user-controlled request parameters.

## Lifecycle

All calls below are declared in `ffi/lumberjack.h`. Status, length, and handle types use its base definitions. Request lengths and output sizes are **bytes**. Output is one JSON document, not NUL-terminated; on success use its returned length. For example (inside a C function with the header and `<string.h>` included):

```c
if (ic_lj_record_abi_version() != 1) return LJ_INVALID;
const char *req = "{\"directory\":\"/var/lib/example/records\",\"name\":\"s\","
                  "\"principal\":\"owner\",\"durability\":\"local-sync\"}";
lj_handle_t h = 0;
lj_status_t st = ic_lj_record_open(req, strlen(req), &h);
if (st != LJ_OK) return st;
char out[4096];
int64_t n = 0;
const char *cmd = "{\"command_id\":\"c1\",\"edits\":[{\"op\":\"create\",\"kind\":\"ticket\"}]}";
st = ic_lj_record_apply(h, cmd, strlen(cmd), out, sizeof out, &n);
/* A truncated receipt is already committed: retry identical cmd with n bytes. */
if (st == LJ_OK) {
    const char *q = "{\"by\":\"kind\",\"kind\":\"ticket\",\"limit\":10}";
    st = ic_lj_record_page(h, q, strlen(q), out, sizeof out, &n);
}
lj_status_t closed = ic_lj_record_close(h);
return st == LJ_OK ? closed : st;
```

- `ic_lj_record_abi_version()` returns the record protocol version, independent of `ic_lj_abi_version()`. Bind callers compiled for it to an archive exporting this family.
- `ic_lj_record_open(req,n,&h)`: absolute directory, one path-component name, authenticated principal, explicit durability mode; the first open creates the marker and binds its owner. A populated, clean open requires no state update. Different handles for the same owner share one runtime; different owners are refused.
- `ic_lj_record_apply(h,req,n,out,cap,&len)`: validate, commit and return e.g. `{"command_id":"c1","sequence":1,"created":["node-…"]}`. A repeat returns the original receipt; a changed request with the same ID conflicts. Keep IDs through timeouts. A success or truncation is never a promise of off-machine durability.
- `ic_lj_record_page(h,req,n,out,cap,&len)`: reads committed data. Example `{"sequence":1,"items":[{"id":"node-…","kind":"ticket","revision":1,"topology":0}]}`. Truncation returns the required size and no partial document.
- `ic_lj_record_close(h)`: release this token. Repeat close is harmless; later apply/page on it returns `LJ_BAD_HANDLE`. Use the matching family, not a pointer-handle operation.

Provide a non-null output buffer and length pointer. If `LJ_TRUNCATED`, allocate the reported size within your service's budget and repeat the original request. Other relevant statuses: invalid input, too large, forbidden owner, missing record, revision/identity conflict, and busy when durability is unresolved. A transport error or absent response is not proof of refusal: recover/retry the same command. Do not dispatch an external effect on the basis of a timeout or a merely local receipt where remote durability is required.

## Edits and expectations

A request is at most 1 MiB, 1–256 edits, and at most 768 expectation entries. Supply a nonempty command ID up to 256 bytes. Receipt scope is the store and authenticated issuer. An optional create ID must be exactly 64 lowercase hexadecimal digits and unused; omit the member to mint. Do not use content equality as an occurrence ID. `$0`, `$1`, etc. refer to **earlier create edit positions** in this command, indexed from zero. `root` is the initial node (both revisions zero).

```json
{"command_id":"c2","expected":{"root":{"topology":0}},"edits":[
  {"op":"create","kind":"ticket"},
  {"op":"field","id":"$0","key":"title","value":"Example"},
  {"op":"slot","id":"$0","key":"codec-v3","value":{"integer":9007199254740993}},
  {"op":"append","id":"$0","value":{"text":"opened"}},
  {"op":"link","parent":"root","child":"$0"}
]}
```

`field` and `slot` replace one named JSON value; `unset_field` and `unset_slot` take ID and key (no value). `append` adds one entry, not a replacement list. `link`/`unlink` change one named pair, reject duplicates/missing edges and prevent cycles. `delete` takes one ID, removes incident links, and reserves its ID as a tombstone. No delete of root. For existing records supply their current data revision for content edits and current topology revision for both endpoints of each changed link. Delete requires both revisions of its target and topology for neighbors. Values are exact integers or raw JSON, never coerced through binary floating point. Reads return JSON values, not a whitespace-preserving wire rendering.

All supplied expectations apply to the state **before** the command. Each touched revision advances once per command; no separate expectation is needed for its own new records. An invalid last edit publishes none of the earlier ones. One frame stores explicit edits, minted IDs, prefix length (including zero) for each append, and receipt identity. A complete recovered local frame is synced before a receipt is returned.

## Page requests

| Operation | Example | Continuation |
|---|---|---|
| Record and entries | `{"by":"id","id":"root","limit":50}` | Supply `offset` from `next_offset` and the returned `sequence` for more entries. Fields and slots are not paged. |
| Direct children | `{"by":"children","id":"root","limit":50}` | Supply `after` from `next` and `sequence`. |
| Kind | `{"by":"kind","kind":"ticket","limit":50}` | Same; rows ordered by ID. |

The default limit is 50; maximum 256. A continuation is a keyset/offset at the **current** sequence, not a retained snapshot. Restart if the sequence changed. A record absent or tombstoned returns not found. Row summaries never contain a parent's entire child list. The resident implementation scans and sorts for list pages; the API bounds returned rows, not total work or the size of one field.
