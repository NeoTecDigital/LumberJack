/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Non-commercial use only; see LICENSE. */
#ifndef LUMBERJACK_H
#define LUMBERJACK_H

/* THIS HEADER IS THE SPECIFICATION.
 *
 * The Go side is written to match it, never the reverse. `make header-check` compiles a
 * translation unit that includes both this file and the one cgo generates, so a divergence
 * between them is a compile error rather than a diff somebody has to notice.
 *
 * Nothing here allocates on one side and frees on the other. Every output buffer is the
 * caller's, and there is deliberately no free function: a C ABI with one has a lifetime
 * contract across the boundary, and that is where the double-frees live.
 *
 * NEVER LINK TWO GO c-archives INTO ONE BINARY. The Go runtime symbols collide, and
 * `--allow-multiple-definition` does not fix it — it produces two Go runtimes in one
 * address space, which is worse than a link error because it starts. */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The ABI this header describes. A caller checks it before anything else; a mismatch means
 * the archive and the header came from different builds.
 *
 * VERSION 2 widened every length — in_len, req_len, out_cap and *out_len — from int32_t to
 * int64_t. At 32 bits a document of 2^31 bytes or more reported a NEGATIVE *out_len, which then
 * compared below out_cap and answered LJ_OK for a partial document copied over a whole-document
 * buffer: the one lie the boundary exists to prevent. A stale v1 archive linked against a v2
 * binding is caught at open, not silently, because the binding checks this number first.
 *
 * STILL VERSION 2 after LJ_UNGUARDED and ic_lj_adopt: a new status value and a new export are
 * ADDITIVE — a caller built against the earlier v2 header links and runs unchanged, and one built
 * against this header fails to LINK, not to run, against an archive without ic_lj_adopt. Changing or
 * renumbering an existing status or signature is what would make this 3. */
#define LJ_ABI_VERSION 2u

/* An opaque TOKEN for an open runtime: a monotonic counter the Go side maps to a runtime, never an
 * address and never recycled. C must not dereference it; a stale token cannot alias a live runtime,
 * it simply fails to resolve. It is deliberately NOT a runtime/cgo.Handle, whose slots can be reused
 * after Delete — a token that never repeats is what makes use-after-close a clean LJ_BAD_HANDLE. */
typedef uint64_t lj_handle_t;

/* What a call did. Values below LJ_TRUNCATED mirror the engine's own HTTP statuses, which
 * it already carries as data; the rest are facts about this boundary and have no HTTP
 * counterpart. */
typedef int32_t lj_status_t;

/* A borrowed, read-only input buffer. Named so that the const survives into the header cgo
 * generates: cgo renders a `*C.char` as a bare `char *`, which would drop the one thing
 * this type is here to say — the callee does not write through it, and the caller may free
 * it the instant the call returns. */
typedef const char *lj_cstr;

#define LJ_OK              0
#define LJ_INVALID         1   /* 400 — a well-formed request that is wrong                */
#define LJ_UNAUTHENTICATED 2   /* 401 — reserved; the FFI has no session to be missing     */
#define LJ_FORBIDDEN       3   /* 403 — the principal may not                              */
#define LJ_NOT_FOUND       4   /* 404 — no such node, event or entry; adopt: no state file */
#define LJ_CONFLICT        5   /* 409 — already started, id taken; adopt: sidecar present  */
#define LJ_TOO_LARGE       6   /* 413 — over a declared limit                              */
#define LJ_INTERNAL        7   /* 500, and every error carrying no status of its own       */
#define LJ_TRUNCATED       8   /* success; the document did not fit, *out_len is its size  */
#define LJ_BAD_HANDLE      9   /* never opened, or opened and closed                       */
#define LJ_CLOSED         10   /* closing underneath this call                             */
#define LJ_PANIC          11   /* a Go panic was recovered; the process survived           */
#define LJ_CODEC          12   /* the envelope would not parse or emit                     */
#define LJ_GAP            13   /* stream: the cursor is older than the replay ring         */
#define LJ_LOCKED         14   /* open: another runtime holds this state file; RETRY      */
#define LJ_BUSY           15   /* 429 — the worker pool is saturated; retry                */
#define LJ_UNGUARDED      16   /* open: a state file with no lock sidecar; DO NOT RETRY    */

/* LJ_LOCKED and LJ_UNGUARDED are two statuses because they call for opposite actions. LJ_LOCKED is
 * transient: another process has the sidecar flocked now, and the refusal lifts when it lets go, so
 * a caller retries with a back-off. LJ_UNGUARDED is PERMANENT: the state file is there and its
 * `<state>.lock` is not — a forest written before the sidecar existed, a backup restored without it,
 * or a sidecar that was deleted, possibly while another process still held it — and nothing a caller
 * does short of ic_lj_adopt clears it. Under one status a caller that backed off correctly on the
 * first would back off forever on the second. */

/* Bounds that make the no-truncated-mutation guarantee PROVABLE. LJ_MAX_PATH caps the one unbounded
 * field a mutation's acknowledgement carries — the node path, and the event id read back with it —
 * and LJ_MUTATION_OUT_MIN is a buffer large enough to hold any such acknowledgement given that cap.
 * A mutation is refused before it runs when out_cap is smaller, so a write can never happen and then
 * fail to be acknowledged: a write the caller does not know it made is the one failure a store may
 * not have. Reads have no such floor — they may answer LJ_TRUNCATED and be retried, because a read
 * that did not fit changed nothing. */
#define LJ_MAX_PATH          4096
#define LJ_MUTATION_OUT_MIN  16384

/* The inbound ceiling: the most a single call's req_len (or echo's in_len) may be before it is
 * refused LJ_TOO_LARGE. It exists because the binding COPIES the request into its own memory, so an
 * unbounded in_len is an unbounded allocation per call. It is declared here, not just enforced, so a
 * caller can size its requests against the same number the binding checks. It is far above any real
 * request — a mutation's path is capped at LJ_MAX_PATH — and comfortably above LJ_MUTATION_OUT_MIN. */
#define LJ_MAX_IN_LEN        (256 * 1024 * 1024)

/* YAML ON THE WIRE, JSON ON THE ROUTES. The document names are the HTTP surface's json names exactly,
 * because the codec re-encodes through JSON rather than tagging sixteen structs twice. Typed fields
 * are carried faithfully in BOTH directions — including large integers: epoch, oldest and sequence
 * are UnixNano-scale, past 2^53, and the codec preserves them exactly (it decodes the JSON hop with
 * UseNumber rather than widening every number to a lossy float). One caution the emitter cannot
 * remove: on the INBOUND side, a bare scalar in `metadata` — 0123, null, ~, 2026-01-01 — is resolved
 * by the YAML parser into an int, a nil or a timestamp before it is a string. Typed fields (path,
 * event_id, content) are safe; metadata is not. QUOTE identity-bearing metadata values that could be
 * read as a number, a date, a bool or null. */

/* The ABI version this archive implements. Takes no handle, cannot fail, cannot panic. */
uint32_t ic_lj_abi_version(void);

/* Open a runtime over a state file and bind a principal, returning a TOKEN for it in *out_handle.
 *
 * `req` is a YAML document carrying the config (organization, process.database_path, process.name)
 * and the principal to act as. Idempotent per state path WITHIN a process: a second open of the same
 * file shares one refcounted runtime, and the last close tears it down. Another PROCESS holding the
 * same file is refused LJ_LOCKED — the lock is a sidecar `<state>.lock` that survives the snapshot
 * rename a persist performs — and a state file with NO sidecar beside it is refused LJ_UNGUARDED,
 * which only ic_lj_adopt clears. The token is never recycled, so a stale one cannot alias a live
 * runtime; it is a value, never an address, and C must not dereference it. */
lj_status_t ic_lj_open(lj_cstr req, int64_t req_len, lj_handle_t *out_handle);

/* Adopt a state file that has no lock sidecar, so an open refused LJ_UNGUARDED can succeed. `req`
 * is a YAML document carrying `database_path` and `name`, the two fields of an open request that
 * name the state file. It mints the empty `<state>.lock` beside the state file and answers LJ_OK;
 * the same act as a `touch` by hand, with the checks. It is the caller's ASSERTION that no other
 * process holds the file — a sidecar deleted while held leaves its holder on an unlinked inode
 * nothing can find, so this cannot be checked here, which is why it is a separate explicit call and
 * not an option on open.
 *
 * ONE-SHOT, deliberately: LJ_CONFLICT when the sidecar is already there (nothing to adopt), and
 * LJ_NOT_FOUND when there is no state file (a fresh path mints its own sidecar on open). The act is
 * logged to stderr.
 *
 * THE HONEST LIMIT: one-shot is per MISSING-SIDECAR EPISODE, not per forest. If the sidecar is
 * deleted again while a holder is live, adopt succeeds again — it cannot see the holder — and the
 * next open brings up a rival runtime beside the live one, last-writer-wins. So the guard is NOT
 * this call's refusal; the guard is that open NEVER adopts, and that a caller runs adopt only by
 * a human's decision, on that human's word that nothing holds the file. An adopt automated in front
 * of every open is protected by LJ_CONFLICT only while the sidecar survives, and only if the caller
 * treats LJ_CONFLICT as fatal rather than as "already done". Do not automate it. */
lj_status_t ic_lj_adopt(lj_cstr req, int64_t req_len);

/* Close a handle. IDEMPOTENT: closing a handle that was never opened, or was already closed, is LJ_OK
 * and not an error. The runtime is torn down only when its last handle closes; a data call on a
 * closed handle is LJ_BAD_HANDLE, never a hang. */
lj_status_t ic_lj_close(lj_handle_t h);

/* The data operations, ALL of one shape:
 *
 *   lj_status_t ic_lj_OP(lj_handle_t h, lj_cstr req, int64_t req_len,
 *                        char *out, int64_t out_cap, int64_t *out_len);
 *
 * `req` is a YAML request; the answer is written to `out` as a YAML document, `*out_len` its size,
 * and the return value is the status of the CALL. The principal is the handle's; requests carry only
 * the operation's own fields. A read that does not fit answers LJ_TRUNCATED, writes NOTHING, and sets
 * `*out_len` to the size to retry with. A MUTATION (node_create, event_plan, event_start,
 * event_append, event_end) is refused LJ_INVALID before it runs if out_cap < LJ_MUTATION_OUT_MIN, and
 * LJ_TOO_LARGE if its path or event id exceeds LJ_MAX_PATH — so its acknowledgement provably fits and
 * it never runs unacknowledgeably. A negative req_len is LJ_INVALID; a req_len past LJ_MAX_IN_LEN is
 * LJ_TOO_LARGE, so no single call can demand an unbounded copy of the request into the binding. */
lj_status_t ic_lj_node_create(lj_handle_t h, lj_cstr req, int64_t req_len,
                              char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_event_plan(lj_handle_t h, lj_cstr req, int64_t req_len,
                             char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_event_start(lj_handle_t h, lj_cstr req, int64_t req_len,
                              char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_event_append(lj_handle_t h, lj_cstr req, int64_t req_len,
                               char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_event_end(lj_handle_t h, lj_cstr req, int64_t req_len,
                            char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_event_entries(lj_handle_t h, lj_cstr req, int64_t req_len,
                                char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_query(lj_handle_t h, lj_cstr req, int64_t req_len,
                        char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_aggregate(lj_handle_t h, lj_cstr req, int64_t req_len,
                            char *out, int64_t out_cap, int64_t *out_len);
lj_status_t ic_lj_forest(lj_handle_t h, lj_cstr req, int64_t req_len,
                         char *out, int64_t out_cap, int64_t *out_len);

/* stream_poll subscribes PER POLL from the mutation ring and holds no goroutine between calls. The
 * request carries {after, epoch, timeout_ms}; the answer carries {events, epoch, caught_up, oldest}.
 * When the cursor has fallen off the back of the ring — or its epoch is not this run's, because
 * sequences live only in memory and restart afresh — the status is LJ_GAP and the answer's `oldest`
 * is the sequence to re-derive from. A poll blocks up to timeout_ms for the next mutation; a close
 * returns it at once. timeout_ms is CLAMPED to five minutes — a longer wait is served by polling
 * again, and the cap keeps the millisecond conversion from overflowing into a negative, instant
 * return — and a NEGATIVE timeout_ms is refused LJ_INVALID rather than treated as zero. */
lj_status_t ic_lj_stream_poll(lj_handle_t h, lj_cstr req, int64_t req_len,
                              char *out, int64_t out_cap, int64_t *out_len);

/* Copy `in` to `out`, so a caller can prove the buffer convention end to end before
 * trusting it with a forest.
 *
 * The convention, which every call below shares: `*out_len` describes the DOCUMENT and the
 * return value describes the CALL. When `out_cap` is too small this answers LJ_TRUNCATED,
 * writes NOTHING to `out`, and sets `*out_len` to the size required — a partial document is
 * worse than none, because a caller cannot tell one from a whole one. */
lj_status_t ic_lj_echo(lj_cstr in, int64_t in_len,
                       char *out, int64_t out_cap, int64_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* LUMBERJACK_H */
