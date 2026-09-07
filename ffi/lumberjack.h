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
 * the archive and the header came from different builds. */
#define LJ_ABI_VERSION 1u

/* An opaque TOKEN for an open runtime. It is a `runtime/cgo.Handle`, never an address:
 * C must not dereference it, and it carries no information about the process layout. */
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
#define LJ_NOT_FOUND       4   /* 404 — no such node, event or entry                       */
#define LJ_CONFLICT        5   /* 409 — already started, id taken, already exists          */
#define LJ_TOO_LARGE       6   /* 413 — over a declared limit                              */
#define LJ_INTERNAL        7   /* 500, and every error carrying no status of its own       */
#define LJ_TRUNCATED       8   /* success; the document did not fit, *out_len is its size  */
#define LJ_BAD_HANDLE      9   /* never opened, or opened and closed                       */
#define LJ_CLOSED         10   /* closing underneath this call                             */
#define LJ_PANIC          11   /* a Go panic was recovered; the process survived           */
#define LJ_CODEC          12   /* the envelope would not parse or emit                     */
#define LJ_GAP            13   /* stream: the cursor is older than the replay ring         */
#define LJ_LOCKED         14   /* open: another runtime holds this state file              */

/* The ABI version this archive implements. Takes no handle, cannot fail, cannot panic. */
uint32_t ic_lj_abi_version(void);

/* Copy `in` to `out`, so a caller can prove the buffer convention end to end before
 * trusting it with a forest.
 *
 * The convention, which every call below shares: `*out_len` describes the DOCUMENT and the
 * return value describes the CALL. When `out_cap` is too small this answers LJ_TRUNCATED,
 * writes NOTHING to `out`, and sets `*out_len` to the size required — a partial document is
 * worse than none, because a caller cannot tell one from a whole one. */
lj_status_t ic_lj_echo(lj_cstr in, int32_t in_len,
                       char *out, int32_t out_cap, int32_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* LUMBERJACK_H */
