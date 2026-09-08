/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Non-commercial use only; see LICENSE. */

/* This translation unit exists to be COMPILED, never linked or run.
 *
 * ffi/lumberjack.h is the specification and cgo's generated header is an artefact of the
 * build. Including both in one unit makes a divergence between them a compile error, which
 * somebody finds, rather than a diff between two files, which nobody reads. A signature
 * that drifts is caught here at -Werror.
 *
 * Same intent as intercessor's `make header-check` over include/intercessor.h.
 *
 * It lives in ctest/ rather than beside the header it checks because cgo compiles EVERY .c
 * file in its package directory as part of the package. A checking file placed there would
 * be built into the archive it is meant to check, and `go build ./...` would fail on an
 * include of a header the build has not generated yet. */

#include "lumberjack.h"          /* the specification */
#include "liblumberjack.h"       /* what cgo generated from ffi/main.go */

/* Each check names the declaration it is holding to account. A pointer to a function is
 * only assignable from one of exactly its type, so a changed parameter or return type
 * fails to compile rather than warning. */

static uint32_t (*const check_abi_version)(void) = ic_lj_abi_version;

static lj_status_t (*const check_echo)(const char *, int32_t,
                                       char *, int32_t, int32_t *) = ic_lj_echo;

/* Lifecycle. */
static lj_status_t (*const check_open)(lj_cstr, int32_t, lj_handle_t *) = ic_lj_open;
static lj_status_t (*const check_close)(lj_handle_t) = ic_lj_close;

/* The data operations. Every one is held to the same shape; a changed parameter fails to compile. */
typedef lj_status_t (*lj_data_op)(lj_handle_t, lj_cstr, int32_t, char *, int32_t, int32_t *);
static const lj_data_op check_node_create   = ic_lj_node_create;
static const lj_data_op check_event_plan    = ic_lj_event_plan;
static const lj_data_op check_event_start   = ic_lj_event_start;
static const lj_data_op check_event_append  = ic_lj_event_append;
static const lj_data_op check_event_end     = ic_lj_event_end;
static const lj_data_op check_event_entries = ic_lj_event_entries;
static const lj_data_op check_query         = ic_lj_query;
static const lj_data_op check_aggregate     = ic_lj_aggregate;
static const lj_data_op check_forest        = ic_lj_forest;
static const lj_data_op check_stream_poll   = ic_lj_stream_poll;

/* The status values are the header's, and nothing may quietly renumber them: a caller
 * compiled against one numbering and an archive built against another agree on every
 * signature and disagree on every answer. */
_Static_assert(LJ_OK == 0, "LJ_OK is the absence of a problem and must be falsy");
_Static_assert(LJ_INVALID == 1, "LJ_INVALID");
_Static_assert(LJ_FORBIDDEN == 3, "LJ_FORBIDDEN");
_Static_assert(LJ_NOT_FOUND == 4, "LJ_NOT_FOUND");
_Static_assert(LJ_CONFLICT == 5, "LJ_CONFLICT");
_Static_assert(LJ_TOO_LARGE == 6, "LJ_TOO_LARGE");
_Static_assert(LJ_INTERNAL == 7, "LJ_INTERNAL");
_Static_assert(LJ_TRUNCATED == 8, "LJ_TRUNCATED");
_Static_assert(LJ_BAD_HANDLE == 9, "LJ_BAD_HANDLE");
_Static_assert(LJ_CLOSED == 10, "LJ_CLOSED");
_Static_assert(LJ_PANIC == 11, "LJ_PANIC");
_Static_assert(LJ_CODEC == 12, "LJ_CODEC");
_Static_assert(LJ_GAP == 13, "LJ_GAP");
_Static_assert(LJ_LOCKED == 14, "LJ_LOCKED");
_Static_assert(LJ_ABI_VERSION == 1u, "LJ_ABI_VERSION");
_Static_assert(LJ_MUTATION_OUT_MIN > LJ_MAX_PATH, "a mutation's buffer floor must exceed its path cap");

/* Silence "defined but not used" without weakening the checks above: taking their
 * addresses is the whole point, and this is the one place that reads them. */
const void *const lj_header_agreement[] = {
    (const void *)&check_abi_version,
    (const void *)&check_echo,
    (const void *)&check_open,
    (const void *)&check_close,
    (const void *)&check_node_create,
    (const void *)&check_event_plan,
    (const void *)&check_event_start,
    (const void *)&check_event_append,
    (const void *)&check_event_end,
    (const void *)&check_event_entries,
    (const void *)&check_query,
    (const void *)&check_aggregate,
    (const void *)&check_forest,
    (const void *)&check_stream_poll,
};
