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

/* The status values are the header's, and nothing may quietly renumber them: a caller
 * compiled against one numbering and an archive built against another agree on every
 * signature and disagree on every answer. */
_Static_assert(LJ_OK == 0, "LJ_OK is the absence of a problem and must be falsy");
_Static_assert(LJ_TRUNCATED == 8, "LJ_TRUNCATED");
_Static_assert(LJ_PANIC == 11, "LJ_PANIC");
_Static_assert(LJ_ABI_VERSION == 1u, "LJ_ABI_VERSION");

/* Silence "defined but not used" without weakening the checks above: taking their
 * addresses is the whole point, and this is the one place that reads them. */
const void *const lj_header_agreement[] = {
    (const void *)&check_abi_version,
    (const void *)&check_echo,
};
