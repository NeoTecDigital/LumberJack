/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* The example product archive's header: the base specification, and the product's own export. A
 * product archive is a superset of the generic one, so its header includes lumberjack.h and
 * declares only what it adds. */
#ifndef LUMBERJACK_EXAMPLE_H
#define LUMBERJACK_EXAMPLE_H

#include "lumberjack.h"

#ifdef __cplusplus
extern "C" {
#endif

/* How many writes the example's extension saw. LJ_BAD_HANDLE for a handle ic_lj_open did not issue. */
lj_status_t ic_lj_example_writes(lj_handle_t h, int64_t *out);

#ifdef __cplusplus
}
#endif
#endif /* LUMBERJACK_EXAMPLE_H */
