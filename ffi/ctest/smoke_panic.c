/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Non-commercial use only; see LICENSE. */

/* The guard is real if a panic inside an export becomes a STATUS and a living process, not a dead
 * one. Linked against the tagged archive — the only build carrying ic_lj__panic_for_test — this
 * forces a panic, asserts it was recovered to LJ_PANIC, and then proves the process is still usable
 * by making a further call. Run by `make smoke-panic`. */

#include <assert.h>
#include <stdio.h>
#include "lumberjack.h"

/* Declared here rather than in lumberjack.h: this symbol is NOT part of the ABI, and the header is
 * the ABI. The tagged archive provides it; the shipped one does not. */
extern lj_status_t ic_lj__panic_for_test(void);

int main(void) {
    assert(ic_lj__panic_for_test() == LJ_PANIC);

    /* Still alive, still answering. */
    assert(ic_lj_abi_version() == LJ_ABI_VERSION);

    printf("C panic smoke ok: a recovered panic is LJ_PANIC and the process survives\n");
    return 0;
}
