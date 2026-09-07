/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Non-commercial use only; see LICENSE. */

/* The C ABI is real if a program that knows nothing about Go can drive it, and if the two
 * failure modes behave as the header says they do. Run by `make smoke`. */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lumberjack.h"

int main(void) {
    assert(ic_lj_abi_version() == LJ_ABI_VERSION);

    char out[64]; int32_t len = -1;
    const char *msg = "hello forest";
    assert(ic_lj_echo(msg, (int32_t)strlen(msg), out, sizeof out, &len) == LJ_OK);
    assert(len == (int32_t)strlen(msg));
    assert(memcmp(out, msg, (size_t)len) == 0);

    char tiny[4]; int32_t need = -1;
    memset(tiny, 0x7f, sizeof tiny);
    assert(ic_lj_echo(msg, (int32_t)strlen(msg), tiny, sizeof tiny, &need) == LJ_TRUNCATED);
    assert(need == (int32_t)strlen(msg));
    assert(tiny[0] == 0x7f);   /* nothing was written */

    printf("C smoke ok: abi=%u echo=%d truncated_needs=%d\n",
           ic_lj_abi_version(), len, need);
    return 0;
}
