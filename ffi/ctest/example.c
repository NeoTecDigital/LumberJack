/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Drives the example product archive from C: the base exports and the product's export, in one
 * archive with one Go runtime, over one handle. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lumberjack_example.h"
#include "libexample.h"   /* what cgo generated for the example archive: compiled beside the specification */

#define REQ(s) (const char *)(s), (int64_t)strlen(s)

static lj_status_t (*const check_writes)(lj_handle_t, int64_t *) = ic_lj_example_writes;
static lj_status_t (*const check_open)(lj_cstr, int64_t, lj_handle_t *) = ic_lj_open;

int main(void) {
    assert(ic_lj_abi_version() == LJ_ABI_VERSION);
    char dir[] = "/tmp/lj_example_XXXXXX";
    assert(mkdtemp(dir) != NULL);
    char open_req[256];
    snprintf(open_req, sizeof open_req,
             "organization: example\ndatabase_path: %s\nname: state\nprincipal: example-admin\n", dir);
    lj_handle_t h = 0;
    assert(check_open(REQ(open_req), &h) == LJ_OK);

    int64_t before = -1, after = -1;
    assert(check_writes(h, &before) == LJ_OK);
    char out[LJ_MUTATION_OUT_MIN];
    int64_t out_len = 0;
    assert(ic_lj_node_create(h, REQ("path: example/one\ntype: leaf\n"), out, sizeof out, &out_len) == LJ_OK);
    assert(check_writes(h, &after) == LJ_OK);
    assert(after > before);
    assert(check_writes((lj_handle_t)987654321, &after) == LJ_BAD_HANDLE);

    assert(ic_lj_close(h) == LJ_OK);
    assert(check_writes(h, &after) == LJ_BAD_HANDLE);
    printf("C example ok: one archive, base and product exports, the hook saw %lld writes\n", (long long)after);
    return 0;
}
