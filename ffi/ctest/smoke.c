/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Non-commercial use only; see LICENSE. */

/* The C ABI is real if a program that knows nothing about Go can drive the whole lifecycle, and if
 * the boundary's promises hold: a read that does not fit truncates and retries, a mutation whose
 * acknowledgement could not fit is refused BEFORE it runs, close is idempotent, and a call on a
 * closed handle is refused rather than hanging. Run by `make smoke`. */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lumberjack.h"

#define REQ(s) (const char *)(s), (int64_t)strlen(s)

/* ok runs a data op expected to succeed, null-terminates the answer, and returns its length. */
static int64_t ok(lj_status_t (*op)(lj_handle_t, lj_cstr, int64_t, char *, int64_t, int64_t *),
                  lj_handle_t h, const char *req, char *out, int64_t cap) {
    int64_t len = -1;
    lj_status_t st = op(h, REQ(req), out, cap, &len);
    assert(st == LJ_OK);
    assert(len >= 0 && len < cap);
    out[len] = '\0';
    return len;
}

int main(void) {
    assert(ic_lj_abi_version() == LJ_ABI_VERSION);

    /* The echo convention, end to end. */
    char echo[64]; int64_t elen = -1;
    const char *msg = "hello forest";
    assert(ic_lj_echo(REQ(msg), echo, sizeof echo, &elen) == LJ_OK);
    assert(elen == (int64_t)strlen(msg) && memcmp(echo, msg, (size_t)elen) == 0);
    char tiny[4]; int64_t need = -1;
    memset(tiny, 0x7f, sizeof tiny);
    assert(ic_lj_echo(REQ(msg), tiny, sizeof tiny, &need) == LJ_TRUNCATED);
    assert(need == (int64_t)strlen(msg) && tiny[0] == 0x7f);

    /* A fresh state directory, so this run installs rather than loads. */
    char dir[] = "/tmp/lj_smoke_XXXXXX";
    assert(mkdtemp(dir) != NULL);
    char open_req[256];
    snprintf(open_req, sizeof open_req,
             "organization: smoke\ndatabase_path: %s\nname: state\nprincipal: smoke-admin\n", dir);

    lj_handle_t h = 0;
    assert(ic_lj_open(REQ(open_req), &h) == LJ_OK);
    assert(h != 0);

    char out[LJ_MUTATION_OUT_MIN + 4096];
    ok(ic_lj_node_create, h, "path: work/site\ntype: leaf\n", out, sizeof out);
    ok(ic_lj_event_plan, h,
       "path: work/site\nevent_id: planned-1\n"
       "start_time: 2030-01-01T00:00:00Z\nend_time: 2030-01-01T01:00:00Z\n", out, sizeof out);
    ok(ic_lj_event_start, h, "path: work/site\nevent_id: e1\n", out, sizeof out);
    ok(ic_lj_event_append, h, "path: work/site\nevent_id: e1\ncontent: inspection complete\n",
       out, sizeof out);
    ok(ic_lj_event_end, h, "path: work/site\nevent_id: e1\n", out, sizeof out);

    /* The entry reads back, content intact. */
    const char *entries_req = "path: work/site\nevent_id: e1\n";
    int64_t before = ok(ic_lj_event_entries, h, entries_req, out, sizeof out);
    assert(strstr(out, "inspection complete") != NULL);

    /* A read that does not fit truncates, writes nothing, and reports the size to retry with. */
    char small[8]; int64_t want = -1;
    memset(small, 0x7f, sizeof small);
    assert(ic_lj_event_entries(h, REQ(entries_req), small, sizeof small, &want) == LJ_TRUNCATED);
    assert(want == before && small[0] == 0x7f);
    char retry[LJ_MUTATION_OUT_MIN + 4096]; int64_t got = -1;
    assert(ic_lj_event_entries(h, REQ(entries_req), retry, want + 1, &got) == LJ_OK && got == before);

    /* A mutation whose acknowledgement could not fit is refused BEFORE running: the append does not
     * happen, so the entries are byte-for-byte what they were. */
    char muti[8]; int64_t mlen = -1;
    assert(ic_lj_event_append(h, REQ("path: work/site\nevent_id: e1\ncontent: must-not-appear\n"),
                              muti, sizeof muti, &mlen) == LJ_INVALID);
    char after[LJ_MUTATION_OUT_MIN + 4096];
    int64_t after_len = ok(ic_lj_event_entries, h, entries_req, after, sizeof after);
    assert(after_len == before && memcmp(out, after, (size_t)before) == 0);
    assert(strstr(after, "must-not-appear") == NULL);

    /* A NULL out buffer or a NULL out_len is refused BEFORE the mutation runs, the same as an
     * undersized one: all three are ways the acknowledgement could not be delivered. The forest is
     * unchanged either way — the most ordinary C mistake must not land a silent write. */
    char forest_before[LJ_MUTATION_OUT_MIN + 4096];
    int64_t fb = ok(ic_lj_forest, h, "", forest_before, sizeof forest_before);
    int64_t nlen = -1;
    assert(ic_lj_node_create(h, REQ("path: guarded/x\ntype: leaf\n"),
                             NULL, LJ_MUTATION_OUT_MIN, &nlen) == LJ_INVALID);
    assert(ic_lj_node_create(h, REQ("path: guarded/x\ntype: leaf\n"),
                             out, sizeof out, NULL) == LJ_INVALID);
    char forest_after[LJ_MUTATION_OUT_MIN + 4096];
    int64_t fa = ok(ic_lj_forest, h, "", forest_after, sizeof forest_after);
    assert(fa == fb && memcmp(forest_before, forest_after, (size_t)fb) == 0);
    assert(strstr(forest_after, "guarded") == NULL);

    /* The epoch survives the wire: a poll echoing back the epoch it was just given does NOT report a
     * gap on a healthy runtime. Its value is UnixNano-scale, past 2^53, so this also proves the codec
     * carries a large integer exactly rather than rounding it to a float. */
    char poll1[LJ_MUTATION_OUT_MIN + 4096]; int64_t p1 = -1;
    assert(ic_lj_stream_poll(h, REQ("after: 0\ntimeout_ms: 0\n"), poll1, sizeof poll1, &p1) == LJ_OK);
    poll1[p1] = '\0';
    char *ep = strstr(poll1, "epoch:");
    assert(ep != NULL);
    unsigned long long epoch = strtoull(ep + 6, NULL, 10);
    assert(epoch != 0ULL);
    char poll2req[128];
    snprintf(poll2req, sizeof poll2req, "after: 0\nepoch: %llu\ntimeout_ms: 0\n", epoch);
    char poll2[LJ_MUTATION_OUT_MIN + 4096]; int64_t p2 = -1;
    assert(ic_lj_stream_poll(h, REQ(poll2req), poll2, sizeof poll2, &p2) == LJ_OK);

    /* query and forest answer too. */
    ok(ic_lj_query, h, "select: entries\n", out, sizeof out);
    ok(ic_lj_forest, h, "", out, sizeof out);

    /* close is idempotent, and a call after close is refused, not hung. */
    assert(ic_lj_close(h) == LJ_OK);
    assert(ic_lj_close(h) == LJ_OK);
    int64_t dead = -1;
    assert(ic_lj_event_entries(h, REQ(entries_req), out, sizeof out, &dead) == LJ_BAD_HANDLE);

    printf("C smoke ok: lifecycle, truncation, mutation-guard, idempotent close, bad-handle\n");
    return 0;
}
