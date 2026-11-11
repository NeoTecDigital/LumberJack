#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lumberjack.h"
#define REQ(s) (const char *)(s), (int64_t)strlen(s)

static void batch(lj_handle_t h) {
    char out[LJ_MUTATION_OUT_MIN + 1];
    int64_t length = 0;
    const char *req = "{\"path\":\"work/batch\",\"events\":["
        "{\"event_id\":\"a\",\"content\":\"first\",\"metadata\":{\"id\":\"a\"}},"
        "{\"event_id\":\"b\",\"content\":\"second\",\"metadata\":{\"id\":\"b\"}}]}";
    assert(ic_lj_events_publish(h, NULL, LJ_PUBLISH_MAX_BYTES+1, out, sizeof out, &length) == LJ_TOO_LARGE);
    assert(ic_lj_events_publish(h, REQ(req), out, LJ_MUTATION_OUT_MIN-1, &length) == LJ_INVALID);
    assert(ic_lj_events_publish(h, REQ(req), NULL, sizeof out, &length) == LJ_INVALID);
    assert(ic_lj_events_publish(h, REQ(req), out, sizeof out, NULL) == LJ_INVALID);
    /* Success of the SAME ids proves all three buffer refusals had no effects. */
    assert(ic_lj_events_publish(h, REQ(req), out, LJ_MUTATION_OUT_MIN, &length) == LJ_OK);
    assert(length > 0 && length < LJ_MUTATION_OUT_MIN);
    out[length] = 0;
    assert(strstr(out, "published: 2") != NULL);
    assert(ic_lj_events_publish(h, REQ(req), out, sizeof out, &length) == LJ_CONFLICT);
}

static void verify(lj_handle_t h) {
    char out[LJ_MUTATION_OUT_MIN + 1];
    int64_t length = 0;
    assert(ic_lj_event_entries(h, REQ("path: work/batch\nevent_id: a\n"), out, sizeof out-1, &length) == LJ_OK);
    out[length] = 0;
    assert(strstr(out, "first") && strstr(out, "system"));
    assert(ic_lj_query(h, REQ("select: events\nwhere:\n  status: [finished]\n"), out, sizeof out-1, &length) == LJ_OK);
    out[length] = 0;
    assert(strstr(out, "total: 2") != NULL);
}

int main(void) {
    char dir[] = "/tmp/lj_publication_XXXXXX", req[256], out[LJ_MUTATION_OUT_MIN];
    int64_t length = 0;
    lj_handle_t h = 0;
    assert(mkdtemp(dir));
    snprintf(req, sizeof req, "organization: smoke\ndatabase_path: %s\nname: state\nprincipal: system\n", dir);
    assert(ic_lj_open(REQ(req), &h) == LJ_OK);
    assert(ic_lj_node_create(h, REQ("path: work/batch\ntype: leaf\n"), out, sizeof out, &length) == LJ_OK);
    batch(h);
    verify(h);
    assert(ic_lj_close(h) == LJ_OK);
    assert(ic_lj_open(REQ(req), &h) == LJ_OK);
    verify(h);
    assert(ic_lj_close(h) == LJ_OK);
    puts("publication: bounded acknowledgement, no-effect refusal and durable reopen passed");
    return 0;
}
