/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Non-commercial use only; see LICENSE. */

/* The C ABI is real if a program that knows nothing about Go can drive the whole lifecycle, and if
 * the boundary's promises hold: a read that does not fit truncates and retries, a mutation whose
 * acknowledgement could not fit is refused BEFORE it runs, close is idempotent, and a call on a
 * closed handle is refused rather than hanging. Run by `make smoke`.
 *
 * IT IS ALSO WHERE THE ABI'S BOUNDS AND ITS STATUSES ARE TESTED, because cgo is not supported in Go
 * test files: an lj_cstr is a *C.char and there is no way to build one from a Go test. So everything
 * that needs a real C buffer — LJ_MUTATION_OUT_MIN at its edge, the "the acknowledgement provably
 * fits" claim, LJ_TOO_LARGE, LJ_CODEC, LJ_NOT_FOUND, LJ_CONFLICT, LJ_GAP, ic_lj_aggregate, and the
 * archive under several threads at once — lives here rather than beside the Go unit tests. The two
 * statuses an OPEN refuses with — LJ_LOCKED, which needs another process, and LJ_UNGUARDED with its
 * adopt — live in smoke_lock.c, a programme of their own, run by `make smoke-lock`. */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
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


/* THREADS is how many drive the archive at once below. The Rust engine will not be single-threaded,
 * and the guard's own note says recover does NOT catch a runtime throw — a concurrent map write is
 * one — so what keeps this process alive under concurrency is the forest lock, not the guard. This
 * is the test of that claim from the side the claim is about. */
#define THREADS 8
#define READERS 4
#define PER_THREAD 24

/* repeat fills dst with n copies of one byte and terminates it, for the path and event-id lengths
 * LJ_MAX_PATH is declared at. */
static void repeat(char *dst, char fill, size_t n) {
    memset(dst, fill, n);
    dst[n] = '\0';
}

/* limits drives every declared bound of the ABI at its edge and just past it.
 *
 * Not one of these had a test. LJ_MUTATION_OUT_MIN's floor was asserted only from far below it, so
 * an off-by-one either way was invisible; LJ_MAX_PATH produced LJ_TOO_LARGE nowhere at all; and the
 * header's most emphatic claim — that a mutation's acknowledgement PROVABLY FITS in
 * LJ_MUTATION_OUT_MIN given the LJ_MAX_PATH cap — had never been made to hold up a worst case. */
static void limits(lj_handle_t h) {
    static char out[LJ_MUTATION_OUT_MIN + 8192];
    static char req[2 * LJ_MAX_PATH + 256];
    static char path[LJ_MAX_PATH + 2];
    static char eid[LJ_MAX_PATH + 2];
    int64_t len = -1;

    /* LJ_MUTATION_OUT_MIN, exactly. One byte below the floor is refused BEFORE the mutation runs;
     * at the floor the very same request is admitted. */
    len = -1;
    assert(ic_lj_node_create(h, REQ("path: bounds/under\ntype: leaf\n"),
                             out, LJ_MUTATION_OUT_MIN - 1, &len) == LJ_INVALID);
    len = -1;
    assert(ic_lj_node_create(h, REQ("path: bounds/at\ntype: leaf\n"),
                             out, LJ_MUTATION_OUT_MIN, &len) == LJ_OK);
    assert(len > 0 && len <= LJ_MUTATION_OUT_MIN);

    /* The refusal was a REFUSAL: bounds/under is not in the forest, and bounds/at is. */
    ok(ic_lj_forest, h, "", out, sizeof out);
    assert(strstr(out, "bounds/under") == NULL);
    assert(strstr(out, "under") == NULL);
    assert(strstr(out, "at") != NULL);

    /* LJ_MAX_PATH, exactly. A path of the declared length is admitted; one byte past it is
     * LJ_TOO_LARGE — the status no test produced. */
    repeat(path, 'p', LJ_MAX_PATH);
    snprintf(req, sizeof req, "path: %s\ntype: leaf\n", path);
    len = -1;
    assert(ic_lj_node_create(h, REQ(req), out, sizeof out, &len) == LJ_OK);

    repeat(path, 'q', LJ_MAX_PATH + 1);
    snprintf(req, sizeof req, "path: %s\ntype: leaf\n", path);
    len = -1;
    assert(ic_lj_node_create(h, REQ(req), out, sizeof out, &len) == LJ_TOO_LARGE);

    /* And on the EVENT ID, which the acknowledgement carries too. */
    repeat(eid, 'e', LJ_MAX_PATH + 1);
    snprintf(req, sizeof req, "path: bounds/at\nevent_id: %s\n", eid);
    len = -1;
    assert(ic_lj_event_start(h, REQ(req), out, sizeof out, &len) == LJ_TOO_LARGE);

    /* THE CLAIM, held up by its own worst case: a mutation whose path AND event id are both exactly
     * LJ_MAX_PATH, acknowledged into a buffer of exactly LJ_MUTATION_OUT_MIN. If this does not fit,
     * the floor is too low and the "provably fits" guarantee is arithmetic nobody checked. */
    repeat(path, 'p', LJ_MAX_PATH);
    snprintf(req, sizeof req, "path: %s\ntype: leaf\n", path);
    len = -1;
    assert(ic_lj_node_create(h, REQ(req), out, LJ_MUTATION_OUT_MIN, &len) == LJ_OK);
    assert(len > LJ_MAX_PATH && len <= LJ_MUTATION_OUT_MIN);

    repeat(eid, 'e', LJ_MAX_PATH);
    snprintf(req, sizeof req, "path: %s\nevent_id: %s\n", path, eid);
    len = -1;
    assert(ic_lj_event_start(h, REQ(req), out, LJ_MUTATION_OUT_MIN, &len) == LJ_OK);
    assert(len > 2 * LJ_MAX_PATH && len <= LJ_MUTATION_OUT_MIN);
    len = -1;
    assert(ic_lj_event_end(h, REQ(req), out, LJ_MUTATION_OUT_MIN, &len) == LJ_OK);
    assert(len <= LJ_MUTATION_OUT_MIN);

    /* req_len's own edges. A NEGATIVE length is LJ_INVALID; a length past LJ_MAX_IN_LEN is
     * LJ_TOO_LARGE, and both are decided before a byte is copied — the pointer is never read. */
    len = -1;
    assert(ic_lj_echo(NULL, -1, out, sizeof out, &len) == LJ_INVALID);
    len = -1;
    assert(ic_lj_echo(NULL, (int64_t)LJ_MAX_IN_LEN + 1, out, sizeof out, &len) == LJ_TOO_LARGE);
    len = -1;
    assert(ic_lj_echo(NULL, 0, out, sizeof out, &len) == LJ_OK && len == 0);

    /* take COPIES the caller's buffer rather than viewing it, which is the rule cgo's lifetime
     * contract turns into a use-after-free if it is broken. A megabyte-scale echo is where a
     * narrowed length or a borrowed view would show; the buffer is then overwritten and the answer
     * must be unaffected. */
    const size_t big = 1u << 20;
    char *source = malloc(big);
    char *echoed = malloc(big);
    assert(source != NULL && echoed != NULL);
    memset(source, 'Z', big);
    len = -1;
    assert(ic_lj_echo(source, (int64_t)big, echoed, (int64_t)big, &len) == LJ_OK);
    assert(len == (int64_t)big);
    memset(source, 'Y', big);
    for (size_t i = 0; i < big; i++) assert(echoed[i] == 'Z');
    free(source);
    free(echoed);
}

/* statuses produces the ones no test had ever produced. Six of statusForError's seven branches were
 * dead, and LJ_GAP, LJ_CODEC and LJ_TOO_LARGE were reachable from nowhere. */
static void statuses(lj_handle_t h, const char *dir) {
    static char out[LJ_MUTATION_OUT_MIN + 4096];
    static char req[2048];
    int64_t len = -1;

    /* LJ_CODEC: a request that is not a YAML document at all. */
    len = -1;
    assert(ic_lj_node_create(h, REQ("path: 'unterminated\ntype: leaf\n"),
                             out, sizeof out, &len) == LJ_CODEC);
    len = -1;
    assert(ic_lj_query(h, REQ("select: [entries\n"), out, sizeof out, &len) == LJ_CODEC);

    /* LJ_NOT_FOUND: a mutation on a node that is not there. 404, not 500. */
    len = -1;
    assert(ic_lj_event_start(h, REQ("path: nowhere/at/all\nevent_id: e9\n"),
                             out, sizeof out, &len) == LJ_NOT_FOUND);

    /* LJ_CONFLICT: a path already occupied by a node of another type. 409, not 400 — it is a
     * conflict with what is already there, not a malformed request. */
    ok(ic_lj_node_create, h, "path: clash\ntype: leaf\n", out, sizeof out);
    len = -1;
    assert(ic_lj_node_create(h, REQ("path: clash\ntype: branch\n"),
                             out, sizeof out, &len) == LJ_CONFLICT);

    /* LJ_INVALID from the ENGINE rather than from the guard: an event id that names nothing. */
    len = -1;
    assert(ic_lj_event_end(h, REQ("path: clash\nevent_id: \"\"\n"),
                           out, sizeof out, &len) == LJ_INVALID);

    /* LJ_GAP: a cursor from another RUN. Sequences live only in memory and restart on every open, so
     * an epoch that is not this run's is a gap of its own — and the answer still carries `oldest`,
     * which is where the caller re-derives from. */
    len = -1;
    assert(ic_lj_stream_poll(h, REQ("after: 0\nepoch: 1\ntimeout_ms: 0\n"),
                             out, sizeof out, &len) == LJ_GAP);
    out[len] = '\0';
    assert(strstr(out, "caught_up: false") != NULL);
    assert(strstr(out, "oldest:") != NULL);

    /* LJ_INTERNAL: an open whose state path cannot be made. The directory is a FILE, so neither the
     * sidecar's directory nor the state file can be created under it. */
    char blocker[512];
    snprintf(blocker, sizeof blocker, "%s/state.dat", dir);
    snprintf(req, sizeof req,
             "organization: smoke\ndatabase_path: %s/not-a-directory\nname: state\nprincipal: p\n",
             blocker);
    lj_handle_t bad = 0;
    assert(ic_lj_open(REQ(req), &bad) == LJ_INTERNAL);
    assert(bad == 0);

    /* LJ_CODEC on open, too: the envelope is parsed before anything is opened. */
    bad = 0;
    assert(ic_lj_open(REQ("organization: 'unterminated\n"), &bad) == LJ_CODEC);
    assert(bad == 0);

    /* A NULL out_handle is refused rather than dereferenced. */
    assert(ic_lj_open(REQ("organization: smoke\n"), NULL) == LJ_INVALID);
}

/* worker is one thread's share of the archive. Every thread writes its leaves under ONE SHARED
 * BRANCH, on purpose: that makes all eight of them insert into the same Children map, which is the
 * map a projection of the forest is walking at the same moment — the thing forest_lock.go exists to
 * serialise. Measured with the lock removed, the shared branch RAISED the catch rate (14/15 runs
 * died, against 8/15 with a branch per thread) and did not make it certain; see threads. */
struct worker_arg { lj_handle_t h; int id; volatile int *stop; };

static void *worker(void *raw) {
    struct worker_arg *arg = raw;
    char *out = malloc(1 << 20);
    char req[256];
    int64_t len = -1;
    assert(out != NULL);

    for (int i = 0; i < PER_THREAD; i++) {
        snprintf(req, sizeof req, "path: shared/t%d-n%d\ntype: leaf\n", arg->id, i);
        len = -1;
        assert(ic_lj_node_create(arg->h, REQ(req), out, 1 << 20, &len) == LJ_OK);

        snprintf(req, sizeof req, "path: shared/t%d-n%d\nevent_id: e\n", arg->id, i);
        len = -1;
        assert(ic_lj_event_start(arg->h, REQ(req), out, 1 << 20, &len) == LJ_OK);

        snprintf(req, sizeof req, "path: shared/t%d-n%d\nevent_id: e\ncontent: from thread %d\n",
                 arg->id, i, arg->id);
        len = -1;
        assert(ic_lj_event_append(arg->h, REQ(req), out, 1 << 20, &len) == LJ_OK);

        snprintf(req, sizeof req, "path: shared/t%d-n%d\nevent_id: e\n", arg->id, i);
        len = -1;
        assert(ic_lj_event_end(arg->h, REQ(req), out, 1 << 20, &len) == LJ_OK);

        len = -1;
        assert(ic_lj_stream_poll(arg->h, REQ("after: 0\ntimeout_ms: 0\n"),
                                 out, 1 << 20, &len) == LJ_OK);
    }

    free(out);
    return NULL;
}

/* reader projects the WHOLE forest, over and over, for as long as the writers run. A projection
 * walks every Children map in the graph — including the one every writer above is inserting into —
 * so this is the read side of the race the forest lock serialises. */
static void *reader(void *raw) {
    struct worker_arg *arg = raw;
    char *out = malloc(1 << 20);
    int64_t len = -1;
    assert(out != NULL);

    while (!*arg->stop) {
        len = -1;
        assert(ic_lj_forest(arg->h, REQ(""), out, 1 << 20, &len) == LJ_OK);
        len = -1;
        assert(ic_lj_query(arg->h, REQ("select: entries\n"), out, 1 << 20, &len) == LJ_OK);
        len = -1;
        assert(ic_lj_aggregate(arg->h, REQ("select: entries\nmetric:\n  - count\n"),
                               out, 1 << 20, &len) == LJ_OK);
    }

    free(out);
    return NULL;
}

/* threads drives one archive from several OS threads at once, through their own handles.
 *
 * smoke.c was single-threaded, so nothing had ever put two C threads inside the Go runtime against
 * one forest. Each thread opens its own handle: within one process those share a refcounted runtime,
 * which is exactly the shape a multi-threaded host has and the shape the in-process refcount exists
 * for. What must hold: every acknowledged write is there afterwards, and the process is alive to say
 * so — a torn map would be a runtime throw that no recover in this binding can catch.
 *
 * THIS SECTION IS PROBABILISTIC, and one green run is NOT proof the lock is present. With the forest
 * lock removed it dies in most runs (14/15 measured; 0 false positives with the lock in place): a
 * torn map is a race, and a race that happens not to fire is a green run. It is not made
 * deterministic here because it cannot be cheaply — a race-instrumented archive is a second build of
 * the whole thing. The deterministic proof lives in `go test -race ./embedded`, where the race
 * detector reports an unsynchronised access whether or not it tore anything: with the lock neutered
 * the package fails every run; the report counts and which tests fail vary (measured 4–161 reports —
 * a run can die on the runtime's own map-write throw before the detector has accumulated much). What
 * only THIS can claim is that the lock holds under OS threads that entered the Go runtime from
 * outside, and that the archive stays alive doing it. */
static void threads(const char *parent) {
    char dir[256];
    snprintf(dir, sizeof dir, "%s/threads", parent);
    assert(mkdir(dir, 0700) == 0);

    char open_req[512];
    snprintf(open_req, sizeof open_req,
             "organization: smoke\ndatabase_path: %s\nname: state\nprincipal: smoke-admin\n", dir);

    pthread_t tid[THREADS + READERS];
    struct worker_arg args[THREADS + READERS];
    lj_handle_t handles[THREADS + READERS];
    volatile int stop = 0;

    for (int i = 0; i < THREADS + READERS; i++) {
        handles[i] = 0;
        assert(ic_lj_open(REQ(open_req), &handles[i]) == LJ_OK);
        assert(handles[i] != 0);
        /* Every handle is its own token, never a recycled one. */
        for (int j = 0; j < i; j++) assert(handles[i] != handles[j]);
        args[i].h = handles[i];
        args[i].id = i;
        args[i].stop = &stop;
    }

    for (int i = 0; i < READERS; i++)
        assert(pthread_create(&tid[THREADS + i], NULL, reader, &args[THREADS + i]) == 0);
    for (int i = 0; i < THREADS; i++) assert(pthread_create(&tid[i], NULL, worker, &args[i]) == 0);
    for (int i = 0; i < THREADS; i++) assert(pthread_join(tid[i], NULL) == 0);
    stop = 1;
    for (int i = 0; i < READERS; i++) assert(pthread_join(tid[THREADS + i], NULL) == 0);

    /* EVERY acknowledged entry survived every other thread's writes. */
    char *out = malloc(1 << 20);
    char req[256];
    int64_t len = -1;
    assert(out != NULL);
    for (int i = 0; i < THREADS; i++) {
        for (int j = 0; j < PER_THREAD; j++) {
            snprintf(req, sizeof req, "path: shared/t%d-n%d\nevent_id: e\n", i, j);
            len = -1;
            assert(ic_lj_event_entries(handles[0], REQ(req), out, 1 << 20, &len) == LJ_OK);
            out[len] = '\0';
            char wanted[64];
            snprintf(wanted, sizeof wanted, "from thread %d", i);
            assert(strstr(out, wanted) != NULL);
        }
    }
    free(out);

    /* Every leaf every thread made is under the ONE shared branch, and none was lost out of the map
     * the others were growing. */
    len = -1;
    out = malloc(1 << 20);
    assert(out != NULL);
    assert(ic_lj_forest(handles[0], REQ(""), out, 1 << 20, &len) == LJ_OK);
    out[len] = '\0';
    for (int i = 0; i < THREADS; i++) {
        for (int j = 0; j < PER_THREAD; j++) {
            char leaf[64];
            snprintf(leaf, sizeof leaf, "t%d-n%d", i, j);
            assert(strstr(out, leaf) != NULL);
        }
    }
    free(out);

    /* Closing from many threads is safe and the LAST one tears the runtime down. */
    for (int i = 0; i < THREADS + READERS; i++) assert(ic_lj_close(handles[i]) == LJ_OK);
    for (int i = 0; i < THREADS + READERS; i++) assert(ic_lj_close(handles[i]) == LJ_OK);
    int64_t dead = -1;
    assert(ic_lj_forest(handles[0], REQ(""), NULL, 0, &dead) == LJ_BAD_HANDLE);
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

    /* ic_lj_aggregate, which nothing had ever executed. An empty group is the whole selection as one
     * bucket, which is what "how many are there" asks for. */
    ok(ic_lj_aggregate, h, "select: entries\nmetric:\n  - count\n", out, sizeof out);
    assert(strstr(out, "buckets") != NULL);
    ok(ic_lj_aggregate, h,
       "select: events\ngroup:\n  - node_path\n  - status\nmetric:\n  - count\n  - duration_sum\n",
       out, sizeof out);
    assert(strstr(out, "work/site") != NULL);

    limits(h);
    statuses(h, dir);
    threads(dir);

    /* close is idempotent, and a call after close is refused, not hung. */
    assert(ic_lj_close(h) == LJ_OK);
    assert(ic_lj_close(h) == LJ_OK);
    int64_t dead = -1;
    assert(ic_lj_event_entries(h, REQ(entries_req), out, sizeof out, &dead) == LJ_BAD_HANDLE);

    /* A token that was NEVER issued, and the zero token a caller gets from a zeroed struct, are both
     * refused rather than resolved to whatever was opened first. */
    assert(ic_lj_event_entries(0, REQ(entries_req), out, sizeof out, &dead) == LJ_BAD_HANDLE);
    assert(ic_lj_event_entries(h + 4242, REQ(entries_req), out, sizeof out, &dead) == LJ_BAD_HANDLE);

    printf("C smoke ok: lifecycle, truncation, mutation-guard, idempotent close, bad-handle,\n"
           "            bounds at their edges, ten statuses, aggregate, and %d threads\n", THREADS);
    return 0;
}
