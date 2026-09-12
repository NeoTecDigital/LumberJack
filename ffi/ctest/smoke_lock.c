/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
/* Non-commercial use only; see LICENSE. */

/* The two statuses an OPEN refuses with, produced from the C side, which nothing had done for either.
 *
 * LJ_LOCKED needs ANOTHER PROCESS holding the sidecar flock, so this programme re-runs itself as the
 * holder (`smoke_lock --hold <dir>`), the same shape as embedded/lifecycle_test.go's subprocess
 * harness: the Go tests produce embedded.ErrLocked that way, and the mapping to LJ_LOCKED at the
 * boundary was dead in test until here. LJ_UNGUARDED is its permanent sibling — a state file with no
 * sidecar — and ic_lj_adopt is the one route past it. The two are asserted APART: a caller told
 * LJ_LOCKED backs off and retries, and a missing sidecar never clears by retrying. Run by
 * `make smoke-lock`; it is its own programme rather than a section of smoke.c so each stays a size
 * a reader can hold. */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lumberjack.h"

#define REQ(s) (const char *)(s), (int64_t)strlen(s)

/* HOLD_FLAG turns this binary into THE OTHER PROCESS: `smoke_lock --hold <dir>` opens the state file
 * under dir through the real ic_lj_open, prints HOLD_READY on stdout, and holds the flock until its
 * stdin closes. The parent controls the release by closing the pipe, so the hold lasts exactly as
 * long as the assertion needs and not one scheduling accident longer. Its stdout carries only the
 * announcement; the runtime's own log goes to stderr. */
#define HOLD_FLAG "--hold"
#define HOLD_READY "HELD"

static int hold_main(const char *dir) {
    char req[512];
    snprintf(req, sizeof req,
             "organization: smoke\ndatabase_path: %s\nname: state\nprincipal: holder\n", dir);
    lj_handle_t h = 0;
    if (ic_lj_open(REQ(req), &h) != LJ_OK) return 2;
    printf("%s\n", HOLD_READY);
    fflush(stdout);

    char byte;
    while (read(STDIN_FILENO, &byte, 1) < 0 && errno == EINTR) {}
    return ic_lj_close(h) == LJ_OK ? 0 : 3;
}

/* spawn_holder starts this binary as the holder over dir and returns once it has announced the
 * hold — a fact read off a pipe, not a sleep. *release is the write end of the holder's stdin:
 * closing it lets the holder go. posix_spawn rather than fork: this process carries a Go runtime
 * with its threads, and a bare fork of it is not a process anything should run in. The pipes are
 * O_CLOEXEC, so the holder inherits only the two ends dup2'd onto its stdin and stdout; Go opens
 * every file O_CLOEXEC, so it inherits none of this process's own sidecar locks either. */
static pid_t spawn_holder(const char *dir, int *release, FILE **announce) {
    int to_child[2], from_child[2];
    assert(pipe2(to_child, O_CLOEXEC) == 0 && pipe2(from_child, O_CLOEXEC) == 0);

    posix_spawn_file_actions_t actions;
    assert(posix_spawn_file_actions_init(&actions) == 0);
    assert(posix_spawn_file_actions_adddup2(&actions, to_child[0], STDIN_FILENO) == 0);
    assert(posix_spawn_file_actions_adddup2(&actions, from_child[1], STDOUT_FILENO) == 0);

    char *argv[] = { "smoke_lock", HOLD_FLAG, (char *)dir, NULL };
    pid_t pid = 0;
    assert(posix_spawn(&pid, "/proc/self/exe", &actions, NULL, argv, environ) == 0);
    posix_spawn_file_actions_destroy(&actions);
    close(to_child[0]);
    close(from_child[1]);

    FILE *from = fdopen(from_child[0], "r");
    assert(from != NULL);
    char line[64];
    assert(fgets(line, sizeof line, from) != NULL);
    assert(strncmp(line, HOLD_READY, strlen(HOLD_READY)) == 0);

    *release = to_child[1];
    *announce = from;
    return pid;
}

/* locked produces LJ_LOCKED from the C side, which nothing had: a second PROCESS holds the sidecar
 * flock through its own ic_lj_open while this one asks for the path. embedded/lifecycle_test.go
 * produces embedded.ErrLocked the same way; the mapping to LJ_LOCKED at the boundary was dead in
 * test until here. And the refusal LIFTS when the holder lets go — a lock that never releases is as
 * broken as one that never held — which is what makes LJ_LOCKED the status a caller retries. */
static void locked(const char *parent) {
    char dir[256];
    snprintf(dir, sizeof dir, "%s/locked", parent);
    assert(mkdir(dir, 0700) == 0);

    int release = -1;
    FILE *announce = NULL;
    pid_t holder = spawn_holder(dir, &release, &announce);

    char req[512];
    snprintf(req, sizeof req,
             "organization: smoke\ndatabase_path: %s\nname: state\nprincipal: system\n", dir);
    lj_handle_t h = 0;
    assert(ic_lj_open(REQ(req), &h) == LJ_LOCKED);
    assert(h == 0);
    /* Still LJ_LOCKED while the holder holds: honest about being transient, not permanent. */
    assert(ic_lj_open(REQ(req), &h) == LJ_LOCKED);
    assert(h == 0);

    close(release);
    int status = 0;
    assert(waitpid(holder, &status, 0) == holder);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    fclose(announce);

    /* The refusal lifts the moment the holder is gone. */
    assert(ic_lj_open(REQ(req), &h) == LJ_OK);
    assert(h != 0);
    assert(ic_lj_close(h) == LJ_OK);
}

/* unguarded produces LJ_UNGUARDED and drives ic_lj_adopt. A state file with no sidecar — what every
 * forest from before the sidecar looks like, and what a restored backup looks like — is refused with
 * the PERMANENT status and never the transient one, retrying it is the same answer, and adoption is
 * explicit, one-shot, and admits the forest that was there. */
static void unguarded(const char *parent) {
    char dir[256];
    snprintf(dir, sizeof dir, "%s/unguarded", parent);
    assert(mkdir(dir, 0700) == 0);

    char req[512];
    snprintf(req, sizeof req,
             "organization: smoke\ndatabase_path: %s\nname: state\nprincipal: system\n", dir);
    static char out[LJ_MUTATION_OUT_MIN + 4096];

    /* A real forest, then its sidecar removed. */
    lj_handle_t h = 0;
    assert(ic_lj_open(REQ(req), &h) == LJ_OK);
    int64_t len = -1;
    assert(ic_lj_node_create(h, REQ("path: legacy/kept\ntype: leaf\n"), out, sizeof out, &len) == LJ_OK);
    assert(ic_lj_close(h) == LJ_OK);
    char sidecar[512];
    snprintf(sidecar, sizeof sidecar, "%s/state.dat.lock", dir);
    assert(unlink(sidecar) == 0);

    /* REFUSED, permanently: the same answer on a retry, and never LJ_LOCKED. */
    h = 0;
    assert(ic_lj_open(REQ(req), &h) == LJ_UNGUARDED);
    assert(h == 0);
    assert(ic_lj_open(REQ(req), &h) == LJ_UNGUARDED);
    assert(h == 0);

    /* Adopt's own refusals: no state file is LJ_NOT_FOUND, a document that is not YAML is LJ_CODEC. */
    char empty[256];
    snprintf(empty, sizeof empty, "%s/unguarded-empty", parent);
    assert(mkdir(empty, 0700) == 0);
    char adopt_empty[512];
    snprintf(adopt_empty, sizeof adopt_empty, "database_path: %s\nname: state\n", empty);
    assert(ic_lj_adopt(REQ(adopt_empty)) == LJ_NOT_FOUND);
    assert(ic_lj_adopt(REQ("database_path: 'unterminated\n")) == LJ_CODEC);

    /* THE ROUTE, and it is ONE-SHOT: the second adopt is a conflict with the sidecar now there. */
    char adopt_req[512];
    snprintf(adopt_req, sizeof adopt_req, "database_path: %s\nname: state\n", dir);
    assert(ic_lj_adopt(REQ(adopt_req)) == LJ_OK);
    assert(access(sidecar, F_OK) == 0);
    assert(ic_lj_adopt(REQ(adopt_req)) == LJ_CONFLICT);

    /* The forest opens, intact, and while it is live its sidecar is held: still nothing to adopt. */
    assert(ic_lj_open(REQ(req), &h) == LJ_OK);
    assert(h != 0);
    len = -1;
    assert(ic_lj_forest(h, REQ(""), out, sizeof out, &len) == LJ_OK);
    assert(len >= 0 && len < (int64_t)sizeof out);
    out[len] = '\0';
    assert(strstr(out, "kept") != NULL);
    assert(ic_lj_adopt(REQ(adopt_req)) == LJ_CONFLICT);
    assert(ic_lj_close(h) == LJ_OK);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], HOLD_FLAG) == 0) return hold_main(argv[2]);

    assert(ic_lj_abi_version() == LJ_ABI_VERSION);

    char dir[] = "/tmp/lj_smoke_lock_XXXXXX";
    assert(mkdtemp(dir) != NULL);

    locked(dir);
    unguarded(dir);

    printf("C lock smoke ok: LJ_LOCKED from a second process and lifted on its release,\n"
           "                 LJ_UNGUARDED apart from it, and adopt one-shot\n");
    return 0;
}
