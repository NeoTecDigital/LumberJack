# Written by Richard Christopher, Copyright 2026 NeoTec, LLC
# Non-commercial use only; see LICENSE.

GO      ?= go
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror
NM      ?= nm
BUILD   := build
ARCHIVE := $(BUILD)/liblumberjack.a
HEADER  := $(BUILD)/liblumberjack.h
# The forced-panic export lives behind a build tag and must NOT be in the shipped archive; it is
# built into a separate archive only to prove the guard turns a panic into a status.
PANIC_ARCHIVE := $(BUILD)/liblumberjack_panic.a
# The SPEC.md §11.4 conformance corpus is the parent repository's: every case in it is hashed by
# the Rust, C and Go readers, and this is the path from here to it.
CANON_CORPUS ?= ../../crates/intercessor/tests/corpus/canon_corpus.json

# The generic archive's exports, exactly: the base a product archive is a superset of
# (docs/extension-api.md §6). nm-check refuses an archive with any other ic_lj_ export.
BASE_EXPORTS := ic_lj_abi_version ic_lj_echo ic_lj_open ic_lj_adopt ic_lj_close ic_lj_node_create \
	ic_lj_event_plan ic_lj_event_start ic_lj_event_append ic_lj_event_end ic_lj_event_entries \
	ic_lj_query ic_lj_aggregate ic_lj_forest ic_lj_stream_poll ic_lj_events_publish \
	ic_lj_application_configure ic_lj_application_call ic_lj_application_free

# The libraries a cgo archive needs on Linux. pthread and dl fold into libc on glibc >= 2.34
# and are no-ops there; they are named because an older glibc still wants them and the
# failure without them is an undefined symbol three steps away from its cause.
CLIBS   := -lpthread -ldl -lresolv

.PHONY: rollback-check
.PHONY: all test ffi header-check nm-check smoke smoke-lock smoke-panic canon-check clean

all: test ffi header-check nm-check smoke smoke-lock smoke-panic smoke-publication canon-check rollback-check

test:
	@$(GO) test ./... -count=1

$(BUILD):
	@mkdir -p $(BUILD)

# CGO_ENABLED=1 is stated rather than assumed. With cgo off this produces an archive that
# links and exports nothing, and the failure surfaces as a missing symbol in some other
# language's build rather than here.
ffi: | $(BUILD)
	@CGO_ENABLED=1 $(GO) build -buildmode=c-archive -trimpath -o $(ARCHIVE) ./ffi
	@echo "  archive: $$(stat -c%s $(ARCHIVE)) bytes"

# ffi/lumberjack.h is the specification; cgo's header is an artefact. Compiling a unit that
# includes both is what makes a divergence a compile error instead of a diff nobody reads.
header-check: ffi
	@$(CC) $(CFLAGS) -fsyntax-only -I ffi -I $(BUILD) ffi/ctest/header_agreement.c
	@echo "  header: the archive matches the specification"

# The forced-panic export must not ship. It lives behind the lj_panic_test tag, so the archive `make
# ffi` builds does not carry it; a diff between the tag and the symbol table is caught here.
nm-check: ffi
	@if $(NM) $(ARCHIVE) | grep -q ic_lj__panic_for_test; then \
		echo "ERROR: ic_lj__panic_for_test is present in the shipped archive"; exit 1; fi
	@echo "  nm: the shipped archive carries no forced-panic export"
	@$(NM) -g --defined-only $(ARCHIVE) | awk '$$2 == "T" && $$3 ~ /^ic_lj_/ { print $$3 }' | sort -u > $(BUILD)/exports.txt
	@printf '%s\n' $(BASE_EXPORTS) | sort -u > $(BUILD)/exports.want
	@diff -u $(BUILD)/exports.want $(BUILD)/exports.txt || { \
		echo "ERROR: the shipped archive's exports are not exactly the base"; exit 1; }
	@echo "  nm: the shipped archive exports exactly the $$(wc -l < $(BUILD)/exports.txt) base functions"

# The ABI is real if a C program that knows nothing about Go can drive it.
smoke: ffi
	@$(CC) $(CFLAGS) -I ffi -I $(BUILD) -o $(BUILD)/smoke ffi/ctest/smoke.c $(ARCHIVE) $(CLIBS)
	@$(BUILD)/smoke

# The lock is real at the boundary if a SECOND PROCESS holding the sidecar is refused LJ_LOCKED, and a
# state file with no sidecar is refused LJ_UNGUARDED until adopted. The programme re-runs itself as
# the holder, so it is a binary of its own.
smoke-lock: ffi
	@$(CC) $(CFLAGS) -I ffi -I $(BUILD) -o $(BUILD)/smoke_lock ffi/ctest/smoke_lock.c $(ARCHIVE) $(CLIBS)
	@$(BUILD)/smoke_lock

# The guard is real if a panic in an export becomes LJ_PANIC and the process is still usable. This
# builds the tagged archive — the ONLY build carrying the forced-panic export — and drives it.
smoke-panic: | $(BUILD)
	@CGO_ENABLED=1 $(GO) build -buildmode=c-archive -trimpath -tags lj_panic_test -o $(PANIC_ARCHIVE) ./ffi
	@$(CC) $(CFLAGS) -I ffi -I $(BUILD) -o $(BUILD)/smoke_panic ffi/ctest/smoke_panic.c $(PANIC_ARCHIVE) $(CLIBS)
	@$(BUILD)/smoke_panic

# The Go canon reader over the corpus: every frozen hex reproduced, every refusal raised by name
# at its locus, every pair held, or the failing case is named. LJ_CANON_CORPUS makes the file
# mandatory — `go test` alone skips when the parent checkout is absent; this gate does not.
canon-check:
	@test -f $(CANON_CORPUS) || { echo "ERROR: no canon corpus at $(CANON_CORPUS)"; exit 1; }
	@LJ_CANON_CORPUS=$(abspath $(CANON_CORPUS)) $(GO) test ./ffi -run '^TestCanonCorpus$$' -count=1 -v
	@echo "  canon: the Go reader agrees with the corpus"

clean:
	@rm -rf $(BUILD)

.PHONY: smoke-publication
smoke-publication: ffi
	@$(CC) $(CFLAGS) -I ffi -I $(BUILD) -o $(BUILD)/smoke_publication ffi/ctest/smoke_publication.c $(ARCHIVE) $(CLIBS)
	@$(BUILD)/smoke_publication

# The rollback check (docs/extension-api.md §7.8.6). This build writes a store from every
# compatibility fixture; the CUT build — the commit every product/* branch starts from — then opens
# each one: plaintext and legacy-label stores with every product field intact, neutral-label stores
# and flag-2 objects refused. The cut build's reader is a template this build does not compile.
CUT      ?= da93661
ROLLBACK := $(BUILD)/rollback
rollback-check: | $(BUILD)
	@git worktree remove --force $(ROLLBACK)/cut > /dev/null 2>&1 || true
	@rm -rf $(ROLLBACK)
	@mkdir -p $(ROLLBACK)/stores
	@git worktree add --detach $(ROLLBACK)/cut $(CUT) > /dev/null
	@LJ_ROLLBACK_DIR=$(abspath $(ROLLBACK)/stores) $(GO) test -tags rollbackwrite -run '^TestWriteRollbackStores$$' -count=1 ./internal > $(ROLLBACK)/write.log 2>&1 || { cat $(ROLLBACK)/write.log; exit 1; }
	@cp internal/compat/rollback/cut_reader_test.go.txt $(ROLLBACK)/cut/internal/zz_rollback_reader_test.go
	@cd $(ROLLBACK)/cut && LJ_ROLLBACK_DIR=$(abspath $(ROLLBACK)/stores) $(GO) test -run '^TestRollbackStoresOpenAtTheCut$$' -count=1 -v ./internal > $(abspath $(ROLLBACK))/read.log 2>&1 || { grep -E -- '--- |_test.go' $(abspath $(ROLLBACK))/read.log; exit 1; }
	@git worktree remove --force $(ROLLBACK)/cut
	@echo "  rollback: the cut build ($(CUT)) opens $$(grep -c -- '--- PASS: TestRollbackStoresOpenAtTheCut/' $(ROLLBACK)/read.log) stores this build wrote as expected"
