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

# The libraries a cgo archive needs on Linux. pthread and dl fold into libc on glibc >= 2.34
# and are no-ops there; they are named because an older glibc still wants them and the
# failure without them is an undefined symbol three steps away from its cause.
CLIBS   := -lpthread -ldl -lresolv

.PHONY: all test ffi header-check nm-check smoke smoke-panic clean

all: test ffi header-check nm-check smoke smoke-panic

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

# The ABI is real if a C program that knows nothing about Go can drive it.
smoke: ffi
	@$(CC) $(CFLAGS) -I ffi -I $(BUILD) -o $(BUILD)/smoke ffi/ctest/smoke.c $(ARCHIVE) $(CLIBS)
	@$(BUILD)/smoke

# The guard is real if a panic in an export becomes LJ_PANIC and the process is still usable. This
# builds the tagged archive — the ONLY build carrying the forced-panic export — and drives it.
smoke-panic: | $(BUILD)
	@CGO_ENABLED=1 $(GO) build -buildmode=c-archive -trimpath -tags lj_panic_test -o $(PANIC_ARCHIVE) ./ffi
	@$(CC) $(CFLAGS) -I ffi -I $(BUILD) -o $(BUILD)/smoke_panic ffi/ctest/smoke_panic.c $(PANIC_ARCHIVE) $(CLIBS)
	@$(BUILD)/smoke_panic

clean:
	@rm -rf $(BUILD)
