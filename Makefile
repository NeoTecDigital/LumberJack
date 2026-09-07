# Written by Richard Christopher, Copyright 2026 NeoTec, LLC
# Non-commercial use only; see LICENSE.

GO      ?= go
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror
BUILD   := build
ARCHIVE := $(BUILD)/liblumberjack.a
HEADER  := $(BUILD)/liblumberjack.h

# The libraries a cgo archive needs on Linux. pthread and dl fold into libc on glibc >= 2.34
# and are no-ops there; they are named because an older glibc still wants them and the
# failure without them is an undefined symbol three steps away from its cause.
CLIBS   := -lpthread -ldl -lresolv

.PHONY: all test ffi header-check smoke clean

all: test ffi header-check smoke

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

# The ABI is real if a C program that knows nothing about Go can drive it.
smoke: ffi
	@$(CC) $(CFLAGS) -I ffi -I $(BUILD) -o $(BUILD)/smoke ffi/ctest/smoke.c $(ARCHIVE) $(CLIBS)
	@$(BUILD)/smoke

clean:
	@rm -rf $(BUILD)
