// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Command ffi is the generic C archive: the nineteen base exports lumberjack.h specifies and no
// others. Its exports are generated wrappers over ffi/abi (base_exports.go, from ffi/gen); a product
// archive is a main package of its own built the same way, with its exports added
// (docs/extension-api.md §6).
//
//go:generate sh -c "go run ./gen > base_exports.go"
package main

func main() {}
