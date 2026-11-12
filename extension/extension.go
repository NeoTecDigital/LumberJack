// Written by Richard Christopher, Copyright 2026 NeoTec, LLC

// Package extension is the public surface a product builds on to run inside a LumberJack store. It
// imports only core and types, so the engine can call it without a cycle and a product can be built
// against it without the engine's internals. See docs/extension-api.md.
//
// The extension set is known at Open and fixed for the life of a runtime: it is static
// configuration, not runtime discovery.
package extension

import (
	"context"
	"encoding/json"
	"regexp"
)

// Extension is registered at Open. Spec is read once. Attach runs once per runtime (per forest),
// after the state is loaded and before the first request, with no forest hold.
type Extension interface {
	Spec() Spec
	Attach(host Host) (Instance, error)
}

// Spec is what an extension declares about itself. Everything in it is validated at Open.
type Spec struct {
	Name        string      // stable, [a-z0-9-]+; namespaces grant ids, config parts, errors
	Slot        SlotSpec    // persisted keys this extension owns
	Markers     []string    // CommandReceipts keys that mark a node as owned by this extension
	ConfigParts []string    // application_configure parts it consumes, e.g. "admission"
	Persistence Persistence // AnyPersistence | SnapshotOnly (refused under tiered persistence)
}

// Persistence is which persistence modes an extension can run under.
type Persistence uint8

const (
	// AnyPersistence runs under snapshot and tiered persistence.
	AnyPersistence Persistence = iota
	// SnapshotOnly is refused at Open under tiered persistence.
	SnapshotOnly
)

// SlotSpec names the persisted keys an extension owns. Keys nobody claims are preserved as the
// bytes the state file held.
type SlotSpec struct {
	RootKeys   []SlotKey // top-level keys on the root's node record, e.g. "account_security"
	NodeKeys   []SlotKey // top-level keys any node record may carry
	OutboxKeys []SlotKey // keys inside the root's "correspondence" object, e.g. "feed"
}

// SlotKey is one claimed key and how its value is decoded.
type SlotKey struct {
	Name  string
	Codec Codec // nil: the extension sees json.RawMessage
}

// Codec decodes a slot value once on first access and encodes it only when it was set since load.
type Codec interface {
	Decode(raw json.RawMessage) (any, error) // must preserve numbers (decoder.UseNumber)
	Encode(v any) (json.RawMessage, error)
}

// Instance is the per-forest object. It may implement any of the optional capability interfaces
// (PermitProvider, WriteHook, VisibilityFilter, RouteProvider, RequestAuthenticator, SecondFactor,
// GrantSource, OutboxListener, OutboxEntitlement, Configurable). The engine type-asserts each one
// once, at Attach.
type Instance interface {
	Close(ctx context.Context) error // forest unheld; after it returns, no Host call may arrive
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// ValidName reports whether a name is a valid extension name.
func ValidName(name string) bool { return namePattern.MatchString(name) }
