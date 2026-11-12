// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
)

// The extensions a runtime was opened with. The set is validated and attached once, after the state
// is loaded and before the first request, and is fixed for the life of the runtime
// (docs/extension-api.md §3).

// ErrExtensionSet is wrapped by every refusal of an extension set at Open.
var ErrExtensionSet = errors.New("lumberjack: extension set refused")

// engineConfigParts are the application_configure parts the engine itself reads.
var engineConfigParts = []string{"username", "password", "secret"}

// owned is a capability with the name of the extension that implements it, so the transaction it is
// handed reaches that extension's slots.
type owned[T any] struct {
	capability T
	owner      string
}

type extensionSet struct {
	specs     []extension.Spec
	instances []extension.Instance // attach order

	// The capabilities the instances implement, type-asserted once at attach.
	authenticators []extension.RequestAuthenticator
	configurables  map[string]extension.Configurable // by config part
	secondFactor   extension.SecondFactor            // at most one
	factorOwner    string
	listeners      []owned[extension.OutboxListener]
	entitlements   []owned[extension.OutboxEntitlement]
	routes         []extensionRoute // registration order
	presentation   map[string]bool  // metadata keys whose changes are not news
	markers        []string         // ownership markers: the compatibility marker, then each Spec's
	filters        []extension.VisibilityFilter
	hooks          []owned[extension.WriteHook]
	permits        extension.PermitProvider // at most one
}

// ExtensionSetIdentity names an extension set: its names in registration order. A runtime is shared
// per state path, so a second Open of a path with a different identity is refused.
func ExtensionSetIdentity(exts []extension.Extension) string {
	names := make([]string, len(exts))
	for index, ext := range exts {
		names[index] = ext.Spec().Name
	}
	return strings.Join(names, ",")
}

// extensionClaims is who holds each declared name, per kind, so two declarations of one name are
// refused whoever made them.
type extensionClaims map[string]map[string]string

func (claims extensionClaims) claim(kind, name, owner string) error {
	if name == "" {
		return fmt.Errorf("%w: %s declares an empty %s", ErrExtensionSet, owner, kind)
	}
	if claims[kind] == nil {
		claims[kind] = map[string]string{}
	}
	if holder, taken := claims[kind][name]; taken {
		return fmt.Errorf("%w: %s %q is declared by both %s and %s", ErrExtensionSet, kind, name, holder, owner)
	}
	claims[kind][name] = owner
	return nil
}

// engineClaims are the names the engine holds itself: every key a node record and the outbox carry
// as typed fields, and the configuration parts the engine reads.
func engineClaims() extensionClaims {
	claims := extensionClaims{}
	for _, name := range jsonFieldNames(reflect.TypeOf(core.Node{})) {
		_ = claims.claim("root key", name, "the engine")
		_ = claims.claim("node key", name, "the engine")
	}
	_ = claims.claim("root key", "children", "the engine")
	_ = claims.claim("node key", "children", "the engine")
	for _, name := range jsonFieldNames(reflect.TypeOf(core.Outbox{})) {
		_ = claims.claim("outbox key", name, "the engine")
	}
	for _, part := range engineConfigParts {
		_ = claims.claim("config part", part, "the engine")
	}
	return claims
}

// jsonFieldNames is every key a struct type contributes to its JSON object.
func jsonFieldNames(structType reflect.Type) []string {
	var names []string
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		names = append(names, name)
	}
	return names
}

// validateExtensions refuses a set whose names repeat or are malformed, whose declared keys,
// markers or configuration parts collide with each other's or the engine's, or which holds a
// SnapshotOnly extension under tiered persistence.
func validateExtensions(exts []extension.Extension, tiered bool) ([]extension.Spec, error) {
	claims := engineClaims()
	specs := make([]extension.Spec, 0, len(exts))
	for _, ext := range exts {
		if ext == nil {
			return nil, fmt.Errorf("%w: a nil extension", ErrExtensionSet)
		}
		spec := ext.Spec()
		if !extension.ValidName(spec.Name) {
			return nil, fmt.Errorf("%w: extension name %q is not [a-z0-9-]+", ErrExtensionSet, spec.Name)
		}
		if err := claimSpec(claims, spec); err != nil {
			return nil, err
		}
		if tiered && spec.Persistence == extension.SnapshotOnly {
			return nil, fmt.Errorf("%w: %s runs under snapshot persistence only, and this store is tiered", ErrExtensionSet, spec.Name)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func claimSpec(claims extensionClaims, spec extension.Spec) error {
	declared := []struct {
		kind  string
		names []string
	}{
		{"extension name", []string{spec.Name}},
		{"root key", slotNames(spec.Slot.RootKeys)},
		{"node key", slotNames(spec.Slot.NodeKeys)},
		{"outbox key", slotNames(spec.Slot.OutboxKeys)},
		{"marker", spec.Markers},
		{"config part", spec.ConfigParts},
	}
	for _, group := range declared {
		for _, name := range group.names {
			if err := claims.claim(group.kind, name, spec.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func slotNames(keys []extension.SlotKey) []string {
	names := make([]string, len(keys))
	for index, key := range keys {
		names[index] = key.Name
	}
	return names
}

// ownedMarkers is every CommandReceipts key that marks a node as owned: the compatibility marker
// plus each extension's declared markers.
func (set *extensionSet) ownedMarkers() []string {
	markers := []string{compat.OwnedScopeMarker}
	if set == nil {
		return markers
	}
	for _, spec := range set.specs {
		for _, marker := range spec.Markers {
			if marker != compat.OwnedScopeMarker {
				markers = append(markers, marker)
			}
		}
	}
	return markers
}

// AttachExtensions validates an extension set and attaches each extension in order, once, before
// the first request and with no hold on the forest. A failed attach closes what attached before it,
// in reverse order, and refuses the set.
func (server *Server) AttachExtensions(exts []extension.Extension) error {
	if server.extensions != nil {
		return fmt.Errorf("%w: extensions are attached once per runtime", ErrExtensionSet)
	}
	specs, err := validateExtensions(exts, server.tier != nil)
	if err != nil {
		return err
	}
	set := &extensionSet{specs: specs, configurables: map[string]extension.Configurable{}, presentation: map[string]bool{}}
	set.markers = set.ownedMarkers()
	for index, ext := range exts {
		instance, err := ext.Attach(&extensionHost{server: server, name: specs[index].Name})
		if err == nil && instance == nil {
			err = errors.New("attach answered no instance")
		}
		if err != nil {
			_ = set.close(context.Background())
			return fmt.Errorf("%w: %s did not attach: %v", ErrExtensionSet, specs[index].Name, err)
		}
		set.instances = append(set.instances, instance)
		if err := set.capabilities(specs[index], instance); err != nil {
			_ = set.close(context.Background())
			return err
		}
	}
	if err := set.collectRoutes(server, specs); err != nil {
		_ = set.close(context.Background())
		return err
	}
	server.extensions = set
	return nil
}

// capabilities records what one attached instance implements. An instance that declared config
// parts must be able to receive them.
func (set *extensionSet) capabilities(spec extension.Spec, instance extension.Instance) error {
	if authenticator, ok := instance.(extension.RequestAuthenticator); ok {
		set.authenticators = append(set.authenticators, authenticator)
	}
	if factor, ok := instance.(extension.SecondFactor); ok {
		if set.secondFactor != nil {
			return fmt.Errorf("%w: %s is a second SecondFactor; at most one is registered", ErrExtensionSet, spec.Name)
		}
		set.secondFactor, set.factorOwner = factor, spec.Name
	}
	if listener, ok := instance.(extension.OutboxListener); ok {
		set.listeners = append(set.listeners, owned[extension.OutboxListener]{listener, spec.Name})
	}
	if entitlement, ok := instance.(extension.OutboxEntitlement); ok {
		set.entitlements = append(set.entitlements, owned[extension.OutboxEntitlement]{entitlement, spec.Name})
	}
	if filter, ok := instance.(extension.VisibilityFilter); ok {
		set.filters = append(set.filters, filter)
	}
	if hook, ok := instance.(extension.WriteHook); ok {
		set.hooks = append(set.hooks, owned[extension.WriteHook]{hook, spec.Name})
	}
	if provider, ok := instance.(extension.PermitProvider); ok {
		if set.permits != nil {
			return fmt.Errorf("%w: %s is a second PermitProvider; at most one is registered", ErrExtensionSet, spec.Name)
		}
		set.permits = provider
	}
	for _, key := range spec.PresentationMetadata {
		set.presentation[key] = true
	}
	configurable, ok := instance.(extension.Configurable)
	if len(spec.ConfigParts) > 0 && !ok {
		return fmt.Errorf("%w: %s declares config parts and cannot be configured", ErrExtensionSet, spec.Name)
	}
	for _, part := range spec.ConfigParts {
		set.configurables[part] = configurable
	}
	return nil
}

// CloseExtensions closes every attached instance in reverse attach order, with no hold on the
// forest. After it returns no Host call is honoured.
func (server *Server) CloseExtensions(ctx context.Context) error {
	set := server.extensions
	if set == nil {
		return nil
	}
	err := set.close(ctx)
	server.extensionsClosed.Store(true)
	return err
}

func (set *extensionSet) close(ctx context.Context) error {
	var first error
	for index := len(set.instances) - 1; index >= 0; index-- {
		if err := set.instances[index].Close(ctx); err != nil && first == nil {
			first = err
		}
	}
	set.instances = nil
	return first
}
