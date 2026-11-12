// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/NeoTecDigital/LumberJack/extension"
)

// OpenWith's runtime rules (docs/extension-api.md §3): one extension set per runtime, attached once,
// closed in reverse attach order before the server shuts down and the flock is released.

type recordingExtension struct {
	name   string
	events *[]string
	mu     *sync.Mutex
}

func (e recordingExtension) Spec() extension.Spec { return extension.Spec{Name: e.name} }

func (e recordingExtension) Attach(extension.Host) (extension.Instance, error) {
	e.record("attach " + e.name)
	return e, nil
}

func (e recordingExtension) Close(context.Context) error {
	e.record("close " + e.name)
	return nil
}

func (e recordingExtension) record(event string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	*e.events = append(*e.events, event)
}

func TestOpenWithSharesOnlyTheSameExtensionSet(t *testing.T) {
	var events []string
	var mu sync.Mutex
	one := recordingExtension{"one", &events, &mu}
	two := recordingExtension{"two", &events, &mu}
	config := embeddedConfig(t)
	first, err := OpenWith(config, "", one, two)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(config, "", two, one); !errors.Is(err, ErrExtensionConflict) {
		t.Fatalf("a different order of the set was shared: %v", err)
	}
	if _, err := Open(config, ""); !errors.Is(err, ErrExtensionConflict) {
		t.Fatalf("an Open with no extensions shared an extended runtime: %v", err)
	}
	second, err := OpenWith(config, "", one, two)
	if err != nil {
		t.Fatalf("the same set was refused: %v", err)
	}
	if refsOf(first.runtime) != 2 {
		t.Fatalf("the same set did not share the runtime: %d refs", refsOf(first.runtime))
	}
	_ = second.Close()
	if got := strings.Join(events, ";"); got != "attach one;attach two" {
		t.Fatalf("a shared close closed the instances: %q", got)
	}
	_ = first.Close()
	if got := strings.Join(events, ";"); got != "attach one;attach two;close two;close one" {
		t.Fatalf("last close sequence %q", got)
	}
	if inRegistry(first.runtime.path) {
		t.Fatal("a closed extended runtime is still registered")
	}
	reopened, err := Open(config, "")
	if err != nil {
		t.Fatalf("the path did not reopen without extensions after the close: %v", err)
	}
	_ = reopened.Close()
}
