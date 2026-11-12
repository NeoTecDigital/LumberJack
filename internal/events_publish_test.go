package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
)

func publicationFixture(t *testing.T) (*Server, string, string, string) {
	t.Helper()
	s, dir := newStockServer(t)
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	actor := adminID(t, s)
	return s, dir, actor, leafFor(t, s, actor, "work/publication")
}

func publicationRequest(path string, ids ...string) PublishEventsRequest {
	request := PublishEventsRequest{Path: path}
	for _, id := range ids {
		request.Events = append(request.Events, CompleteEvent{EventID: id, Content: "body-" + id,
			Metadata: map[string]interface{}{"id": id}, EntryMetadata: map[string]interface{}{"seal": "test"}})
	}
	return request
}

func assertPublication(t *testing.T, s *Server, actor, path, id string) {
	t.Helper()
	err := s.readNode(path, actor, core.ReadPermission, func(node *core.Node) error {
		event, exists := node.Events[id]
		if !exists || event.Status != "finished" || len(event.Entries) != 1 {
			return fmt.Errorf("not one complete event: %+v", event)
		}
		entry := event.Entries[0]
		if entry.Content != "body-"+id || entry.UserID != actor || entry.ID == "" || entry.Timestamp.IsZero() {
			return fmt.Errorf("lost lifecycle provenance: %+v", entry)
		}
		if event.Metadata["id"] != id || entry.Metadata["seal"] != "test" {
			return errors.New("metadata changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicationOneCommitAndDurableLifecycle(t *testing.T) {
	s, dir, actor, path := publicationFixture(t)
	original, commits := s.stateWriter.write, 0
	s.stateWriter.write = func(snapshot stateSnapshot) error { commits++; return original(snapshot) }
	request := publicationRequest(path, "a", "b", "c")
	before := s.mutations.sequence
	result, err := s.PublishEvents(actor, request)
	if err != nil || result.Published != 3 || commits != 1 {
		t.Fatalf("%+v %v commits=%d", result, err, commits)
	}
	if s.mutations.sequence != before+3 {
		t.Fatal("missing completed notifications")
	}
	request.Events[0].Metadata["id"] = "tampered"
	loaded := reloadServer(t, dir)
	defer loaded.Shutdown(context.Background())
	for _, id := range []string{"a", "b", "c"} {
		assertPublication(t, s, actor, path, id)
		assertPublication(t, loaded, actor, path, id)
	}
}

func assertPublicationRefused(t *testing.T, s *Server, actor string, request PublishEventsRequest) {
	t.Helper()
	before, err := os.ReadFile(s.statePath())
	if err != nil {
		t.Fatal(err)
	}
	sequence := s.mutations.sequence
	result, err := s.PublishEvents(actor, request)
	if err == nil || result.Published != 0 {
		t.Fatalf("unexpected ack %+v %v", result, err)
	}
	after, err := os.ReadFile(s.statePath())
	if err != nil || !bytes.Equal(before, after) || sequence != s.mutations.sequence {
		t.Fatal("refusal changed state/feed")
	}
	if err := s.readNode(request.Path, adminID(t, s), core.ReadPermission, func(n *core.Node) error {
		if _, found := n.Events["fresh"]; found {
			return errors.New("partial publication")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationRejectsWholeInvalidBatch(t *testing.T) {
	s, _, actor, path := publicationFixture(t)
	if _, err := s.PublishEvents(actor, publicationRequest(path, "existing")); err != nil {
		t.Fatal(err)
	}
	if err := s.changeNode(path, actor, core.WritePermission, func(n *core.Node) error {
		n.PlannedEvents["planned"] = core.Event{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]string{{"fresh", "existing"}, {"fresh", "planned"}, {"fresh", "fresh"}, {"fresh", " "}, {"fresh", strings.Repeat("x", 4097)}} {
		assertPublicationRefused(t, s, actor, publicationRequest(path, ids...))
	}
	assertPublicationRefused(t, s, "denied", publicationRequest(path, "fresh"))
	assertPublicationRefused(t, s, actor, publicationRequest(path))
	many := publicationRequest(path, "fresh")
	many.Events = append(many.Events, make([]CompleteEvent, PublishMaxEvents)...)
	assertPublicationRefused(t, s, actor, many)
	large := publicationRequest(path, "fresh")
	large.Events[0].Content = strings.Repeat("x", PublishMaxBytes)
	assertPublicationRefused(t, s, actor, large)
	if _, err := ownedPublication(publicationRequest(strings.Repeat("x", 4097), "fresh")); err == nil {
		t.Fatal("unbounded path")
	}
}

func TestPublicationPersistenceFailureHasNoAckOrAnnouncement(t *testing.T) {
	s, dir, actor, path := publicationFixture(t)
	original := s.stateWriter.write
	defer func() { s.stateWriter.write = original }()
	s.stateWriter.write = func(stateSnapshot) error { return errors.New("injected durable write failure") }
	sequence := s.mutations.sequence
	result, err := s.PublishEvents(actor, publicationRequest(path, "uncertain"))
	if err == nil || result.Published != 0 || s.mutations.sequence != sequence {
		t.Fatal("false durable acknowledgement")
	}
	// Memory retains uncertainty, while the previously durable file is unchanged.
	assertPublication(t, s, actor, path, "uncertain")
	loaded := reloadServer(t, dir)
	defer loaded.Shutdown(context.Background())
	if err := loaded.readNode(path, actor, core.ReadPermission, func(n *core.Node) error {
		if _, found := n.Events["uncertain"]; found {
			return errors.New("failed write on disk")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationConcurrentBatchesAreDurable(t *testing.T) {
	s, dir, actor, path := publicationFixture(t)
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			ids := []string{fmt.Sprintf("%d-a", index), fmt.Sprintf("%d-b", index)}
			if _, err := s.PublishEvents(actor, publicationRequest(path, ids...)); err != nil {
				t.Error(err)
			}
		}(index)
	}
	wait.Wait()
	loaded := reloadServer(t, dir)
	defer loaded.Shutdown(context.Background())
	for index := 0; index < 8; index++ {
		assertPublication(t, loaded, actor, path, fmt.Sprintf("%d-a", index))
		assertPublication(t, loaded, actor, path, fmt.Sprintf("%d-b", index))
	}
}
