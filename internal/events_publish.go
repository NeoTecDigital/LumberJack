package internal

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/core"
)

const PublishMaxEvents = 16
const PublishMaxBytes = 4 * 1024 * 1024
const publishMaxPath = 4096

// CompleteEvent is one fresh, single-entry event, not a general mutation program.
type CompleteEvent struct {
	EventID       string                 `json:"event_id"`
	Metadata      map[string]interface{} `json:"metadata"`
	Content       string                 `json:"content"`
	EntryMetadata map[string]interface{} `json:"entry_metadata"`
}

type PublishEventsRequest struct {
	Path   string          `json:"path"`
	Events []CompleteEvent `json:"events"`
}

type PublishEventsResult struct {
	Published int `json:"published"`
}

// PublishEvents stages all changes before installing them under the forest lock.
// Success still waits for the existing durable snapshot commit. Persist failure
// retains the existing uncertain-memory semantics, never an early acknowledgement.
func (server *Server) PublishEvents(userID string, request PublishEventsRequest) (PublishEventsResult, error) {
	owned, err := ownedPublication(request)
	if err != nil {
		return PublishEventsResult{}, err
	}
	err = server.changeNode(owned.Path, userID, core.WritePermission, func(node *core.Node) error {
		return installPublication(node, userID, owned.Events)
	})
	if err != nil {
		return PublishEventsResult{}, err
	}
	for _, item := range owned.Events {
		announced := mutation(mutationEventEnded, owned.Path)
		announced.EventID = item.EventID
		server.publish(announced)
	}
	return PublishEventsResult{Published: len(owned.Events)}, nil
}

func ownedPublication(request PublishEventsRequest) (PublishEventsRequest, error) {
	if len(request.Events) < 1 || len(request.Events) > PublishMaxEvents {
		return PublishEventsRequest{}, apiErrorf(http.StatusBadRequest, "publication requires 1..16 events")
	}
	if len(request.Path) > publishMaxPath {
		return PublishEventsRequest{}, apiErrorf(http.StatusRequestEntityTooLarge, "publication path exceeds bound")
	}
	wire, err := json.Marshal(request)
	if err != nil {
		return PublishEventsRequest{}, apiErrorf(http.StatusBadRequest, "invalid publication metadata")
	}
	if len(wire) > PublishMaxBytes {
		return PublishEventsRequest{}, apiErrorf(http.StatusRequestEntityTooLarge, "publication exceeds byte bound")
	}
	var owned PublishEventsRequest
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if err := decoder.Decode(&owned); err != nil {
		return PublishEventsRequest{}, err
	}
	return owned, nil
}

func publicationIDs(node *core.Node, events []CompleteEvent) error {
	seen := make(map[string]bool, len(events))
	for _, item := range events {
		if !validEventID(item.EventID) {
			return apiErrorf(http.StatusBadRequest, eventIDRequired)
		}
		if len(item.EventID) > publishMaxPath {
			return apiErrorf(http.StatusRequestEntityTooLarge, "publication ID exceeds bound")
		}
		_, live := node.Events[item.EventID]
		_, planned := node.PlannedEvents[item.EventID]
		if live || planned || seen[item.EventID] {
			return apiErrorf(http.StatusConflict, "publication identity already exists")
		}
		seen[item.EventID] = true
	}
	return nil
}

func installPublication(node *core.Node, userID string, events []CompleteEvent) error {
	if err := publicationIDs(node, events); err != nil {
		return err
	}
	// The existing lifecycle supplies timestamps, authorship, entry IDs and state.
	// This detached node is not a store or another authority; its user list is read
	// only while the real node's current permission is protected by the forest lock.
	stage := &core.Node{Users: node.Users, Events: make(map[string]core.Event), PlannedEvents: make(map[string]core.Event)}
	for _, item := range events {
		if err := stageCompleteEvent(stage, userID, item); err != nil {
			return err
		}
	}
	if node.Events == nil {
		node.Events = make(map[string]core.Event)
	}
	for id, event := range stage.Events {
		node.Events[id] = event
	}
	return nil
}

func stageCompleteEvent(stage *core.Node, userID string, item CompleteEvent) error {
	if err := stage.StartEvent(item.EventID, userID, nil, nil, item.Metadata); err != nil {
		return err
	}
	if err := stage.AppendToEvent(item.EventID, userID, item.Content, item.EntryMetadata); err != nil {
		return err
	}
	return stage.EndEvent(item.EventID, userID)
}
