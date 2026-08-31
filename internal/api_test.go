package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

var (
	testDbPath string // Global state file for all tests
	testDbName string // Global state file for all tests
	testDbFile string // Global state file for all tests
	logger     types.Logger
)

func TestMain(m *testing.M) {
	// The server FAILS CLOSED without a signing key, so the suite has to supply one the way a
	// deployment does.
	if err := os.Setenv("LUMBERJACK_JWT_SECRET", "test-signing-key-not-a-deployment-key"); err != nil {
		log.Fatalf("Failed to set the test signing key: %v", err)
	}

	// Setup test environment
	testDbName = "test_state"
	testDbPath, err := os.MkdirTemp("", "core-test-*")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	testDbFile = filepath.Join(testDbPath, testDbName+".dat")
	logger = types.NewLogger()

	// Create empty database file
	if _, err := os.Create(testDbFile); err != nil {
		log.Fatalf("Failed to create test state file: %v", err)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	os.RemoveAll(testDbPath)
	os.Exit(code)
}

// withUser puts the caller in the request context the way authMiddleware does.
//
// These tests used to set an X-User-ID header, which the middleware ABANDONED when it moved to
// reading the id out of the token claims. The header went nowhere, so every handler under test saw
// no user at all.
func withUser(r *http.Request, userID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), "user_id", userID))
}

func setupTestForest(t *testing.T) *Server {
	server, err := NewServer(types.ServerConfig{
		Organization: "test_org",
		Phone:        "1234567890",
		Process: types.ProcessInfo{
			ID:            "test_process",
			PID:           12345,
			Name:          "test_state",
			ServerURL:     "localhost",
			ServerPort:    "8080",
			DashboardPort: "8081",
			DashboardURL:  "localhost",
			DashboardUp:   true,
			LogPath:       filepath.Dir(testDbFile),
			DatabasePath:  filepath.Dir(testDbFile),
		},
	}, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	logger := types.NewLogger()
	logger.Enter("Setting up test forest")
	defer logger.Exit("Setting up test forest")
	root := server.forest

	// Create basic structure with admin user
	root.ID = "root"
	root.Name = "root"
	root.Type = core.BranchNode
	root.Children = make(map[string]*core.Node)

	adminUser := core.User{
		ID:          "admin",
		Username:    "admin",
		Permissions: []core.Permission{core.AdminPermission},
	}
	root.Users = []core.User{adminUser}

	// Create test node with admin permissions
	testNode := core.NewNode(core.LeafNode, "test-node")
	testNode.ID = "test-node"
	testNode.Users = []core.User{adminUser}

	// Add child and set up parent reference
	root.AddChild(testNode)

	// Save initial state
	if err := server.writeChangesToFile(testDbFile); err != nil {
		logger.Failure("Failed to write initial state: %v", err)
	} else {
		logger.Success("Saved initial state to file")
	}

	logger.Info("Test forest setup complete")
	return server
}

func TestForestOperations(t *testing.T) {
	logger.Enter("ForestOperations")
	defer logger.Exit("ForestOperations")

	// Setup test server
	server := setupTestForest(t)
	rootNode := server.forest

	t.Run("Node Creation", func(t *testing.T) {
		logger.Enter("Node Creation")
		defer logger.Exit("Node Creation")

		childNode1 := core.NewNode(core.BranchNode, "child1")
		childNode1.ID = "child1"
		childNode2 := core.NewNode(core.LeafNode, "child2")
		childNode2.ID = "child2"
		childNode3 := core.NewNode(core.LeafNode, "child3")
		childNode3.ID = "child3"

		rootNode.Children[childNode1.ID] = childNode1
		rootNode.Children[childNode2.ID] = childNode2
		rootNode.Children[childNode3.ID] = childNode3

		if err := server.writeChangesToFile(testDbFile); err != nil {
			logger.Failure("Failed to write state to file: %v", err)
			t.Errorf("Failed to write state to file: %v", err)
		} else {
			logger.Success("State saved to file")
		}

		if len(rootNode.Children) != 4 {
			logger.Failure("Expected 4 children, got %d", len(rootNode.Children))
			t.Errorf("Expected 4 children, got %d", len(rootNode.Children))
		} else {
			logger.Success("Found 4 children")
			for _, child := range rootNode.Children {
				logger.Info("Child: %s", child.Name)
			}
		}
	})

	t.Run("User Management", func(t *testing.T) {
		logger.Enter("User Management")
		defer logger.Exit("User Management")

		user1 := core.User{ID: "user1", Permissions: []core.Permission{core.ReadPermission, core.WritePermission}}
		user2 := core.User{ID: "user2", Permissions: []core.Permission{core.ReadPermission}}
		user3 := core.User{ID: "user3", Permissions: []core.Permission{core.AdminPermission}}

		childNode2 := rootNode.Children["child2"]
		childNode3 := rootNode.Children["child3"]

		if err := childNode2.AssignUser(user1, core.ReadPermission); err != nil {
			logger.Failure("Failed to assign user1 to childNode2: %v", err)
			t.Error(err)
		} else {
			logger.Success("User1 assigned to childNode2")
		}

		if err := childNode2.AssignUser(user2, core.ReadPermission); err != nil {
			logger.Failure("Failed to assign user2 to childNode2: %v", err)
			t.Error(err)
		} else {
			logger.Success("User2 assigned to childNode2")
		}

		if err := childNode3.AssignUser(user3, core.AdminPermission); err != nil {
			logger.Failure("Failed to assign user3 to childNode3: %v", err)
			t.Error(err)
		} else {
			logger.Success("User3 assigned to childNode3")
		}

		// Check permissions
		if !childNode2.CheckPermission("user1", core.ReadPermission) {
			logger.Failure("user1 should have read permission on childNode2")
			t.Error("user1 should have read permission on childNode2")
		} else if !childNode3.CheckPermission("user3", core.AdminPermission) {
			logger.Failure("user3 should have admin permission on childNode3")
			t.Error("user3 should have admin permission on childNode3")
		} else if childNode2.CheckPermission("user2", core.WritePermission) {
			logger.Failure("user2 should not have write permission on childNode2")
			t.Error("user2 should not have write permission on childNode2")
		} else {
			logger.Success("Permission checks passed successfully")
		}
	})

	t.Run("Event Management", func(t *testing.T) {
		logger.Enter("Event Management")
		defer logger.Exit("Event Management")

		childNode2 := rootNode.Children["child2"]
		now := time.Now()
		event1ID := "event1"

		logger.Info("Starting Event 1")
		if err := childNode2.StartEvent(event1ID, "user1", &now, nil, map[string]interface{}{"title": "Test Event 1"}); err != nil {
			logger.Failure("Failed to start event: %v", err)
			t.Error(err)
		} else {
			logger.Success("Event started successfully")
		}

		logger.Info("Appending Entry to Event 1")
		if err := childNode2.AppendToEvent(event1ID, "user1", "Event entry 1", map[string]interface{}{"note": "First entry"}); err != nil {
			logger.Failure("Failed to append to event: %v", err)
			t.Errorf("Failed to append to event: %v", err)
		} else {
			logger.Success("Appended entry to event")
		}

		logger.Info("Ending Event 1")
		if err := childNode2.EndEvent(event1ID, "user1"); err != nil {
			logger.Failure("Failed to end event: %v", err)
			t.Errorf("Failed to end event: %v", err)
		} else {
			logger.Success("Event ended successfully")
		}

		// Verify event storage and persistence
		originalEvent, exists := childNode2.Events[event1ID]
		if !exists {
			logger.Failure("Event %s not found in storage", event1ID)
			t.Errorf("Event %s not found in storage", event1ID)
		} else {
			logger.Success("Event found in storage")
		}

		if err := server.writeChangesToFile(testDbFile); err != nil {
			logger.Failure("Failed to write state to file: %v", err)
		} else {
			logger.Success("State saved to file")
		}

		// Get the stored event after reload
		storedEvent, exists := childNode2.Events[event1ID]
		if !exists {
			logger.Failure("Event %s not found in storage after reload", event1ID)
			t.Errorf("Event %s not found in storage after reload", event1ID)
		} else {
			logger.Success("Event found in storage after reload")
		}

		// Verify event properties
		if !storedEvent.StartTime.Equal(*originalEvent.StartTime) {
			logger.Failure("Start time mismatch after storage: expected %v, got %v",
				originalEvent.StartTime, storedEvent.StartTime)
			t.Errorf("Start time mismatch after storage: expected %v, got %v",
				originalEvent.StartTime, storedEvent.StartTime)
		} else {
			logger.Success("Event start time is correct")
		}

		logger.Info("Getting Event Summary")
		eventSummary, err := childNode2.GetEventSummary(event1ID)
		if err != nil {
			logger.Failure("Failed to get event summary: %v", err)
			t.Errorf("Failed to get event summary: %v", err)
		} else if eventSummary.Status != core.EventFinished {
			logger.Failure("Expected event status to be 'finished', got '%s'", eventSummary.Status)
			t.Errorf("Expected event status to be 'finished', got '%s'", eventSummary.Status)
		} else if eventSummary.EntriesCount != 1 {
			logger.Failure("Expected 1 entry in the event, got %d", eventSummary.EntriesCount)
			t.Errorf("Expected 1 entry in the event, got %d", eventSummary.EntriesCount)
		} else {
			logger.Success("Event summary is correct")
		}

		// Test planned events
		event2ID := "event2"
		plannedStart := now.Add(time.Hour)
		plannedEnd := now.Add(2 * time.Hour)
		if err := childNode2.PlanEvent(event2ID, "user1", &plannedStart, &plannedEnd, map[string]interface{}{"title": "Test Event 2"}); err != nil {
			logger.Failure("Failed to plan event: %v", err)
			t.Errorf("Failed to plan event: %v", err)
		} else {
			logger.Success("Planned event successfully")
		}

		// Compare planned vs actual events
		match, err := childNode2.CompareEvents(event2ID, event1ID)
		if match {
			logger.Failure("Expected events to not match, but they did")
			t.Errorf("Expected events to not match, but they did")
		} else {
			logger.Success("Found expected differences: %s", err)
		}
	})

	t.Run("Time Tracking", func(t *testing.T) {
		logger.Enter("Time Tracking")
		defer logger.Exit("Time Tracking")

		childNode2 := rootNode.Children["child2"]

		_, err := childNode2.StartTimeTracking("user1")
		if err != nil {
			logger.Failure("Failed to start time tracking: %v", err)
			t.Error(err)
		} else {
			logger.Success("Time tracking started")
		}

		_, err = childNode2.StopTimeTracking("user1")
		if err != nil {
			logger.Failure("Failed to stop time tracking: %v", err)
			t.Error(err)
		} else {
			logger.Success("Time tracking stopped")
		}

		summary := childNode2.GetTimeTrackingSummary("user1")
		if len(summary) != 1 {
			logger.Failure("Expected 1 time tracking entry, got %d: %s", len(summary), summary)
			t.Errorf("Expected 1 time tracking entry, got %d: %s", len(summary), summary)
		} else {
			logger.Success("Time tracking summary is correct")
		}
	})

	t.Run("Persistence Verification", func(t *testing.T) {
		logger.Enter("Persistence Verification")
		defer logger.Exit("Persistence Verification")

		if err := server.writeChangesToFile(testDbFile); err != nil {
			logger.Failure("Failed to save final state: %v", err)
			t.Error(err)
		} else {
			logger.Success("State saved successfully")
		}

		// Create new app and load state
		newApp, err := NewServer(types.ServerConfig{
			Organization: "test_org",
			Phone:        "1234567890",
			Process: types.ProcessInfo{
				Name:         "test_state",
				DatabasePath: t.TempDir(),
				ServerPort:   "8080",
			},
		}, core.User{Username: "admin", Password: "admin"})
		if err != nil {
			logger.Failure("Failed to create server: %v", err)
			t.Fatalf("Failed to create server: %v", err)
		} else {
			logger.Success("Server created successfully")
		}
		if err := newApp.loadFromFile(testDbFile); err != nil {
			logger.Failure("Failed to load state from file: %v", err)
			t.Fatalf("Failed to load state from file: %v", err)
		} else {
			logger.Success("State loaded successfully")
		}

		// Verify the loaded forest
		if _, err := newApp.forest.GetNode("child2"); err != nil {
			logger.Failure("Failed to find childNode2 in the loaded forest: %v", err)
			t.Errorf("Failed to find childNode2 in the loaded forest: %v", err)
		} else {
			logger.Success("Found childNode2 in the loaded forest")
		}
	})
}

func TestJsonSerialization(t *testing.T) {

	logger.Enter("JsonSerialization")
	defer logger.Exit("JsonSerialization")

	logger.Enter("Node Setup")
	node := core.NewNode(core.BranchNode, "test-node")
	node.Users = []core.User{
		{ID: "user1", Username: "User 1", Email: "user1@example.com", Permissions: []core.Permission{core.ReadPermission, core.WritePermission}},
		{ID: "user2", Username: "User 2", Email: "user2@example.com", Permissions: []core.Permission{core.ReadPermission}},
	}

	// Add some events
	now := time.Now()
	one_hour := now.Add(time.Hour)
	node.Events = map[string]core.Event{
		"event1": {
			StartTime: &now,
			EndTime:   &one_hour,
			Entries: []core.Entry{
				{Content: "Entry 1", Timestamp: now, UserID: "user1"},
				{Content: "Entry 2", Timestamp: now.Add(10 * time.Minute), UserID: "user2"},
			},
			Metadata: map[string]interface{}{"title": "Test Event 1"},
			Status:   core.EventFinished,
		},
	}
	logger.Exit("Node Setup")

	logger.Enter("Serialization")
	jsonData, err := json.Marshal(node)
	if err != nil {
		logger.Failure("Failed to marshal node: %v", err)
		t.Error(err)
	} else {
		logger.Success("Node marshalled successfully")
	}

	// Deserialize the node from JSON
	var loadedNode core.Node
	if err := json.Unmarshal(jsonData, &loadedNode); err != nil {
		logger.Failure("Failed to unmarshal node from JSON: %v", err)
		t.Error(err)
	}

	// Verify the deserialized node
	if loadedNode.Name != "test-node" {
		logger.Failure("Expected node name to be 'test-node', got '%s'", loadedNode.Name)
		t.Errorf("Expected node name to be 'test-node', got '%s'", loadedNode.Name)
	} else {
		logger.Success("Node name is correct")
	}
	if len(loadedNode.Users) != 2 {
		logger.Failure("Expected 2 users, got %d", len(loadedNode.Users))
		t.Errorf("Expected 2 users, got %d", len(loadedNode.Users))
	} else {
		logger.Success("Found 2 users")
	}
	if len(loadedNode.Events) != 1 {
		logger.Failure("Expected 1 event, got %d", len(loadedNode.Events))
		t.Errorf("Expected 1 event, got %d", len(loadedNode.Events))
	} else {
		logger.Success("Found 1 event")
	}
	event, ok := loadedNode.Events["event1"]
	if !ok {
		logger.Failure("Expected event with ID 'event1' to be present")
		t.Errorf("Expected event with ID 'event1' to be present")
	} else {
		logger.Success("Event found")
	}
	if event.Entries[0].Content != "Entry 1" {
		logger.Failure("Expected first event entry to have content 'Entry 1', got '%s'", event.Entries[0].Content)
		t.Errorf("Expected first event entry to have content 'Entry 1', got '%s'", event.Entries[0].Content)
	} else {
		logger.Success("Event entry content is correct")
	}
	logger.Exit("Serialization")
}

func TestHandleAssignUser(t *testing.T) {

	logger.Enter("HandleAssignUser")
	defer logger.Exit("HandleAssignUser")

	app := setupTestForest(t)

	body := map[string]interface{}{
		"path":        "test-node",
		"assignee_id": "test_user",
		"permission":  core.WritePermission,
	}
	bodyBytes, _ := json.Marshal(body)

	rr := post(t, app.handleAssignUser, "admin", body)
	if rr.Code != http.StatusOK {
		logger.Failure("Handler returned wrong status code: got %v want %v\nBody: %v",
			rr.Code, http.StatusOK, rr.Body.String())
		t.Errorf("Handler returned wrong status code: got %v want %v\nBody: %v",
			rr.Code, http.StatusOK, rr.Body.String())
	} else {
		logger.Success("User assigned successfully")
	}

	// The assignment actually landed on the node, which a test that only reads the status code
	// could not tell from a handler that answered 200 and did nothing.
	node, err := app.forest.GetNode("test-node")
	if err != nil {
		t.Fatalf("Failed to find the node the user was assigned to: %v", err)
	}
	if !node.CheckPermission("test_user", core.WritePermission) {
		t.Error("The assignee has no write permission on the node")
	}

	// A caller with no user in the context is refused rather than crashing the process, which is
	// what the unchecked context assertion used to do.
	unauthenticated := httptest.NewRequest("POST", "/users/assign", bytes.NewBuffer(bodyBytes))
	unauthenticatedRecorder := httptest.NewRecorder()
	app.handleAssignUser(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Errorf("Assign with no user in session: got %d, want %d",
			unauthenticatedRecorder.Code, http.StatusUnauthorized)
	}

	// Save state
	if err := app.writeChangesToFile(testDbFile); err != nil {
		logger.Failure("Failed to save state: %v", err)
		t.Fatalf("Failed to save state: %v", err)
	} else {
		logger.Success("State saved successfully")
	}
}

func TestHandleGetTimeTracking(t *testing.T) {

	logger.Enter("HandleGetTimeTracking")
	defer logger.Exit("HandleGetTimeTracking")

	app := setupTestForest(t)

	// Start time tracking
	startBody := map[string]interface{}{
		"path": "test-node",
	}
	startBytes, _ := json.Marshal(startBody)
	startReq := httptest.NewRequest("POST", "/start_time_tracking", bytes.NewBuffer(startBytes))
	startReq = withUser(startReq, "admin")
	startReq.Header.Set("Content-Type", "application/json")
	app.handleStartTimeTracking(httptest.NewRecorder(), startReq)

	// Stop time tracking
	stopReq := httptest.NewRequest("POST", "/stop_time_tracking", bytes.NewBuffer(startBytes))
	stopReq = withUser(stopReq, "admin")
	stopReq.Header.Set("Content-Type", "application/json")
	app.handleStopTimeTracking(httptest.NewRecorder(), stopReq)

	// A GET with the path in the QUERY STRING. This route used to decode a JSON body, which no
	// conforming client sends on a GET, so it answered 400 "EOF" to everybody.
	req := withUser(httptest.NewRequest("GET", "/time?path=test-node", nil), "admin")
	rr := httptest.NewRecorder()
	app.handleGetTimeTracking(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /time: got %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var summary []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&summary)

	if len(summary) == 0 {
		logger.Failure("Expected non-empty summary")
		t.Error("Expected non-empty summary")
	} else {
		logger.Success("Time tracking summary is correct")
		logger.Info("Summary: %v", summary)
	}
}

func TestHandleGetEventEntries(t *testing.T) {

	logger.Enter("HandleGetEventEntries")
	defer logger.Exit("HandleGetEventEntries")

	app := setupTestForest(t)

	// First create an event
	startBody := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
		"metadata": map[string]interface{}{
			"test": "data",
		},
	}
	startBytes, _ := json.Marshal(startBody)
	startReq := httptest.NewRequest("POST", "/start_event", bytes.NewBuffer(startBytes))
	startReq = withUser(startReq, "admin")
	startReq.Header.Set("Content-Type", "application/json")

	startRR := httptest.NewRecorder()
	app.handleStartEvent(startRR, startReq)

	if startRR.Code != http.StatusOK {
		logger.Failure("Failed to start event: %v", startRR.Body.String())
		t.Fatalf("Failed to start event: %v", startRR.Body.String())
	}

	// Now get the entries
	body := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/get_event_entries", bytes.NewBuffer(bodyBytes))
	req = withUser(req, "admin")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	app.handleGetEventEntries(rr, req)

	if status := rr.Code; status != http.StatusOK {
		logger.Failure("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var entries []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&entries); err != nil {
		logger.Failure("Failed to decode response: %v", err)
		t.Errorf("Failed to decode response: %v", err)
	} else {
		logger.Success("Successfully retrieved event entries")
		logger.Info("Entries: %v", entries)
	}
}

func TestHandleEndEvent(t *testing.T) {

	logger.Enter("HandleEndEvent")
	defer logger.Exit("HandleEndEvent")

	app := setupTestForest(t)

	// Start event
	startBody := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
		"metadata": map[string]interface{}{"test": "data"},
	}
	startBytes, _ := json.Marshal(startBody)
	startReq := httptest.NewRequest("POST", "/start_event", bytes.NewBuffer(startBytes))
	startReq = withUser(startReq, "admin")
	startReq.Header.Set("Content-Type", "application/json")
	app.handleStartEvent(httptest.NewRecorder(), startReq)

	// End event
	endBody := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
	}
	endBytes, _ := json.Marshal(endBody)
	endReq := httptest.NewRequest("POST", "/end_event", bytes.NewBuffer(endBytes))
	endReq = withUser(endReq, "admin")
	endReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	app.handleEndEvent(rr, endReq)

	if status := rr.Code; status != http.StatusOK {
		logger.Failure("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	} else {
		logger.Success("Event ended successfully")
		logger.Info("Response: %s", rr.Body.String())
	}
}

func TestHandleAppendToEvent(t *testing.T) {
	logger.Enter("HandleAppendToEvent")
	defer logger.Exit("HandleAppendToEvent")

	app := setupTestForest(t)

	// First start an event
	startBody := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
		"metadata": map[string]interface{}{
			"test": "data",
		},
	}
	startBytes, _ := json.Marshal(startBody)
	startReq := httptest.NewRequest("POST", "/start_event", bytes.NewBuffer(startBytes))
	startReq = withUser(startReq, "admin")
	startReq.Header.Set("Content-Type", "application/json")

	startRR := httptest.NewRecorder()
	app.handleStartEvent(startRR, startReq)

	if startRR.Code != http.StatusOK {
		logger.Failure("Failed to start event: %v", startRR.Body.String())
		t.Fatalf("Failed to start event: %v", startRR.Body.String())
	}

	// Now append to the event
	body := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
		"content":  "test content",
		"metadata": map[string]interface{}{
			"test": "data",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/append_event", bytes.NewBuffer(bodyBytes))
	req = withUser(req, "admin")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	app.handleAppendToEvent(rr, req)

	if status := rr.Code; status != http.StatusOK {
		logger.Failure("Handler returned wrong status code: got %v want %v, body: %v",
			status, http.StatusOK, rr.Body.String())
		t.Errorf("Handler returned wrong status code: got %v want %v, body: %v",
			status, http.StatusOK, rr.Body.String())
	} else {
		logger.Success("Successfully appended to event")
	}

	// Verify the entry was added
	getBody := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
	}
	getBytes, _ := json.Marshal(getBody)
	getReq := httptest.NewRequest("POST", "/get_event_entries", bytes.NewBuffer(getBytes))
	getReq = withUser(getReq, "admin")
	getReq.Header.Set("Content-Type", "application/json")

	getRR := httptest.NewRecorder()
	app.handleGetEventEntries(getRR, getReq)

	var entries []interface{}
	if err := json.NewDecoder(getRR.Body).Decode(&entries); err != nil {
		logger.Failure("Failed to decode entries: %v", err)
		t.Errorf("Failed to decode entries: %v", err)
	}

	if len(entries) != 1 {
		logger.Failure("Expected 1 entry, got %d", len(entries))
		t.Errorf("Expected 1 entry, got %d", len(entries))
	} else {
		logger.Success("Verified correct number of entries")
		logger.Info("Entries: %v", entries)
	}
}

func TestHandleStartEvent(t *testing.T) {
	logger.Enter("HandleStartEvent")
	defer logger.Exit("HandleStartEvent")

	app := setupTestForest(t)

	body := map[string]interface{}{
		"path":     "test-node",
		"event_id": "test-event",
		"metadata": map[string]interface{}{
			"test": "data",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/start_event", bytes.NewBuffer(bodyBytes))
	req = withUser(req, "admin")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	app.handleStartEvent(rr, req)

	if status := rr.Code; status != http.StatusOK {
		logger.Failure("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	} else {
		logger.Success("Event started successfully")
		logger.Info("Response: %s", rr.Body.String())
	}
}

func TestHandleAppendToEventWithCategories(t *testing.T) {
	logger.Enter("HandleAppendToEventWithCategories")
	defer logger.Exit("HandleAppendToEventWithCategories")

	app := setupTestForest(t)
	nodePath := "health/exercise/workout"
	logger.Info("Looking for node at path: %s", nodePath)

	// Create branch structure: health::exercise::workout
	healthNode := core.NewNode(core.BranchNode, "health")
	healthNode.ID = "health"
	exerciseNode := core.NewNode(core.BranchNode, "exercise")
	exerciseNode.ID = "exercise"
	workoutNode := core.NewNode(core.LeafNode, "workout")
	workoutNode.ID = "workout"

	// Add admin user to all nodes
	adminUser := core.User{
		ID:          "admin",
		Username:    "admin",
		Permissions: []core.Permission{core.AdminPermission},
	}
	healthNode.Users = []core.User{adminUser}
	exerciseNode.Users = []core.User{adminUser}
	workoutNode.Users = []core.User{adminUser}

	// Set up node hierarchy
	app.forest.AddChild(healthNode)
	healthNode.AddChild(exerciseNode)
	exerciseNode.AddChild(workoutNode)

	logger.Info("Testing with node path: %s", nodePath)

	// Start event
	startBody := map[string]interface{}{
		"path":     nodePath,
		"event_id": "morning_run",
		"metadata": map[string]interface{}{
			"type":           "event",
			"frequency":      "weekly",
			"custom_pattern": "MWF@0700",
			"category":       "health::exercise::workout",
		},
	}
	startBytes, _ := json.Marshal(startBody)
	startReq := httptest.NewRequest("POST", "/start_event", bytes.NewBuffer(startBytes))
	startReq = withUser(startReq, "admin")
	startReq.Header.Set("Content-Type", "application/json")
	app.handleStartEvent(httptest.NewRecorder(), startReq)

	// Append to event
	appendBody := map[string]interface{}{
		"path":     nodePath,
		"event_id": "morning_run",
		"content":  "Completed morning run",
		"metadata": map[string]interface{}{
			"type":     "event",
			"status":   "completed",
			"category": "health::exercise::workout",
		},
	}
	appendBytes, _ := json.Marshal(appendBody)
	req := httptest.NewRequest("POST", "/append_event", bytes.NewBuffer(appendBytes))
	req = withUser(req, "admin")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	app.handleAppendToEvent(rr, req)

	if status := rr.Code; status != http.StatusOK {
		logger.Failure("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	} else {
		logger.Success("Event appended successfully")
		logger.Info("Response: %s", rr.Body.String())
	}
}

func TestHandlePlanEvent(t *testing.T) {
	logger.Enter("HandlePlanEvent")
	defer logger.Exit("HandlePlanEvent")

	app := setupTestForest(t)

	logger.Info("Setting up test environment")

	// Create branch structure: study::languages::spanish
	studyNode := core.NewNode(core.BranchNode, "study")
	languagesNode := core.NewNode(core.BranchNode, "languages")
	spanishNode := core.NewNode(core.LeafNode, "spanish")

	// The handler checks write permission now, so the node has to know the caller.
	adminUser := core.User{
		ID:          "admin",
		Username:    "admin",
		Permissions: []core.Permission{core.AdminPermission},
	}
	spanishNode.Users = []core.User{adminUser}

	app.forest.Children["study"] = studyNode
	studyNode.Children["languages"] = languagesNode
	languagesNode.Children["spanish"] = spanishNode

	// Plan a study routine
	start := time.Now().Add(time.Hour)
	end := time.Now().Add(2 * time.Hour)
	body := map[string]interface{}{
		"path":       "study/languages/spanish",
		"event_id":   "vocabulary_practice",
		"start_time": start.Format(time.RFC3339),
		"end_time":   end.Format(time.RFC3339),
		"metadata": map[string]interface{}{
			"frequency":      "daily",
			"custom_pattern": "2000",
			"category":       "study::languages::spanish",
			"message":        "Plan vocabulary practice",
			"status":         "pending",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/plan_event", bytes.NewBuffer(bodyBytes))
	req = withUser(req, "admin")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(app.handlePlanEvent)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		logger.Failure("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	} else {
		logger.Success("Event planned successfully")
		logger.Info("Response: %s", rr.Body.String())
	}
}

func TestMultipleParentNodes(t *testing.T) {
	logger.Enter("MultipleParentNodes")
	defer logger.Exit("MultipleParentNodes")

	app := setupTestForest(t)
	root := app.forest

	// Create branch structure for multiple paths to savings
	lifeNode := core.NewNode(core.BranchNode, "life")
	workNode := core.NewNode(core.BranchNode, "work")
	paydayNode := core.NewNode(core.BranchNode, "payday")
	financeNode := core.NewNode(core.BranchNode, "finance")
	wealthNode := core.NewNode(core.BranchNode, "wealth")
	houseNode := core.NewNode(core.BranchNode, "house")
	fundNode := core.NewNode(core.BranchNode, "fund")
	savingsNode := core.NewNode(core.LeafNode, "savings")

	// StartEvent refuses a user the node does not know, and the assertion below is about where the
	// event is reachable from, not about who may write it.
	savingsNode.Users = []core.User{{
		ID:          "user1",
		Username:    "user1",
		Permissions: []core.Permission{core.WritePermission},
	}}

	// Setup path: life::work::payday::savings
	root.Children["life"] = lifeNode
	lifeNode.Children["work"] = workNode
	workNode.Children["payday"] = paydayNode
	paydayNode.Children["savings"] = savingsNode

	// Setup path: life::finance::savings
	lifeNode.Children["finance"] = financeNode
	financeNode.Children["savings"] = savingsNode

	// Setup path: life::wealth::house::fund::savings
	lifeNode.Children["wealth"] = wealthNode
	wealthNode.Children["house"] = houseNode
	houseNode.Children["fund"] = fundNode
	fundNode.Children["savings"] = savingsNode

	// Verify the node structure
	if len(root.Children["life"].Children) != 3 {
		logger.Failure("Expected life node to have 3 children, got %d", len(root.Children["life"].Children))
		t.Errorf("Expected life node to have 3 children, got %d", len(root.Children["life"].Children))
	} else {
		logger.Success("Life node has expected number of children")
	}

	// Verify savings node is accessible from all paths
	paths := [][]string{
		{"life", "work", "payday", "savings"},
		{"life", "finance", "savings"},
		{"life", "wealth", "house", "fund", "savings"},
	}

	logger.Enter("Path Verification")
	for _, path := range paths {
		currentNode := root
		for _, nodeName := range path {
			if next, exists := currentNode.Children[nodeName]; exists {
				currentNode = next
				logger.Success("Path %v is valid at node %s", path, nodeName)
			} else {
				logger.Failure("Path %v is broken at node %s", path, nodeName)
				t.Errorf("Path %v is broken at node %s", path, nodeName)
			}
		}
	}
	logger.Exit("Path Verification")

	logger.Enter("Event Propagation")
	// Test event propagation through all parents
	if err := savingsNode.StartEvent("deposit", "user1", nil, nil, map[string]interface{}{"amount": 1000}); err != nil {
		t.Fatalf("Failed to start the event: %v", err)
	}

	// Verify event is accessible from all paths
	for _, path := range paths {
		currentNode := root
		for _, nodeName := range path {
			currentNode = currentNode.Children[nodeName]
		}
		if _, err := currentNode.GetEventSummary("deposit"); err != nil {
			logger.Failure("Event not accessible through path %v: %v", path, err)
			t.Errorf("Event not accessible through path %v: %v", path, err)
		} else {
			logger.Success("Event accessible through path %v", path)
		}
	}
	logger.Exit("Event Propagation")
}

func TestUserCreationAndAuthentication(t *testing.T) {
	logger.Enter("UserCreationAndAuthentication")
	defer logger.Exit("UserCreationAndAuthentication")

	app := setupTestForest(t)

	logger.Enter("User Creation")
	// Test user creation
	createBody := map[string]interface{}{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "securepass123",
	}
	createBytes, _ := json.Marshal(createBody)

	createReq := httptest.NewRequest("POST", "/create_user", bytes.NewBuffer(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	app.handleCreateUser(createRR, createReq)

	if status := createRR.Code; status != http.StatusOK {
		logger.Failure("User creation failed with status code: got %v want %v", status, http.StatusOK)
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	} else {
		logger.Success("User created successfully")
	}
	logger.Exit("User Creation")

	logger.Enter("Login Tests")
	// Test successful login
	loginBody := map[string]interface{}{
		"username": "testuser",
		"password": "securepass123",
	}
	loginBytes, _ := json.Marshal(loginBody)

	loginReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(loginBytes))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	app.handleLogin(loginRR, loginReq)

	if status := loginRR.Code; status != http.StatusOK {
		logger.Failure("Login failed with status code: got %v want %v", status, http.StatusOK)
		t.Errorf("login handler returned wrong status code: got %v want %v", status, http.StatusOK)
	} else {
		logger.Success("Login successful")
	}

	var loginResponse map[string]string
	if err := json.NewDecoder(loginRR.Body).Decode(&loginResponse); err != nil {
		logger.Failure("Failed to decode login response: %v", err)
		t.Errorf("Failed to decode login response: %v", err)
	} else {
		logger.Success("Login response decoded successfully")
	}

	// The pair the handler actually answers with. The old assertion looked for a "token" key no
	// version of this handler has ever written.
	if loginResponse["session_token"] == "" {
		logger.Failure("Login response missing session token")
		t.Error("Login response missing session token")
	} else if loginResponse["refresh_token"] == "" {
		logger.Failure("Login response missing refresh token")
		t.Error("Login response missing refresh token")
	} else {
		logger.Success("JWT token pair received")
	}

	logger.Enter("Failed Login Test")
	// Test failed login with wrong password
	wrongLoginBody := map[string]interface{}{
		"username": "testuser",
		"password": "wrongpass",
	}
	wrongLoginBytes, _ := json.Marshal(wrongLoginBody)

	wrongLoginReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(wrongLoginBytes))
	wrongLoginReq.Header.Set("Content-Type", "application/json")
	wrongLoginRR := httptest.NewRecorder()
	app.handleLogin(wrongLoginRR, wrongLoginReq)

	if status := wrongLoginRR.Code; status != http.StatusUnauthorized {
		logger.Failure("Wrong password login returned unexpected status: got %v want %v",
			status, http.StatusUnauthorized)
		t.Errorf("login handler with wrong password returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	} else {
		logger.Success("Wrong password correctly rejected")
	}
	logger.Exit("Failed Login Test")
	logger.Exit("Login Tests")
}

func TestErrorHandling(t *testing.T) {
	t.Run("Invalid Node Operations", func(t *testing.T) {
		// Test node operations with invalid paths
		// Test deleting non-existent nodes
		// Test circular references
	})

	t.Run("Concurrent Operations", func(t *testing.T) {
		// Test concurrent event creation
		// Test concurrent user assignments
		// Test race conditions
	})

	t.Run("Permission Boundaries", func(t *testing.T) {
		// Test permission inheritance
		// Test permission conflicts
		// Test permission revocation
	})
}

func TestDataValidation(t *testing.T) {
	t.Run("Input Validation", func(t *testing.T) {
		// Test invalid event IDs
		// Test malformed timestamps
		// Test invalid metadata
	})

	t.Run("State Validation", func(t *testing.T) {
		// Test corrupted state files
		// Test incomplete state recovery
		// Test version migrations
	})
}

func TestAPIEndpoints(t *testing.T) {
	t.Run("Authentication", func(t *testing.T) {
		// Test invalid tokens
		// Test expired tokens
		// Test token refresh
	})

	t.Run("Rate Limiting", func(t *testing.T) {
		// Test request throttling
		// Test concurrent requests
	})
}

func TestMetrics(t *testing.T) {
	// Test performance metrics
	// Test resource usage
	// Test operation timing
}
