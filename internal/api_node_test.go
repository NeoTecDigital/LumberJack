package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// TestNodeCreationEndpoint tests POST /nodes/create
func TestNodeCreationEndpoint(t *testing.T) {
	logger := types.NewLogger()
	logger.Enter("TestNodeCreationEndpoint")
	defer logger.Exit("TestNodeCreationEndpoint")

	// Setup test server
	testDbPath, _ := os.MkdirTemp("", "node-test-*")
	defer os.RemoveAll(testDbPath)

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
			LogPath:       testDbPath,
			DatabasePath:  testDbPath,
		},
	}, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Generate admin token for auth
	adminUser := &server.forest.Users[0]
	tokenPair, err := server.generateTokenPair(adminUser)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create parent structure first with admin permissions
	pngNode := core.NewNode(core.BranchNode, "png")
	handlesNode := core.NewNode(core.BranchNode, "handles")
	templatesNode := core.NewNode(core.BranchNode, "templates")

	// Assign admin user to all parent nodes
	pngNode.Users = []core.User{*adminUser}
	handlesNode.Users = []core.User{*adminUser}
	templatesNode.Users = []core.User{*adminUser}

	server.forest.AddChild(pngNode)
	pngNode.AddChild(handlesNode)
	pngNode.AddChild(templatesNode)

	t.Run("Create Handle Node with Metadata", func(t *testing.T) {
		logger.Enter("Create Handle Node")
		defer logger.Exit("Create Handle Node")

		requestBody := map[string]interface{}{
			"path": "png/handles/InvoiceHandle",
			"name": "Invoice Handle",
			"type": 0, // LeafNode
			"metadata": map[string]interface{}{
				"query":       "SELECT * FROM invoices WHERE id = $1",
				"params":      []string{"invoice_id"},
				"description": "Retrieves invoice by ID",
			},
		}
		bodyBytes, _ := json.Marshal(requestBody)

		req := httptest.NewRequest("POST", "/nodes/create", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)
		req.Header.Set("Content-Type", "application/json")

		// Add user_id to context (normally done by authMiddleware)
		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleCreateNode(rr, req)

		if status := rr.Code; status != http.StatusCreated {
			logger.Failure("Expected status 201, got %d: %s", status, rr.Body.String())
			t.Errorf("Expected status 201, got %d: %s", status, rr.Body.String())
		} else {
			logger.Success("Node created successfully")
		}

		var response map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&response)
		logger.Info("Response: %v", response)

		// Verify response contains expected fields
		if response["path"] != "png/handles/InvoiceHandle" {
			t.Errorf("Expected path png/handles/InvoiceHandle, got %v", response["path"])
		}
	})

	t.Run("Create Template Node with Handlebars Content", func(t *testing.T) {
		logger.Enter("Create Template Node")
		defer logger.Exit("Create Template Node")

		requestBody := map[string]interface{}{
			"path": "png/templates/InvoiceTemplate",
			"name": "Invoice Template",
			"type": 0, // LeafNode
			"metadata": map[string]interface{}{
				"template": "<html><body>Invoice #{{invoice_number}}</body></html>",
				"engine":   "handlebars",
				"version":  "1.0",
			},
		}
		bodyBytes, _ := json.Marshal(requestBody)

		req := httptest.NewRequest("POST", "/nodes/create", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleCreateNode(rr, req)

		if status := rr.Code; status != http.StatusCreated {
			logger.Failure("Expected status 201, got %d: %s", status, rr.Body.String())
			t.Errorf("Expected status 201, got %d: %s", status, rr.Body.String())
		} else {
			logger.Success("Template node created successfully")
		}
	})

	t.Run("Create Node Without Permission", func(t *testing.T) {
		logger.Enter("Create Node Without Permission")
		defer logger.Exit("Create Node Without Permission")

		// Create a user without write permission
		limitedUser := core.User{
			ID:       core.GenerateID(),
			Username: "limited",
		}
		limitedUser.SetPassword("limited")
		server.forest.AssignUser(limitedUser, core.ReadPermission)

		limitedToken, _ := server.generateTokenPair(&limitedUser)

		requestBody := map[string]interface{}{
			"path": "png/unauthorized",
			"name": "Unauthorized Node",
			"type": 0,
		}
		bodyBytes, _ := json.Marshal(requestBody)

		req := httptest.NewRequest("POST", "/nodes/create", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+limitedToken.SessionToken)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), "user_id", limitedUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleCreateNode(rr, req)

		if status := rr.Code; status != http.StatusForbidden {
			logger.Failure("Expected status 403, got %d", status)
			t.Errorf("Expected status 403 (forbidden), got %d", status)
		} else {
			logger.Success("Correctly rejected unauthorized creation")
		}
	})

	t.Run("Create Node with Invalid JSON", func(t *testing.T) {
		logger.Enter("Invalid JSON Test")
		defer logger.Exit("Invalid JSON Test")

		req := httptest.NewRequest("POST", "/nodes/create", bytes.NewBuffer([]byte("{invalid json")))
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleCreateNode(rr, req)

		if status := rr.Code; status != http.StatusBadRequest {
			logger.Failure("Expected status 400, got %d", status)
			t.Errorf("Expected status 400 (bad request), got %d", status)
		} else {
			logger.Success("Correctly rejected invalid JSON")
		}
	})
}

// TestNodeRetrievalEndpoint tests GET /nodes/get
func TestNodeRetrievalEndpoint(t *testing.T) {
	logger := types.NewLogger()
	logger.Enter("TestNodeRetrievalEndpoint")
	defer logger.Exit("TestNodeRetrievalEndpoint")

	// Setup test server
	testDbPath, _ := os.MkdirTemp("", "node-test-*")
	defer os.RemoveAll(testDbPath)

	server, err := NewServer(types.ServerConfig{
		Organization: "test_org",
		Process: types.ProcessInfo{
			Name:         "test_state",
			ServerPort:   "8080",
			LogPath:      testDbPath,
			DatabasePath: testDbPath,
		},
	}, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create test node first
	testNode := core.NewNode(core.LeafNode, "TestHandle")
	testNode.AddActivity("node_created", map[string]interface{}{
		"query":  "SELECT * FROM test",
		"params": []string{"id"},
	}, "admin")

	pngNode := core.NewNode(core.BranchNode, "png")
	handlesNode := core.NewNode(core.BranchNode, "handles")
	server.forest.AddChild(pngNode)
	pngNode.AddChild(handlesNode)
	handlesNode.AddChild(testNode)

	adminUser := &server.forest.Users[0]
	tokenPair, _ := server.generateTokenPair(adminUser)

	t.Run("Retrieve Existing Node", func(t *testing.T) {
		logger.Enter("Retrieve Existing Node")
		defer logger.Exit("Retrieve Existing Node")

		req := httptest.NewRequest("GET", "/nodes/get?path=png/handles/TestHandle", nil)
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)

		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleGetNodeByPath(rr, req)

		if status := rr.Code; status != http.StatusOK {
			logger.Failure("Expected status 200, got %d: %s", status, rr.Body.String())
			t.Errorf("Expected status 200, got %d: %s", status, rr.Body.String())
		} else {
			logger.Success("Node retrieved successfully")
		}

		var node core.Node
		json.NewDecoder(rr.Body).Decode(&node)
		logger.Info("Retrieved node: %s", node.Name)

		if node.Name != "TestHandle" {
			t.Errorf("Expected node name 'TestHandle', got '%s'", node.Name)
		}
	})

	t.Run("Retrieve Non-existent Node", func(t *testing.T) {
		logger.Enter("Retrieve Non-existent Node")
		defer logger.Exit("Retrieve Non-existent Node")

		req := httptest.NewRequest("GET", "/nodes/get?path=png/handles/NonExistent", nil)
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)

		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleGetNodeByPath(rr, req)

		if status := rr.Code; status != http.StatusNotFound {
			logger.Failure("Expected status 404, got %d", status)
			t.Errorf("Expected status 404 (not found), got %d", status)
		} else {
			logger.Success("Correctly returned 404 for non-existent node")
		}
	})

	t.Run("Retrieve Without Path Parameter", func(t *testing.T) {
		logger.Enter("Missing Path Parameter")
		defer logger.Exit("Missing Path Parameter")

		req := httptest.NewRequest("GET", "/nodes/get", nil)
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)

		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleGetNodeByPath(rr, req)

		if status := rr.Code; status != http.StatusBadRequest {
			logger.Failure("Expected status 400, got %d", status)
			t.Errorf("Expected status 400 (bad request), got %d", status)
		} else {
			logger.Success("Correctly rejected missing path parameter")
		}
	})
}

// TestNodeMetadataUpdateEndpoint tests PUT /nodes/metadata
func TestNodeMetadataUpdateEndpoint(t *testing.T) {
	logger := types.NewLogger()
	logger.Enter("TestNodeMetadataUpdateEndpoint")
	defer logger.Exit("TestNodeMetadataUpdateEndpoint")

	// Setup test server
	testDbPath, _ := os.MkdirTemp("", "node-test-*")
	defer os.RemoveAll(testDbPath)

	server, err := NewServer(types.ServerConfig{
		Organization: "test_org",
		Process: types.ProcessInfo{
			Name:         "test_state",
			ServerPort:   "8080",
			LogPath:      testDbPath,
			DatabasePath: testDbPath,
		},
	}, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create test node
	testNode := core.NewNode(core.LeafNode, "TestHandle")
	testNode.AddActivity("node_created", map[string]interface{}{
		"query": "SELECT * FROM test",
	}, "admin")

	pngNode := core.NewNode(core.BranchNode, "png")
	handlesNode := core.NewNode(core.BranchNode, "handles")
	server.forest.AddChild(pngNode)
	pngNode.AddChild(handlesNode)
	handlesNode.AddChild(testNode)

	adminUser := &server.forest.Users[0]
	adminUser.Permissions = []core.Permission{core.AdminPermission}
	testNode.Users = []core.User{*adminUser}

	tokenPair, _ := server.generateTokenPair(adminUser)

	t.Run("Update Node Metadata", func(t *testing.T) {
		logger.Enter("Update Node Metadata")
		defer logger.Exit("Update Node Metadata")

		requestBody := map[string]interface{}{
			"path": "png/handles/TestHandle",
			"metadata": map[string]interface{}{
				"query":       "SELECT * FROM invoices WHERE id = $1 AND status = $2",
				"params":      []string{"invoice_id", "status"},
				"description": "Updated query with status filter",
				"version":     "2.0",
			},
		}
		bodyBytes, _ := json.Marshal(requestBody)

		req := httptest.NewRequest("PUT", "/nodes/metadata", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleUpdateNodeMetadata(rr, req)

		if status := rr.Code; status != http.StatusOK {
			logger.Failure("Expected status 200, got %d: %s", status, rr.Body.String())
			t.Errorf("Expected status 200, got %d: %s", status, rr.Body.String())
		} else {
			logger.Success("Metadata updated successfully")
		}

		// Verify metadata was added as activity
		node, _ := server.getNodeFromPath("png/handles/TestHandle")
		if len(node.Entries) < 2 {
			t.Errorf("Expected at least 2 entries, got %d", len(node.Entries))
		}
		logger.Info("Node now has %d entries", len(node.Entries))
	})

	t.Run("Update Without Write Permission", func(t *testing.T) {
		logger.Enter("Update Without Permission")
		defer logger.Exit("Update Without Permission")

		// Create limited user
		limitedUser := core.User{
			ID:       core.GenerateID(),
			Username: "limited",
		}
		limitedUser.SetPassword("limited")
		server.forest.AssignUser(limitedUser, core.ReadPermission)

		limitedToken, _ := server.generateTokenPair(&limitedUser)

		requestBody := map[string]interface{}{
			"path": "png/handles/TestHandle",
			"metadata": map[string]interface{}{
				"unauthorized": "update",
			},
		}
		bodyBytes, _ := json.Marshal(requestBody)

		req := httptest.NewRequest("PUT", "/nodes/metadata", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+limitedToken.SessionToken)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), "user_id", limitedUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleUpdateNodeMetadata(rr, req)

		if status := rr.Code; status != http.StatusForbidden {
			logger.Failure("Expected status 403, got %d", status)
			t.Errorf("Expected status 403 (forbidden), got %d", status)
		} else {
			logger.Success("Correctly rejected unauthorized update")
		}
	})
}

// TestNodePersistence tests that nodes survive server restart
func TestNodePersistence(t *testing.T) {
	logger := types.NewLogger()
	logger.Enter("TestNodePersistence")
	defer logger.Exit("TestNodePersistence")

	// Setup test server
	testDbPath, _ := os.MkdirTemp("", "node-persist-test-*")
	defer os.RemoveAll(testDbPath)

	// First server instance
	server1, err := NewServer(types.ServerConfig{
		Organization: "test_org",
		Process: types.ProcessInfo{
			Name:         "test_state",
			ServerPort:   "8080",
			LogPath:      testDbPath,
			DatabasePath: testDbPath,
		},
	}, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	adminUser := &server1.forest.Users[0]
	tokenPair, _ := server1.generateTokenPair(adminUser)

	// Create parent structure with admin permissions
	pngNode := core.NewNode(core.BranchNode, "png")
	handlesNode := core.NewNode(core.BranchNode, "handles")
	pngNode.Users = []core.User{*adminUser}
	handlesNode.Users = []core.User{*adminUser}
	server1.forest.AddChild(pngNode)
	pngNode.AddChild(handlesNode)

	t.Run("Create and Persist Node", func(t *testing.T) {
		logger.Enter("Create and Persist Node")
		defer logger.Exit("Create and Persist Node")

		// Create node via API
		requestBody := map[string]interface{}{
			"path": "png/handles/PersistTest",
			"name": "Persist Test Handle",
			"type": 0,
			"metadata": map[string]interface{}{
				"query":       "SELECT * FROM persist_test",
				"should_exist": true,
			},
		}
		bodyBytes, _ := json.Marshal(requestBody)

		req := httptest.NewRequest("POST", "/nodes/create", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server1.handleCreateNode(rr, req)

		if status := rr.Code; status != http.StatusCreated {
			t.Fatalf("Failed to create node: %d - %s", status, rr.Body.String())
		}
		logger.Success("Node created in first server instance")
	})

	t.Run("Load from Disk and Verify", func(t *testing.T) {
		logger.Enter("Load from Disk")
		defer logger.Exit("Load from Disk")

		// Create second server instance (simulates restart)
		server2, err := LoadServer(types.ServerConfig{
			Organization: "test_org",
			Process: types.ProcessInfo{
				Name:         "test_state",
				ServerPort:   "8080",
				LogPath:      testDbPath,
				DatabasePath: testDbPath,
			},
		})
		if err != nil {
			t.Fatalf("Failed to load server: %v", err)
		}

		logger.Success("Second server instance loaded from disk")

		// Verify node exists
		node, err := server2.getNodeFromPath("png/handles/PersistTest")
		if err != nil {
			t.Errorf("Node not found after restart: %v", err)
		} else {
			logger.Success("Node successfully retrieved after restart")
			logger.Info("Node name: %s", node.Name)

			if node.Name != "Persist Test Handle" {
				t.Errorf("Expected name 'Persist Test Handle', got '%s'", node.Name)
			}

			// Verify metadata persisted
			if len(node.Entries) == 0 {
				t.Error("Node entries not persisted")
			} else {
				logger.Success("Node metadata persisted correctly")
			}
		}
	})
}

// TestIntegrationDocumentWorkflow tests the complete document generation workflow
func TestIntegrationDocumentWorkflow(t *testing.T) {
	logger := types.NewLogger()
	logger.Enter("TestIntegrationDocumentWorkflow")
	defer logger.Exit("TestIntegrationDocumentWorkflow")

	testDbPath, _ := os.MkdirTemp("", "workflow-test-*")
	defer os.RemoveAll(testDbPath)

	server, err := NewServer(types.ServerConfig{
		Organization: "test_org",
		Process: types.ProcessInfo{
			Name:         "test_state",
			ServerPort:   "8080",
			LogPath:      testDbPath,
			DatabasePath: testDbPath,
		},
	}, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	adminUser := &server.forest.Users[0]
	tokenPair, _ := server.generateTokenPair(adminUser)

	// Create parent structure with admin permissions
	pngNode := core.NewNode(core.BranchNode, "png")
	handlesNode := core.NewNode(core.BranchNode, "handles")
	templatesNode := core.NewNode(core.BranchNode, "templates")
	pngNode.Users = []core.User{*adminUser}
	handlesNode.Users = []core.User{*adminUser}
	templatesNode.Users = []core.User{*adminUser}
	server.forest.AddChild(pngNode)
	pngNode.AddChild(handlesNode)
	pngNode.AddChild(templatesNode)

	t.Run("Complete Workflow: Template + Handle", func(t *testing.T) {
		logger.Enter("Complete Workflow")
		defer logger.Exit("Complete Workflow")

		// Step 1: Create handle (PostgreSQL query definition)
		handleRequest := map[string]interface{}{
			"path": "png/handles/InvoiceData",
			"name": "Invoice Data Handle",
			"type": 0,
			"metadata": map[string]interface{}{
				"query": `
					SELECT i.id, i.invoice_number, i.total, c.name as customer_name
					FROM invoices i
					JOIN customers c ON i.customer_id = c.id
					WHERE i.id = $1
				`,
				"params": []string{"invoice_id"},
				"type":   "postgres_query",
			},
		}
		handleBytes, _ := json.Marshal(handleRequest)

		req := httptest.NewRequest("POST", "/nodes/create", bytes.NewBuffer(handleBytes))
		req.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), "user_id", adminUser.ID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		server.handleCreateNode(rr, req)

		if status := rr.Code; status != http.StatusCreated {
			t.Fatalf("Failed to create handle: %d - %s", status, rr.Body.String())
		}
		logger.Success("Handle created successfully")

		// Step 2: Create template (Handlebars template)
		templateRequest := map[string]interface{}{
			"path": "png/templates/InvoiceTemplate",
			"name": "Invoice Template",
			"type": 0,
			"metadata": map[string]interface{}{
				"template": `
<!DOCTYPE html>
<html>
<head><title>Invoice {{invoice_number}}</title></head>
<body>
	<h1>Invoice #{{invoice_number}}</h1>
	<p>Customer: {{customer_name}}</p>
	<p>Total: ${{total}}</p>
</body>
</html>
				`,
				"engine":  "handlebars",
				"version": "1.0",
				"type":    "html_template",
			},
		}
		templateBytes, _ := json.Marshal(templateRequest)

		req2 := httptest.NewRequest("POST", "/nodes/create", bytes.NewBuffer(templateBytes))
		req2.Header.Set("Authorization", "Bearer "+tokenPair.SessionToken)
		req2.Header.Set("Content-Type", "application/json")
		ctx2 := context.WithValue(req2.Context(), "user_id", adminUser.ID)
		req2 = req2.WithContext(ctx2)

		rr2 := httptest.NewRecorder()
		server.handleCreateNode(rr2, req2)

		if status := rr2.Code; status != http.StatusCreated {
			t.Fatalf("Failed to create template: %d - %s", status, rr2.Body.String())
		}
		logger.Success("Template created successfully")

		// Step 3: Verify both nodes can be retrieved
		handleNode, err := server.getNodeFromPath("png/handles/InvoiceData")
		if err != nil {
			t.Errorf("Failed to retrieve handle: %v", err)
		} else {
			logger.Success("Handle retrieved: %s", handleNode.Name)
		}

		templateNode, err := server.getNodeFromPath("png/templates/InvoiceTemplate")
		if err != nil {
			t.Errorf("Failed to retrieve template: %v", err)
		} else {
			logger.Success("Template retrieved: %s", templateNode.Name)
		}

		logger.Info("Document workflow integration test completed successfully")
	})
}
