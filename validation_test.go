package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal"
	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// TestNodePersistence - Test A: Node Persistence (Previously Failed)
func TestNodePersistence(t *testing.T) {
	// Setup
	testDir := filepath.Join("/tmp", fmt.Sprintf("lumberjack-test-%d", time.Now().UnixNano()))
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	os.Setenv("JWT_SECRET", "test-secret-key-validation")

	config := types.ServerConfig{
		Process: types.ProcessInfo{
			ID:           "test-persistence",
			Name:         "test-persistence",
			ServerPort:   "18081",
			DatabasePath: testDir,
			LogPath:      testDir,
		},
		Organization: "Test Org",
		Phone:        "+1234567890",
	}

	adminUser := core.User{
		Username:     "admin@test.com",
		Email:        "admin@test.com",
		Password:     "admin123",
		Organization: "Test Org",
	}

	// Create server
	server, err := internal.NewServer(config, adminUser)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Shutdown(nil)

	time.Sleep(1 * time.Second)

	// 1. Login to get token
	loginResp, err := http.Post("http://localhost:18081/login",
		"application/json",
		bytes.NewBufferString(`{"username":"admin@test.com","password":"admin123"}`))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	defer loginResp.Body.Close()

	var loginData map[string]string
	json.NewDecoder(loginResp.Body).Decode(&loginData)
	token := loginData["session_token"]
	if token == "" {
		t.Fatal("No session token received")
	}

	t.Logf("✓ Login successful, got token")

	// 2. Create parent nodes
	createPngNode := map[string]interface{}{
		"path": "/png",
		"name": "png",
		"type": 1,
	}
	createPngJSON, _ := json.Marshal(createPngNode)
	req, _ := http.NewRequest("POST", "http://localhost:18081/nodes/create", bytes.NewBuffer(createPngJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req)

	createHandlesNode := map[string]interface{}{
		"path": "/png/handles",
		"name": "handles",
		"type": 1,
	}
	createHandlesJSON, _ := json.Marshal(createHandlesNode)
	req, _ = http.NewRequest("POST", "http://localhost:18081/nodes/create", bytes.NewBuffer(createHandlesJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req)

	createEmployeeNode := map[string]interface{}{
		"path": "/png/handles/Employee",
		"name": "Employee",
		"type": 1,
	}
	createEmployeeJSON, _ := json.Marshal(createEmployeeNode)
	req, _ = http.NewRequest("POST", "http://localhost:18081/nodes/create", bytes.NewBuffer(createEmployeeJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req)

	// 3. Create node with metadata
	createNodePayload := map[string]interface{}{
		"path": "/png/handles/Employee/Profile",
		"name": "Profile",
		"type": 0,
		"metadata": map[string]interface{}{
			"db_type":   "PostgreSQL",
			"table":     "employees",
			"id_column": "employee_id",
		},
	}
	createNodeJSON, _ := json.Marshal(createNodePayload)

	req, _ = http.NewRequest("POST", "http://localhost:18081/nodes/create", bytes.NewBuffer(createNodeJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	createResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Create node failed: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", createResp.StatusCode)
	}

	t.Logf("✓ Node created successfully")

	// 4. Stop server
	server.Shutdown(nil)
	time.Sleep(1 * time.Second)
	t.Logf("✓ Server stopped")

	// 5. Start server again (load from disk)
	server2, err := internal.LoadServer(config)
	if err != nil {
		t.Fatalf("Failed to load server: %v", err)
	}

	if err := server2.Start(); err != nil {
		t.Fatalf("Failed to restart server: %v", err)
	}
	defer server2.Shutdown(nil)

	time.Sleep(1 * time.Second)
	t.Logf("✓ Server restarted")

	// 6. Login again
	loginResp2, err := http.Post("http://localhost:18081/login",
		"application/json",
		bytes.NewBufferString(`{"username":"admin@test.com","password":"admin123"}`))
	if err != nil {
		t.Fatalf("Second login failed: %v", err)
	}
	defer loginResp2.Body.Close()

	var loginData2 map[string]string
	json.NewDecoder(loginResp2.Body).Decode(&loginData2)
	token2 := loginData2["session_token"]

	// 7. Retrieve node
	req2, _ := http.NewRequest("GET", "http://localhost:18081/nodes/get?path=/png/handles/Employee/Profile", nil)
	req2.Header.Set("Authorization", "Bearer "+token2)

	getResp, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Get node failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", getResp.StatusCode)
	}

	var nodeData map[string]interface{}
	json.NewDecoder(getResp.Body).Decode(&nodeData)

	if nodeData["Name"] != "Profile" {
		t.Fatalf("Expected node name 'Profile', got %v", nodeData["Name"])
	}

	t.Logf("✓ Node retrieved successfully after server restart")
	t.Log("✅ TEST A PASSED: Node persistence works correctly")
}

// TestPermissionEnforcement - Test B: Permission Enforcement (Previously Missing)
func TestPermissionEnforcement(t *testing.T) {
	// Setup
	testDir := filepath.Join("/tmp", fmt.Sprintf("lumberjack-test-%d", time.Now().UnixNano()))
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	os.Setenv("JWT_SECRET", "test-secret-key-validation")

	config := types.ServerConfig{
		Process: types.ProcessInfo{
			ID:           "test-permissions",
			Name:         "test-permissions",
			ServerPort:   "18082",
			DatabasePath: testDir,
			LogPath:      testDir,
		},
		Organization: "Test Org",
		Phone:        "+1234567890",
	}

	adminUser := core.User{
		Username:     "admin@test.com",
		Email:        "admin@test.com",
		Password:     "admin123",
		Organization: "Test Org",
	}

	// Create server
	server, err := internal.NewServer(config, adminUser)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Shutdown(nil)

	time.Sleep(1 * time.Second)

	// 1. Login as admin
	loginResp, err := http.Post("http://localhost:18082/login",
		"application/json",
		bytes.NewBufferString(`{"username":"admin@test.com","password":"admin123"}`))
	if err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}
	defer loginResp.Body.Close()

	var adminLoginData map[string]string
	json.NewDecoder(loginResp.Body).Decode(&adminLoginData)
	adminToken := adminLoginData["session_token"]

	// 2. Create a regular user
	createUserJSON := `{"username":"user@test.com","email":"user@test.com","password":"user123"}`
	req, _ := http.NewRequest("POST", "http://localhost:18082/users/create", bytes.NewBufferString(createUserJSON))
	req.Header.Set("Content-Type", "application/json")

	createUserResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}
	defer createUserResp.Body.Close()

	if createUserResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 for user creation, got %d", createUserResp.StatusCode)
	}

	t.Logf("✓ Regular user created")

	// 3. Create parent nodes first
	createPngNode := map[string]interface{}{
		"path": "/png",
		"name": "png",
		"type": 1,
	}
	createPngJSON, _ := json.Marshal(createPngNode)

	req, _ = http.NewRequest("POST", "http://localhost:18082/nodes/create", bytes.NewBuffer(createPngJSON))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req)

	createSecureNode := map[string]interface{}{
		"path": "/png/secure",
		"name": "secure",
		"type": 1,
	}
	createSecureJSON, _ := json.Marshal(createSecureNode)

	req, _ = http.NewRequest("POST", "http://localhost:18082/nodes/create", bytes.NewBuffer(createSecureJSON))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req)

	// 4. Create node as admin
	createNodePayload := map[string]interface{}{
		"path": "/png/secure/AdminData",
		"name": "AdminData",
		"type": 0,
		"metadata": map[string]interface{}{
			"classification": "confidential",
		},
	}
	createNodeJSON, _ := json.Marshal(createNodePayload)

	req, _ = http.NewRequest("POST", "http://localhost:18082/nodes/create", bytes.NewBuffer(createNodeJSON))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	createResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Create node failed: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", createResp.StatusCode)
	}

	t.Logf("✓ Admin node created")

	// 5. Login as regular user
	userLoginResp, err := http.Post("http://localhost:18082/login",
		"application/json",
		bytes.NewBufferString(`{"username":"user@test.com","password":"user123"}`))
	if err != nil {
		t.Fatalf("User login failed: %v", err)
	}
	defer userLoginResp.Body.Close()

	var userLoginData map[string]string
	json.NewDecoder(userLoginResp.Body).Decode(&userLoginData)
	userToken := userLoginData["session_token"]

	// 6. Try to GET node as regular user (should fail with 403)
	req, _ = http.NewRequest("GET", "http://localhost:18082/nodes/get?path=/png/secure/AdminData", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)

	getResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Get node failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status 403 Forbidden, got %d - Permission check NOT enforced!", getResp.StatusCode)
	}

	t.Logf("✓ Permission check enforced: user denied access (403)")
	t.Log("✅ TEST B PASSED: Permission enforcement works correctly")
}

// TestJWTSecretRequired - Test C: JWT Secret (Previously Hardcoded)
func TestJWTSecretRequired(t *testing.T) {
	// Clear JWT_SECRET env var
	originalSecret := os.Getenv("JWT_SECRET")
	os.Unsetenv("JWT_SECRET")
	defer os.Setenv("JWT_SECRET", originalSecret)

	testDir := filepath.Join("/tmp", fmt.Sprintf("lumberjack-test-%d", time.Now().UnixNano()))
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	config := types.ServerConfig{
		Process: types.ProcessInfo{
			ID:           "test-jwt",
			Name:         "test-jwt",
			ServerPort:   "18083",
			DatabasePath: testDir,
			LogPath:      testDir,
		},
		Organization: "Test Org",
		Phone:        "+1234567890",
	}

	adminUser := core.User{
		Username:     "admin@test.com",
		Email:        "admin@test.com",
		Password:     "admin123",
		Organization: "Test Org",
	}

	// Attempt to create server without JWT_SECRET
	_, err := internal.NewServer(config, adminUser)
	if err == nil {
		t.Fatal("Expected error when JWT_SECRET not set, but server created successfully")
	}

	if err.Error() != "JWT_SECRET environment variable not set" {
		t.Fatalf("Expected specific JWT_SECRET error, got: %v", err)
	}

	t.Logf("✓ Server correctly requires JWT_SECRET environment variable")
	t.Log("✅ TEST C PASSED: JWT secret enforcement works correctly")
}
