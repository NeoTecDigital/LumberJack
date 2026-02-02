package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/vaziolabs/lumberjack/types"
)

var (
	processLock sync.RWMutex
)

func getProcessFilePath(id string) string {
	return filepath.Join(defaultLibDir, id+".pi")
}

func spawnServer(userInput types.ProcessInfo, withDashboard bool) error {
	// Validate server name doesn't already exist
	processes, err := getRunningServers()
	if err != nil {
		return fmt.Errorf("failed to check running servers: %v", err)
	}

	for _, proc := range processes {
		if proc.Name == userInput.Name {
			return fmt.Errorf("server with name '%s' is already running", userInput.Name)
		}
	}

	// Create unique ID for this instance
	id := generateID()

	// Set up new server with user input values, using defaults where not specified
	config := types.ProcessInfo{
		ID:            id,
		Name:          userInput.Name,
		ServerURL:     userInput.ServerURL,
		ServerPort:    userInput.ServerPort,
		DashboardPort: userInput.DashboardPort,
		DashboardUp:   withDashboard,
		LogPath:       userInput.LogPath,
		DatabasePath:  filepath.Join(defaultLibDir, userInput.Name),
		Organization:  userInput.Organization,
		Phone:         userInput.Phone,
		Admin:         userInput.Admin,
	}

	// Fill in defaults for any empty values
	if config.ServerURL == "" {
		config.ServerURL = "localhost"
	}
	if config.ServerPort == "" {
		config.ServerPort = "8080"
	}
	if config.DashboardPort == "" {
		config.DashboardPort = "8081"
	}
	if config.LogPath == "" {
		config.LogPath = defaultLogDir
	}

	// Ensure directories exist
	if err := os.MkdirAll(config.LogPath, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}
	if err := os.MkdirAll(config.DatabasePath, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %v", err)
	}
	liveDir := filepath.Join(defaultProcDir, "live")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		return fmt.Errorf("failed to create live directory: %v", err)
	}

	// Create log file
	logPath := filepath.Join(config.LogPath, fmt.Sprintf("%s.log", id))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}
	defer logFile.Close()

	// Create command with proper arguments
	args := []string{"start", userInput.Name}
	if withDashboard {
		args = append(args, "-d")
	}

	// Serialize config to JSON for passing via environment
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %v", err)
	}

	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(),
		"LUMBERJACK_SPAWNED=1",
		fmt.Sprintf("LUMBERJACK_PROCESS_ID=%s", id),
		fmt.Sprintf("LUMBERJACK_CONFIG=%s", string(configJSON)),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Properly detach the process
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	// Start process without waiting
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}

	// Update config with actual PID
	config.PID = cmd.Process.Pid

	// Write processInfo BEFORE releasing the process
	// This ensures child can find it when it starts
	if err := writeProcessInfo(config); err != nil {
		// Kill the spawned process if we can't write process info
		cmd.Process.Kill()
		return fmt.Errorf("failed to write process info: %v", err)
	}

	// Don't wait for the process
	go func() {
		cmd.Process.Release()
	}()

	// Brief pause to ensure process starts
	time.Sleep(100 * time.Millisecond)

	return nil
}


func getRunningServers() ([]types.ProcessInfo, error) {
	processLock.RLock()

	// Check live processes directory
	liveDir := filepath.Join(defaultProcDir, "live")
	liveFiles, err := os.ReadDir(liveDir)
	if err != nil {
		processLock.RUnlock()
		if os.IsNotExist(err) {
			return []types.ProcessInfo{}, nil
		}
		return nil, err
	}

	var processes []types.ProcessInfo
	var deadProcesses []string

	for _, file := range liveFiles {
		// Get process info from .pi file
		data, err := os.ReadFile(getProcessFilePath(file.Name()))
		if err != nil {
			continue
		}

		var proc types.ProcessInfo
		if err := json.Unmarshal(data, &proc); err != nil {
			continue
		}

		// Verify process is actually running
		if process, err := os.FindProcess(proc.PID); err == nil {
			// Send signal 0 to check if process exists
			if err := process.Signal(syscall.Signal(0)); err == nil {
				processes = append(processes, proc)
			} else {
				// Process not running, mark for cleanup
				deadProcesses = append(deadProcesses, proc.ID)
			}
		} else {
			deadProcesses = append(deadProcesses, proc.ID)
		}
	}

	processLock.RUnlock()

	// Clean up dead processes (need write lock, so do after releasing read lock)
	for _, id := range deadProcesses {
		removeProcess(id)
	}

	return processes, nil
}

func killProcess(proc types.ProcessInfo) error {
	processLock.Lock()
	defer processLock.Unlock()

	// Try to kill the process group first
	pgid, err := syscall.Getpgid(proc.PID)
	if err == nil {
		// Kill the entire process group
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
			// If process group kill fails, try killing individual process
			process, err := os.FindProcess(proc.PID)
			if err == nil {
				_ = process.Kill()
			}
		}
	}

	// Clean up process files regardless of kill success
	_ = os.Remove(getProcessFilePath(proc.ID))
	_ = os.Remove(filepath.Join(defaultProcDir, "live", proc.ID))

	// Don't wait for port cleanup, just run in background
	if proc.DashboardUp {
		go exec.Command("fuser", "-k", proc.DashboardPort+"/tcp").Run()
	}
	go exec.Command("fuser", "-k", proc.ServerPort+"/tcp").Run()

	return nil
}

func removeProcess(id string) error {
	processLock.Lock()
	defer processLock.Unlock()

	// Remove the process info file
	_ = os.Remove(getProcessFilePath(id))

	// Remove the live process file
	liveFilePath := filepath.Join(defaultProcDir, "live", id)
	_ = os.Remove(liveFilePath)

	return nil
}
