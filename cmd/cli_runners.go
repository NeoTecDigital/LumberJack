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

const (
	// The environment the spawned child is told about itself in.
	spawnedEnv = "LUMBERJACK_SPAWNED"
	spawnIDEnv = "LUMBERJACK_ID"
)

var (
	processLock sync.RWMutex
)

func getProcessFilePath(id string) string {
	return filepath.Join(defaultLibDir, id+".pi")
}

func getLiveFilePath(id string) string {
	return filepath.Join(defaultProcDir, "live", id)
}

// prepareRuntimeDirs makes the two directories a spawned server writes into, owner-only.
//
// It is a named function so the mode is one decision with one test, rather than a pair of literals
// repeated at each entrypoint — which is how they all drifted to 0755 and stayed there.
func prepareRuntimeDirs(logPath, databasePath string) error {
	if err := types.EnsureDir(logPath, types.LogDirMode); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}
	if err := types.EnsureDir(databasePath, types.DataDirMode); err != nil {
		return fmt.Errorf("failed to create database directory: %v", err)
	}
	return nil
}

func spawnServer(userInput types.ProcessInfo, withDashboard bool) error {
	if userInput.Name == "" {
		return fmt.Errorf("a database name is required to start a server")
	}

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

	// A CONFIGURED DATABASE IS WHAT `start` IS FOR, not a reason to refuse. This used to reject
	// any name whose config existed — which `create` has just written — so the documented
	// create-then-start sequence could never be completed. What is worth refusing is a name
	// already running, which is the loop above; the caller has already loaded the config.

	// Create unique ID for this instance. The CHILD writes the process record, since it is the
	// only one that knows its own PID, so the id is handed to it in the environment.
	id := generateID()

	// Set up new server with user input values, using defaults where not specified
	config := types.ProcessInfo{
		Name:          userInput.Name,
		ServerURL:     userInput.ServerURL,
		ServerPort:    userInput.ServerPort,
		DashboardPort: userInput.DashboardPort,
		LogPath:       userInput.LogPath,
		DatabasePath:  filepath.Join(defaultLibDir, userInput.Name),
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

	// Ensure directories exist, owner-only. They hold the log file and the state file, and the
	// state file is every bcrypt hash on the server. MkdirAll at 0755 here is what kept the
	// directories world-readable no matter what mode the writers asked for.
	if err := prepareRuntimeDirs(config.LogPath, config.DatabasePath); err != nil {
		return err
	}

	// Create log file.
	//
	// APPENDED to, not truncated: a restart used to throw away everything the previous run recorded.
	// Owner-only, because the log names users, paths and failures and is served over HTTP by
	// GET /logs; os.Create opened it 0666&^umask, which is 0644 on a stock system.
	logPath := filepath.Join(config.LogPath, fmt.Sprintf("%s.log", id))
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, types.LogFileMode)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}
	defer logFile.Close()

	// O_CREATE does not re-permission a file an older build left behind at a wider mode.
	if err := logFile.Chmod(types.LogFileMode); err != nil {
		return fmt.Errorf("failed to set permissions on log file: %v", err)
	}

	// Create command with proper arguments
	args := []string{"start", userInput.Name}
	if withDashboard {
		args = append(args, "-d")
	}

	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), spawnedEnv+"=1", spawnIDEnv+"="+id)

	// The log file made just above is the one `lumberjack logs` and /logs read. Without this the
	// child's output goes to /dev/null and that file stays empty forever.
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

	// Don't wait for the process
	go func() {
		cmd.Process.Release()
	}()

	// Brief pause to ensure process starts
	time.Sleep(100 * time.Millisecond)

	return nil
}

func getRunningServers() ([]types.ProcessInfo, error) {
	processes, stale, err := readProcessRecords()
	if err != nil {
		return nil, err
	}

	// THE STALE RECORDS ARE REMOVED AFTER THE READ LOCK IS RELEASED. removeProcess takes the write
	// lock and Go's RWMutex is not upgradable, so cleaning up from inside the read above deadlocked
	// the process the first time it met a record whose PID was gone.
	for _, id := range stale {
		if err := removeProcess(id); err != nil {
			fmt.Printf("Warning: Error removing stale process record %s: %v\n", id, err)
		}
	}

	return processes, nil
}

// readProcessRecords reads every process record, and reports which of them are no longer running
// rather than acting on them: see getRunningServers for why removing them here would deadlock.
func readProcessRecords() ([]types.ProcessInfo, []string, error) {
	processLock.RLock()
	defer processLock.RUnlock()

	// Check live processes directory
	liveDir := filepath.Join(defaultProcDir, "live")
	liveFiles, err := os.ReadDir(liveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []types.ProcessInfo{}, nil, nil
		}
		return nil, nil, err
	}

	var processes []types.ProcessInfo
	var stale []string
	for _, file := range liveFiles {
		// Get process info from .pi file. A live entry whose record is GONE names nothing and is
		// cleaned up with the rest; one we merely could not read this time is left alone.
		data, err := os.ReadFile(getProcessFilePath(file.Name()))
		if err != nil {
			if os.IsNotExist(err) {
				stale = append(stale, file.Name())
			}
			continue
		}

		var proc types.ProcessInfo
		if err := json.Unmarshal(data, &proc); err != nil {
			stale = append(stale, file.Name())
			continue
		}

		// Verify process is actually running
		process, err := os.FindProcess(proc.PID)
		if err != nil {
			stale = append(stale, proc.ID)
			continue
		}

		// Send signal 0 to check if process exists
		if err := process.Signal(syscall.Signal(0)); err != nil {
			stale = append(stale, proc.ID)
			continue
		}

		processes = append(processes, proc)
	}

	return processes, stale, nil
}

// registerProcess writes the record that says this server is up.
//
// IT IS CALLED BY THE SERVER ITSELF, because the PID in the record has to be the PID of the
// process that is serving: nothing else can write that honestly, and nothing used to write it at
// all — so `runServer` read a record that never existed and exited on every start.
func registerProcess(proc types.ProcessInfo) error {
	if err := os.MkdirAll(filepath.Dir(getProcessFilePath(proc.ID)), 0755); err != nil {
		return fmt.Errorf("failed to create process directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(getLiveFilePath(proc.ID)), 0755); err != nil {
		return fmt.Errorf("failed to create live directory: %v", err)
	}

	if err := updateProcessInfo(proc); err != nil {
		return err
	}

	return os.WriteFile(getLiveFilePath(proc.ID), []byte(proc.Name), 0644)
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
	_ = os.Remove(getLiveFilePath(proc.ID))

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
	_ = os.Remove(getLiveFilePath(id))

	return nil
}
