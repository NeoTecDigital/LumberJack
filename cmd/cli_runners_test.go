package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/types"
)

// How long a lookup over two process records is allowed to take before we call it wedged. The
// deadlock this guards against is permanent, so any generous number states the same thing.
const lookupTimeout = 5 * time.Second

// withTempDirs points the CLI's three directories at somewhere a test may write.
func withTempDirs(t *testing.T) {
	t.Helper()

	root := t.TempDir()
	log, lib, proc := defaultLogDir, defaultLibDir, defaultProcDir
	t.Cleanup(func() {
		defaultLogDir, defaultLibDir, defaultProcDir = log, lib, proc
	})

	defaultLogDir = filepath.Join(root, "log")
	defaultLibDir = filepath.Join(root, "lib")
	defaultProcDir = filepath.Join(root, "etc")
	for _, dir := range []string{defaultLogDir, defaultLibDir, filepath.Join(defaultProcDir, "live")} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create %s: %v", dir, err)
		}
	}
}

// writeRecord puts a process record on disk the way registerProcess does, for a given PID.
func writeRecord(t *testing.T, id string, pid int) {
	t.Helper()

	if err := registerProcess(types.ProcessInfo{
		ID:         id,
		PID:        pid,
		Name:       id,
		ServerURL:  "localhost",
		ServerPort: "8080",
	}); err != nil {
		t.Fatalf("Failed to write the process record: %v", err)
	}
}

// deadPID is a PID that is not running, which is what makes a record stale. Signal 0 is the same
// probe getRunningServers uses, and ESRCH is the kernel saying there is no such process.
func deadPID(t *testing.T) int {
	t.Helper()

	for pid := 4194303; pid > 1024; pid -= 7919 {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return pid
		}
	}
	t.Fatal("Failed to find a PID that is not running")
	return 0
}

// A stale record used to wedge the whole CLI: getRunningServers held the read lock and called
// removeProcess, which takes the write lock, and Go's RWMutex is not upgradable. Every command
// that lists servers — start, kill, list, restart — hung forever on the first one it met.
func TestGetRunningServersClearsStaleRecords(t *testing.T) {
	withTempDirs(t)
	writeRecord(t, "stale", deadPID(t))
	writeRecord(t, "alive", os.Getpid())

	type result struct {
		processes []types.ProcessInfo
		err       error
	}
	done := make(chan result, 1)
	go func() {
		processes, err := getRunningServers()
		done <- result{processes, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Failed to get running servers: %v", got.err)
		}
		if len(got.processes) != 1 || got.processes[0].ID != "alive" {
			t.Fatalf("Expected only the live server, got %v", got.processes)
		}
	case <-time.After(lookupTimeout):
		t.Fatalf("getRunningServers did not return within %s: the stale record deadlocked it", lookupTimeout)
	}

	// The stale record is gone, and the live one is untouched.
	if _, err := os.Stat(getProcessFilePath("stale")); !os.IsNotExist(err) {
		t.Errorf("The stale process record was not removed")
	}
	if _, err := os.Stat(getLiveFilePath("stale")); !os.IsNotExist(err) {
		t.Errorf("The stale live record was not removed")
	}
	if _, err := os.Stat(getProcessFilePath("alive")); err != nil {
		t.Errorf("The live process record was removed: %v", err)
	}
}

// A record nothing can read is as stale as one whose process is gone, and is cleared the same way
// rather than being met again on every command.
func TestGetRunningServersClearsUnreadableRecords(t *testing.T) {
	withTempDirs(t)
	if err := os.WriteFile(getLiveFilePath("orphan"), []byte("orphan"), 0644); err != nil {
		t.Fatalf("Failed to write the live record: %v", err)
	}

	processes, err := getRunningServers()
	if err != nil {
		t.Fatalf("Failed to get running servers: %v", err)
	}
	if len(processes) != 0 {
		t.Fatalf("Expected no running servers, got %v", processes)
	}
	if _, err := os.Stat(getLiveFilePath("orphan")); !os.IsNotExist(err) {
		t.Errorf("The orphaned live record was not removed")
	}
}

// The record a running server writes is the record the CLI reads back, which is what makes it
// findable: it used to be written by nobody, so runServer exited on every start.
func TestRegisteredProcessIsFound(t *testing.T) {
	withTempDirs(t)
	writeRecord(t, "running", os.Getpid())

	data, err := os.ReadFile(getProcessFilePath("running"))
	if err != nil {
		t.Fatalf("Failed to read the process record: %v", err)
	}
	var proc types.ProcessInfo
	if err := json.Unmarshal(data, &proc); err != nil {
		t.Fatalf("Failed to parse the process record: %v", err)
	}
	if proc.PID != os.Getpid() {
		t.Errorf("Recorded PID %d, want %d", proc.PID, os.Getpid())
	}

	processes, err := getRunningServers()
	if err != nil {
		t.Fatalf("Failed to get running servers: %v", err)
	}
	if len(processes) != 1 || processes[0].Name != "running" {
		t.Fatalf("Expected the registered server, got %v", processes)
	}

	if err := removeProcess("running"); err != nil {
		t.Fatalf("Failed to remove the process record: %v", err)
	}
	if processes, err := getRunningServers(); err != nil || len(processes) != 0 {
		t.Fatalf("Expected no running servers after removal, got %v (%v)", processes, err)
	}
}

// A server that is already running is the one thing `start` refuses. A configured database is not:
// refusing that made the documented create-then-start sequence impossible to complete.
func TestSpawnServerRefusesOnlyWhatIsRunning(t *testing.T) {
	withTempDirs(t)
	writeRecord(t, "tower", os.Getpid())

	err := spawnServer(types.ProcessInfo{Name: "tower", ServerPort: "8099"}, false)
	if err == nil {
		t.Fatal("Expected a running server of the same name to be refused")
	}

	if err := spawnServer(types.ProcessInfo{Name: ""}, false); err == nil {
		t.Error("Expected a server with no database name to be refused")
	}
}

// The two directories a spawned server writes into are owner-only, including when they are already
// there at 0755 — which they always were, because this entrypoint used to create them that way and
// os.MkdirAll never re-permissions a directory it did not create.
//
// 0700 is asserted as a LITERAL. Measuring against types.DataDirMode would pass just as happily
// after someone set that constant back to 0755.
func TestPrepareRuntimeDirsNarrowsExistingDirectories(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "log")
	dataDir := filepath.Join(root, "lib")

	for _, dir := range []string{logDir, dataDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to plant %s: %v", dir, err)
		}
		// MkdirAll is subject to the umask, so the starting mode is forced rather than requested.
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatalf("Failed to widen %s: %v", dir, err)
		}
	}

	if err := prepareRuntimeDirs(logDir, dataDir); err != nil {
		t.Fatalf("prepareRuntimeDirs reported %v", err)
	}

	for _, dir := range []string{logDir, dataDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Failed to stat %s: %v", dir, err)
		}
		if mode := info.Mode().Perm(); mode != 0700 {
			t.Errorf("%s is %04o, want %04o", dir, mode, os.FileMode(0700))
		}
	}
}
