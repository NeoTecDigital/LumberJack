package types

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// redirectStderr points the process's standard error at path for the duration of the test.
func redirectStderr(t *testing.T, path string) *os.File {
	t.Helper()

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", path, err)
	}

	original := os.Stderr
	os.Stderr = file
	t.Cleanup(func() {
		os.Stderr = original
		file.Close()
	})
	return file
}

// A file logger actually writes a file, in the format the log reader parses back.
func TestFileLoggerWritesAParseableLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "process.log")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("Failed to open the log file: %v", err)
	}
	defer logger.Close()

	logger.Info("a recorded message")

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read the log file: %v", err)
	}

	line := strings.TrimRight(string(contents), "\n")
	if !strings.Contains(line, "a recorded message") {
		t.Fatalf("The log file holds %q", line)
	}
	// "2006/01/02 15:04:05 " is what the stdlib default flags write and what parseLogEntry reads.
	if len(line) < 19 || strings.Count(line[:19], "/") != 2 || strings.Count(line[:19], ":") != 2 {
		t.Errorf("The line does not begin with a stdlib timestamp: %q", line)
	}
}

// The log file is readable by its owner and by nobody else.
func TestFileLoggerOpensTheFileOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "process.log")

	// A file an older build left behind at a wider mode is narrowed rather than accepted.
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatalf("Failed to plant a world-readable log file: %v", err)
	}

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("Failed to open the log file: %v", err)
	}
	defer logger.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Failed to stat the log file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != LogFileMode {
		t.Errorf("Log file mode is %04o, want %04o", mode, LogFileMode)
	}
}

// Every line lands ONCE when standard error already IS the log file, which is how the CLI spawns a
// server: it opens the log file itself and hands it to the child as stdout and stderr.
func TestFileLoggerDoesNotDoubleWriteIntoARedirectedStderr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "process.log")
	redirectStderr(t, path)

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("Failed to open the log file: %v", err)
	}
	defer logger.Close()

	logger.Info("a message logged exactly once")

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read the log file: %v", err)
	}
	if count := strings.Count(string(contents), "a message logged exactly once"); count != 1 {
		t.Errorf("The message appears %d times in the log file, want 1:\n%s", count, contents)
	}
}

// When standard error is somewhere else, it still gets the line: a foreground or containerized run
// says what it is doing.
func TestFileLoggerAlsoWritesToADistinctStderr(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "process.log")
	stderrPath := filepath.Join(dir, "stderr.txt")
	redirectStderr(t, stderrPath)

	logger, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("Failed to open the log file: %v", err)
	}
	defer logger.Close()

	logger.Info("a message on both sinks")

	for _, path := range []string{logPath, stderrPath} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", path, err)
		}
		if !strings.Contains(string(contents), "a message on both sinks") {
			t.Errorf("%s does not carry the message", path)
		}
	}
}

// A logger with no file sink still logs — to the stdlib default, which is where it always went —
// and closing it is not an error.
func TestStderrLoggerNeedsNoFile(t *testing.T) {
	logger := NewLogger()
	logger.Info("a message with no file sink")

	if err := logger.Close(); err != nil {
		t.Errorf("Closing a logger without a file sink reported %v", err)
	}

	// A zero value logs rather than panicking on a nil sink.
	(&LogInfo{}).Info("a message from a zero-value logger")
}
