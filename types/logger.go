package types

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// LogFileMode is what a log file is created as. The log is operator data — it names users, paths and
// failures — so it is readable by the account that runs the service and by nobody else.
const LogFileMode os.FileMode = 0600

type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Notice(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
	Critical(format string, args ...interface{})
	Alert(format string, args ...interface{})
	Emergency(format string, args ...interface{})
	Success(format string, args ...interface{}) // For Testing Purposes
	Failure(format string, args ...interface{}) // For Testing Purposes
	Enter(name string)
	Exit(name string)
}

// LogInfo is the logger every entrypoint and every request handler shares.
//
// depth is the Enter/Exit nesting the indentation is drawn from, and it is ATOMIC because it is
// shared: two concurrent requests both bracket their work with Enter and Exit, so a plain int here
// is a read-modify-write on shared state from every handler at once. That is a data race the
// detector reports on any two overlapping requests, and its damage outlives the moment — nothing
// ever recomputes the depth, so a lost increment is permanent and the indentation of a long-lived
// server grows without bound.
//
// It is one counter for the whole process rather than one per request, which is what the
// indentation always was: interleaved spans from two requests nest into each other. Making it
// per-request would need the request to be carried into every log call, which is a different
// change to a different surface.
type LogInfo struct {
	depth atomic.Int64
	out   *log.Logger
	file  *os.File
}

// NewLogger returns a logger that writes to the process's standard error, which is where the
// stdlib default goes.
func NewLogger() *LogInfo {
	return &LogInfo{out: log.Default()}
}

// NewFileLogger returns a logger that writes to standard error AND to path.
//
// Nothing opened a file sink before, so the file GET /logs pages did not exist on any install and
// the route could only ever fail. The directory the CLI creates for logs stayed empty forever.
//
// The format is the stdlib default one — "2006/01/02 15:04:05 " and then the line — because that is
// what parseLogEntry reads back.
//
// WHAT GOES IN HERE IS NOW DURABLE AND IS SERVED OVER HTTP. Nothing that logs through this may pass
// a core.User, a core.Node or the forest: they carry bcrypt hashes, and a hash written here is a
// hash on disk and a hash in an API response.
func NewFileLogger(path string) (*LogInfo, error) {
	// EnsureDir rather than MkdirAll: the directory is nearly always already there — the CLI and
	// `serve` both make it before this runs — and MkdirAll says nothing about the mode of a
	// directory it did not create.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := EnsureDir(dir, LogDirMode); err != nil {
			return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
		}
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, LogFileMode)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", path, err)
	}

	// O_CREATE does not re-permission a file that already exists, including one left behind by a
	// build that opened it more widely.
	if err := file.Chmod(LogFileMode); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set permissions on log file %s: %w", path, err)
	}

	return &LogInfo{
		out:  log.New(logSink(file), "", log.LstdFlags),
		file: file,
	}, nil
}

// logSink writes to the log file and ALSO to standard error, so that a foreground or containerized
// run still says what it is doing.
//
// It writes to the file ALONE when standard error IS that file: the CLI spawns the server with its
// stdout and stderr already redirected into the very file this opens, and a MultiWriter across both
// would put every line in it twice.
func logSink(file *os.File) io.Writer {
	fileInfo, fileErr := file.Stat()
	stderrInfo, stderrErr := os.Stderr.Stat()
	if fileErr == nil && stderrErr == nil && os.SameFile(fileInfo, stderrInfo) {
		return file
	}
	return io.MultiWriter(os.Stderr, file)
}

// Close releases the file sink, if there is one. A logger without one is already closed.
func (l *LogInfo) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	return file.Close()
}

// writer is the sink to print to. A zero-value LogInfo still logs, to standard error.
func (l *LogInfo) writer() *log.Logger {
	if l.out == nil {
		return log.Default()
	}
	return l.out
}

// currentDepth is how deep in its Enter/Exit nesting the logger currently is.
func (l *LogInfo) currentDepth() int {
	return int(l.depth.Load())
}

// descend leaves a span, and will not go below zero.
//
// The clamp is a COMPARE-AND-SWAP rather than a read, a test and a write: the last of those is what
// loses an update, and a depth that has drifted is never corrected by anything.
func (l *LogInfo) descend() {
	for {
		depth := l.depth.Load()
		if depth <= 0 {
			return
		}
		if l.depth.CompareAndSwap(depth, depth-1) {
			return
		}
	}
}

// getIndent draws the nesting. It READS ONLY: it used to write the depth back to zero when it saw a
// negative one, which made every Info, Debug and Failure — the read path — a writer of the state
// every other goroutine was also writing.
func (l *LogInfo) getIndent() string {
	depth := l.depth.Load()
	if depth < 0 {
		depth = 0
	}
	return strings.Repeat("│  ", int(depth))
}

func (l *LogInfo) log(prefix, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	l.writer().Printf("%s%s %s", l.getIndent(), prefix, message)
}

func (l *LogInfo) Info(format string, args ...interface{}) {
	l.log("ℹ", format, args...)
}

func (l *LogInfo) Success(format string, args ...interface{}) {
	l.log("✓", format, args...)
}

func (l *LogInfo) Failure(format string, args ...interface{}) {
	l.log("✗", format, args...)
}

func (l *LogInfo) Enter(name string) {
	l.log("┌─", "BEGIN: %s", name)
	l.depth.Add(1)
}

func (l *LogInfo) Exit(name string) {
	l.descend()
	l.log("└─", "END: %s", name)
}

func (l *LogInfo) Debug(format string, args ...interface{}) {
	l.log("🔍", format, args...)
}

func (l *LogInfo) Notice(format string, args ...interface{}) {
	l.log("📝", format, args...)
}

func (l *LogInfo) Warn(format string, args ...interface{}) {
	l.log("⚠", format, args...)
}

func (l *LogInfo) Error(format string, args ...interface{}) {
	l.log("❌", format, args...)
}

func (l *LogInfo) Critical(format string, args ...interface{}) {
	l.log("🔥", format, args...)
}

func (l *LogInfo) Alert(format string, args ...interface{}) {
	l.log("🚨", format, args...)
}

func (l *LogInfo) Emergency(format string, args ...interface{}) {
	l.log("💀", format, args...)
}
