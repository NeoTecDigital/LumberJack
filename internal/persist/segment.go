// Written by Richard Christopher, Copyright 2026 Richard Christopher

package persist

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// A segment is one file of the log. Segments are named by the sequence of the first record they
// were opened for, so a directory listing sorts them into log order:
//
//	<name>.dat.log.00000000000000000001
//	<name>.dat.log.00000000000000002001
//
// A new segment starts after each cold snapshot and when the current one passes segmentLimit, so
// the segments a durable state file covers are whole files that can be deleted.
const (
	segmentSuffix = ".log."
	segmentDigits = 20
	segmentLimit  = 64 << 20
	segmentMode   = os.FileMode(0600)
)

type segment struct {
	path  string
	first uint64
	// last is the highest sequence the segment holds, or first-1 when it holds none.
	last uint64
	size int64
	file *os.File
}

// segmentPath names the segment a sequence opens.
func segmentPath(statePath string, first uint64) string {
	return statePath + segmentSuffix + fmt.Sprintf("%0*d", segmentDigits, first)
}

// listSegments finds the segments beside a state file, in log order.
func listSegments(statePath string) ([]*segment, error) {
	matches, err := filepath.Glob(statePath + segmentSuffix + "*")
	if err != nil {
		return nil, err
	}
	segments := make([]*segment, 0, len(matches))
	for _, path := range matches {
		suffix := strings.TrimPrefix(path, statePath+segmentSuffix)
		first, err := strconv.ParseUint(suffix, 10, 64)
		if err != nil || len(suffix) != segmentDigits {
			return nil, fmt.Errorf("%s: not a log segment name", path)
		}
		segments = append(segments, &segment{path: path, first: first, last: first - 1})
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].first < segments[j].first })
	return segments, nil
}

// create starts a new segment for a first sequence, writes its banner, and makes the directory
// entry durable so the file is there after a crash.
func createSegment(statePath string, first uint64) (*segment, error) {
	path := segmentPath(statePath, first)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, segmentMode)
	if err != nil {
		return nil, err
	}
	if _, err := file.WriteString(SegmentMagic); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &segment{path: path, first: first, last: first - 1, size: int64(len(SegmentMagic)), file: file}, nil
}

// open reopens an existing segment for appending.
func (s *segment) open() error {
	if s.file != nil {
		return nil
	}
	file, err := os.OpenFile(s.path, os.O_WRONLY, segmentMode)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	s.file, s.size = file, info.Size()
	return nil
}

// append writes bytes holding records up to last, and undoes a write that did not land whole so
// a retry appends after a clean end rather than after half a record.
func (s *segment) append(data []byte, last uint64) error {
	start := s.size
	written, err := s.file.WriteAt(data, start)
	if err != nil {
		return s.undo(start, err)
	}
	s.size += int64(written)
	s.last = last
	return nil
}

// sync makes everything appended so far durable, undoing the unsynced tail on a failure so that
// what the file holds is exactly what was vouched for.
func (s *segment) sync(durableSize int64) error {
	if err := s.file.Sync(); err != nil {
		return s.undo(durableSize, err)
	}
	return nil
}

// undo cuts the file back to a size that is known good and reports the error that made it
// necessary, or the worse error of being unable to cut.
func (s *segment) undo(size int64, cause error) error {
	if err := s.file.Truncate(size); err != nil {
		return fmt.Errorf("%w; and the segment could not be cut back to %d bytes: %v", cause, size, err)
	}
	s.size = size
	return cause
}

// close flushes and closes the file. A segment with no file is already closed.
func (s *segment) close() error {
	if s.file == nil {
		return nil
	}
	err := s.file.Sync()
	if closeErr := s.file.Close(); err == nil {
		err = closeErr
	}
	s.file = nil
	return err
}

// syncDir flushes a directory entry, which is what makes a create, a rename or a delete survive a
// crash.
func syncDir(dir string) error {
	if dir == "" {
		dir = "."
	}
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
