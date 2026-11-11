// Written by Richard Christopher, Copyright 2026 Richard Christopher

package persist

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/NeoTecDigital/LumberJack/types"
)

func testConfig(hotSync string) types.PersistenceConfig {
	config := types.DefaultPersistence()
	config.Mode, config.HotSync = types.PersistenceTiered, hotSync
	return config
}

func statePathIn(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "store.dat")
}

// appendRecords opens a log, commits bodies in order and closes it.
func appendRecords(t *testing.T, statePath string, hotSync string, bodies ...string) {
	t.Helper()
	log, _, err := Open(statePath, testConfig(hotSync), NoHook{}, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, body := range bodies {
		seq := log.Stage([]byte(body))
		if err := log.Commit(seq); err != nil {
			t.Fatalf("commit %d: %v", seq, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func recovered(t *testing.T, statePath string, covered uint64) ([]Record, uint64) {
	t.Helper()
	log, records, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, covered)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer log.Close()
	return records, log.LastStaged() + 1
}

func bodies(records []Record) string {
	out := []string{}
	for _, record := range records {
		out = append(out, fmt.Sprintf("%d:%s", record.Seq, record.Body))
	}
	return strings.Join(out, " ")
}

func TestRecordsRoundTripThroughTheFormat(t *testing.T) {
	data, err := encodeRecord(nil, Record{Seq: 7, Body: []byte("seven")})
	if err != nil {
		t.Fatal(err)
	}
	record, span, intact, reason := parseRecord(data)
	if !intact || span != len(data) || record.Seq != 7 || string(record.Body) != "seven" {
		t.Fatalf("parse: intact=%v span=%d seq=%d body=%q reason=%q", intact, span, record.Seq, record.Body, reason)
	}
	if _, _, intact, reason := parseRecord(data[:headerSize+2]); intact || reason != "short body" {
		t.Fatalf("short body: intact=%v reason=%q", intact, reason)
	}
	if _, _, intact, reason := parseRecord(data[:5]); intact || reason != "short header" {
		t.Fatalf("short header: intact=%v reason=%q", intact, reason)
	}
}

func TestEveryHotSyncModeRecoversWhatItCommitted(t *testing.T) {
	for _, mode := range []string{types.HotSyncCommit, types.HotSyncInterval, types.HotSyncNone} {
		t.Run(mode, func(t *testing.T) {
			statePath := statePathIn(t)
			appendRecords(t, statePath, mode, "a", "b", "c")
			records, next := recovered(t, statePath, 0)
			if got := bodies(records); got != "1:a 2:b 3:c" || next != 4 {
				t.Fatalf("recovered %q next %d", got, next)
			}
			past, next := recovered(t, statePath, 2)
			if got := bodies(past); got != "3:c" || next != 4 {
				t.Fatalf("past 2: %q next %d", got, next)
			}
		})
	}
}

// segmentBytes reads the one segment a small log holds.
func segmentBytes(t *testing.T, statePath string) (string, []byte) {
	t.Helper()
	segments, err := listSegments(statePath)
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments: %v %v", segments, err)
	}
	data, err := os.ReadFile(segments[0].path)
	if err != nil {
		t.Fatal(err)
	}
	return segments[0].path, data
}

// recordOffsets is where each record of a segment begins, and the end.
func recordOffsets(data []byte) []int {
	offsets := []int{}
	at := len(SegmentMagic)
	for at < len(data) {
		offsets = append(offsets, at)
		_, span, _, _ := parseRecord(data[at:])
		at += span
	}
	return append(offsets, len(data))
}

func TestATornTailIsCutAtEveryByteOffset(t *testing.T) {
	statePath := statePathIn(t)
	appendRecords(t, statePath, types.HotSyncCommit, "first", "second", "third-and-longer")
	path, whole := segmentBytes(t, statePath)
	offsets := recordOffsets(whole)
	lastStart, end := offsets[2], offsets[3]
	for cut := lastStart; cut < end; cut++ {
		if err := os.WriteFile(path, whole[:cut], 0600); err != nil {
			t.Fatal(err)
		}
		records, next := recovered(t, statePath, 0)
		if got := bodies(records); got != "1:first 2:second" || next != 3 {
			t.Fatalf("cut at %d: recovered %q next %d", cut, got, next)
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() != int64(lastStart) {
			t.Fatalf("cut at %d: segment is %d bytes, want %d", cut, info.Size(), lastStart)
		}
		// Appending continues cleanly after the cut.
		appendRecords(t, statePath, types.HotSyncCommit, "fourth")
		if records, _ := recovered(t, statePath, 0); bodies(records) != "1:first 2:second 3:fourth" {
			t.Fatalf("cut at %d: after append %q", cut, bodies(records))
		}
	}
}

func TestDamageBeforeAnIntactRecordRefusesToOpen(t *testing.T) {
	statePath := statePathIn(t)
	appendRecords(t, statePath, types.HotSyncCommit, "first", "second", "third")
	path, whole := segmentBytes(t, statePath)
	offsets := recordOffsets(whole)
	for _, flip := range []struct {
		name   string
		at     int
		reason string
	}{
		{"body of the first record", offsets[0] + headerSize + 1, "body checksum"},
		{"header of the second record", offsets[1] + 5, "header checksum"},
	} {
		damaged := append([]byte(nil), whole...)
		damaged[flip.at] ^= 0x40
		if err := os.WriteFile(path, damaged, 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 0)
		var fault *Fault
		if !errors.As(err, &fault) {
			t.Fatalf("%s: opened or failed otherwise: %v", flip.name, err)
		}
		if fault.Segment != path || fault.Reason != flip.reason {
			t.Fatalf("%s: fault %+v", flip.name, fault)
		}
		if info, _ := os.Stat(path); info.Size() != int64(len(whole)) {
			t.Fatalf("%s: the segment was truncated to %d bytes", flip.name, info.Size())
		}
	}
}

func TestDamageInAnEarlierSegmentRefusesEvenAtItsEnd(t *testing.T) {
	statePath := statePathIn(t)
	log, _, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"a", "b"} {
		if err := log.Commit(log.Stage([]byte(body))); err != nil {
			t.Fatal(err)
		}
	}
	log.RollAfter(2)
	if err := log.Commit(log.Stage([]byte("c"))); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	segments, _ := listSegments(statePath)
	if len(segments) != 2 {
		t.Fatalf("segments: %d", len(segments))
	}
	first, _ := os.ReadFile(segments[0].path)
	first[len(first)-1] ^= 0x01
	if err := os.WriteFile(segments[0].path, first, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err = Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 0)
	var fault *Fault
	if !errors.As(err, &fault) || fault.Segment != segments[0].path {
		t.Fatalf("damage in the first segment: %v", err)
	}
}

func TestARemovedRecordIsAGapAndRefuses(t *testing.T) {
	statePath := statePathIn(t)
	appendRecords(t, statePath, types.HotSyncCommit, "first", "second", "third")
	path, whole := segmentBytes(t, statePath)
	offsets := recordOffsets(whole)
	spliced := append(append([]byte(nil), whole[:offsets[1]]...), whole[offsets[2]:]...)
	if err := os.WriteFile(path, spliced, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 0)
	var fault *Fault
	if !errors.As(err, &fault) || fault.Offset != int64(offsets[1]) || !strings.Contains(fault.Reason, "expected 2, found 3") {
		t.Fatalf("gap: %v", err)
	}
}

func TestAStateFileAheadOfTheLogsStartRefuses(t *testing.T) {
	statePath := statePathIn(t)
	appendRecords(t, statePath, types.HotSyncCommit, "a", "b", "c")
	log, _, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	log.RollAfter(3)
	if err := log.Commit(log.Stage([]byte("d"))); err != nil {
		t.Fatal(err)
	}
	if err := log.Trim(3); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	// The log now begins at 4. A state file that covers only 2 is missing record 3.
	_, _, err = Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 2)
	if err == nil || !strings.Contains(err.Error(), "the log begins at 4") {
		t.Fatalf("state file behind the log: %v", err)
	}
	if records, next := recovered(t, statePath, 3); bodies(records) != "4:d" || next != 5 {
		t.Fatalf("covered 3: %q %d", bodies(records), next)
	}
	// A state file past the log's end is a store that was snapshotted after its last record.
	if records, next := recovered(t, statePath, 9); len(records) != 0 || next != 10 {
		t.Fatalf("covered 9: %q %d", bodies(records), next)
	}
}

func TestRollAndTrimDeleteOnlyCoveredSegments(t *testing.T) {
	statePath := statePathIn(t)
	log, _, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	for _, body := range []string{"a", "b", "c"} {
		if err := log.Commit(log.Stage([]byte(body))); err != nil {
			t.Fatal(err)
		}
	}
	log.RollAfter(3)
	for _, body := range []string{"d", "e"} {
		if err := log.Commit(log.Stage([]byte(body))); err != nil {
			t.Fatal(err)
		}
	}
	if got := log.Segments(); len(got) != 2 {
		t.Fatalf("segments after roll: %v", got)
	}
	if err := log.Trim(2); err != nil || len(log.Segments()) != 2 {
		t.Fatalf("trim 2 must keep a segment holding 3: %v %v", err, log.Segments())
	}
	if err := log.Trim(3); err != nil || len(log.Segments()) != 1 {
		t.Fatalf("trim 3: %v %v", err, log.Segments())
	}
	if err := log.Trim(5); err != nil || len(log.Segments()) != 0 {
		t.Fatalf("trim 5 must retire the covered current segment: %v %v", err, log.Segments())
	}
	if err := log.Commit(log.Stage([]byte("f"))); err != nil {
		t.Fatal(err)
	}
	if got := log.Segments(); len(got) != 1 || !strings.HasSuffix(got[0], "00000000000000000006") {
		t.Fatalf("segment after trim: %v", got)
	}
}

func TestAFailedAppendIsRetriedAheadOfTheNextCommit(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "missing", "store.dat")
	log, _, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	first := log.Stage([]byte("first"))
	if err := log.Commit(first); err == nil {
		t.Fatal("an append into a directory that is not there succeeded")
	}
	if !log.Behind() {
		t.Fatal("the log does not report itself behind")
	}
	if err := os.Mkdir(filepath.Join(dir, "missing"), 0700); err != nil {
		t.Fatal(err)
	}
	second := log.Stage([]byte("second"))
	if err := log.Commit(second); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if log.Behind() {
		t.Fatal("still behind after a successful retry")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if records, _ := recovered(t, statePath, 0); bodies(records) != "1:first 2:second" {
		t.Fatalf("recovered %q", bodies(records))
	}
}

func TestConcurrentCommitsAllLandInOrder(t *testing.T) {
	statePath := statePathIn(t)
	log, _, err := Open(statePath, testConfig(types.HotSyncCommit), NoHook{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	var staging sync.Mutex
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			staging.Lock()
			seq := log.Stage([]byte(fmt.Sprintf("r%d", i)))
			staging.Unlock()
			if err := log.Commit(seq); err != nil {
				t.Errorf("commit %d: %v", seq, err)
			}
		}(i)
	}
	group.Wait()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	records, next := recovered(t, statePath, 0)
	if len(records) != 32 || next != 33 {
		t.Fatalf("recovered %d records, next %d", len(records), next)
	}
	for i, record := range records {
		if record.Seq != uint64(i+1) {
			t.Fatalf("record %d carries sequence %d", i, record.Seq)
		}
	}
}

func TestTheHookSeesEveryRecordAfterItIsDurable(t *testing.T) {
	statePath := statePathIn(t)
	hook := &recordingHook{}
	log, _, err := Open(statePath, testConfig(types.HotSyncCommit), hook, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"a", "b"} {
		if err := log.Commit(log.Stage([]byte(body))); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if got := bodies(hook.seen); got != "1:a 2:b" || !hook.closed {
		t.Fatalf("hook saw %q closed=%v", got, hook.closed)
	}
}

func TestUnavailableSyncRolesAreRefusedByName(t *testing.T) {
	for _, role := range []string{types.SyncRolePrimary, types.SyncRoleReplica} {
		_, err := OpenHook(types.SyncConfig{Role: role, Listen: "x", Primary: "y", Ack: types.SyncAckLocal})
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("sync.role %q is not available in this build", role)) {
			t.Fatalf("%s: %v", role, err)
		}
	}
	if _, err := OpenHook(types.DefaultSync()); err != nil {
		t.Fatal(err)
	}
}

type recordingHook struct {
	seen   []Record
	closed bool
}

func (h *recordingHook) Appended(record Record) error {
	h.seen = append(h.seen, Record{Seq: record.Seq, Body: bytes.Clone(record.Body)})
	return nil
}
func (h *recordingHook) Close() error { h.closed = true; return nil }
