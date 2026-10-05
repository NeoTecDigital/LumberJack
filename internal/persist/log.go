// Written by Richard Christopher, Copyright 2026 Richard Christopher

package persist

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/NeoTecDigital/LumberJack/types"
)

// Log is the append-only hot layer over one state file.
//
// STAGING AND COMMITTING ARE TWO STEPS, like the state writer's. Stage is called under the
// caller's ordering lock — the forest lock — and does nothing but number the record and queue it,
// so sequence order is forest order. Commit is called with that lock released and answers once the
// record is as durable as hot_sync asks. Whoever finds the queue unattended writes it: everything
// queued goes to the disk in ONE write and, under hot_sync commit, ONE fsync, so a burst of writers
// shares the disk's round trip instead of each paying for its own.
//
// A WRITE THAT FAILS IS NOT FORGOTTEN. The batch goes back to the front of the queue and the next
// commit retries it ahead of its own record, which is what keeps the log a complete record of the
// forest in memory: nothing acknowledged is lost, and nothing unacknowledged is dropped while the
// process lives. Until a retry succeeds, Behind reports the forest ahead of its log, and the graph
// engine refuses to stack new commands on that doubt.
type Log struct {
	statePath string
	config    types.PersistenceConfig
	hook      Hook

	mutex   sync.Mutex
	settled *sync.Cond

	queue   []Record
	writing bool
	closed  bool

	nextSeq    uint64
	writtenSeq uint64
	syncedSeq  uint64
	failedSeq  uint64
	failedErr  error
	attempts   uint64

	current  *segment
	segments []*segment
	rollAt   uint64

	syncStop chan struct{}
	syncDone chan struct{}
}

// Open recovers the log beside a state file and answers the records that are not yet in that
// file: every record with a sequence past covered, in order. The log is then ready to append from
// the sequence after the last one it holds (or after covered, whichever is later).
func Open(statePath string, config types.PersistenceConfig, hook Hook, covered uint64) (*Log, []Record, error) {
	segments, records, next, err := recoverSegments(statePath, covered)
	if err != nil {
		return nil, nil, err
	}
	log := &Log{statePath: statePath, config: config, hook: hook, segments: segments, nextSeq: next,
		writtenSeq: next - 1, syncedSeq: next - 1}
	log.settled = sync.NewCond(&log.mutex)
	if len(segments) > 0 {
		log.current = segments[len(segments)-1]
	}
	if config.HotSync == types.HotSyncInterval {
		log.startSyncer(time.Duration(config.HotSyncIntervalMS) * time.Millisecond)
	}
	return log, records, nil
}

// Stage numbers a record and queues it. The caller holds the lock that orders commits.
func (l *Log) Stage(body []byte) uint64 {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	seq := l.nextSeq
	l.nextSeq++
	l.queue = append(l.queue, Record{Seq: seq, Body: body})
	return seq
}

// LastStaged is the newest sequence handed out, which is the newest change the forest holds.
func (l *Log) LastStaged() uint64 {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.nextSeq - 1
}

// Behind reports that the newest write attempted failed and nothing has succeeded since.
func (l *Log) Behind() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.failedSeq > l.writtenSeq
}

// Commit answers once seq is durable to the configured hot_sync. It MUST be called with no lock on
// the forest held. A seq of zero asks only that everything already staged be written, which is
// how a caller with no change of its own retries a failed append.
func (l *Log) Commit(seq uint64) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if seq == 0 {
		seq = l.nextSeq - 1
	}
	seen := l.attempts
	for {
		if l.durable() >= seq {
			return nil
		}
		if l.closed {
			return fmt.Errorf("log closed before record %d was written", seq)
		}
		if l.failedSeq >= seq && l.attempts > seen {
			return l.failedErr
		}
		if l.writing {
			l.settled.Wait()
			continue
		}
		if len(l.queue) == 0 {
			return fmt.Errorf("log lost record %d", seq)
		}
		l.flush()
	}
}

// durable is the sequence the configured hot_sync vouches for. The caller holds l.mutex.
func (l *Log) durable() uint64 {
	if l.config.HotSync == types.HotSyncCommit {
		return l.syncedSeq
	}
	return l.writtenSeq
}

// flush writes the whole queue with l.mutex RELEASED across the disk. The caller holds l.mutex,
// has established that no flush is in flight, and that the queue is not empty.
//
// While writing is set the segment fields belong to the writer and nothing else reads them: every
// other reader waits on quiesce first. The roll point is read here, under the mutex, and carried
// into the write as a value.
func (l *Log) flush() {
	batch := l.queue
	l.queue = nil
	l.writing = true
	l.attempts++
	roll := l.rollAt

	l.mutex.Unlock()
	rolled, err := l.write(batch, roll)
	if err == nil {
		err = l.ship(batch)
	}
	l.mutex.Lock()

	l.writing = false
	if rolled && l.rollAt == roll {
		l.rollAt = 0
	}
	last := batch[len(batch)-1].Seq
	if err == nil {
		l.failedSeq, l.failedErr = 0, nil
	} else {
		l.queue = append(unwritten(batch, l.writtenSeq), l.queue...)
		l.failedSeq, l.failedErr = last, err
	}
	l.settled.Broadcast()
}

// quiesce waits until no flush is in flight, so the segment fields may be read. The caller holds
// l.mutex.
func (l *Log) quiesce() {
	for l.writing {
		l.settled.Wait()
	}
}

// unwritten is the tail of a batch past what reached the file, which is what a retry must append.
func unwritten(batch []Record, written uint64) []Record {
	for i, record := range batch {
		if record.Seq > written {
			return append([]Record(nil), batch[i:]...)
		}
	}
	return nil
}

// write appends a batch, starting a new segment at the roll point or where the current one is
// full. Called with l.mutex released; the segment fields are the writer's alone while writing. It
// answers whether the roll point was passed.
func (l *Log) write(batch []Record, roll uint64) (bool, error) {
	rolled := false
	start := 0
	for start < len(batch) {
		end := chunkEnd(batch, start, roll)
		if rolls(batch[start].Seq, roll) {
			rolled = true
		}
		if err := l.appendChunk(batch[start:end], roll); err != nil {
			return rolled, err
		}
		start = end
	}
	return rolled, nil
}

// chunkEnd is the index past the last record that goes into the current segment: everything up to
// the roll point.
func chunkEnd(batch []Record, start int, roll uint64) int {
	end := start + 1
	for end < len(batch) && !rolls(batch[end].Seq, roll) {
		end++
	}
	return end
}

// rolls reports whether seq must open a new segment.
func rolls(seq, roll uint64) bool {
	return roll != 0 && seq >= roll
}

// appendChunk writes records destined for one segment, opening it if need be, and syncs them when
// hot_sync is commit.
func (l *Log) appendChunk(chunk []Record, roll uint64) error {
	first, last := chunk[0].Seq, chunk[len(chunk)-1].Seq
	if l.current != nil && (rolls(first, roll) || l.current.size >= segmentLimit) {
		if err := l.retire(); err != nil {
			return err
		}
	}
	if l.current == nil {
		created, err := createSegment(l.statePath, first)
		if err != nil {
			return err
		}
		l.current = created
		l.mutex.Lock()
		l.segments = append(l.segments, created)
		l.mutex.Unlock()
	} else if err := l.current.open(); err != nil {
		return err
	}

	data, err := encodeBatch(chunk)
	if err != nil {
		return err
	}
	durableSize := l.current.size
	if err := l.current.append(data, last); err != nil {
		return err
	}
	l.advance(last, false)
	if l.config.HotSync != types.HotSyncCommit {
		return nil
	}
	if err := l.current.sync(durableSize); err != nil {
		// The chunk was cut back out of the file, so neither mark may stand past it.
		l.current.last = first - 1
		l.advance(first-1, true)
		return err
	}
	l.advance(last, true)
	return nil
}

// advance records what reached the file and, when synced says so, the disk. Called from the
// writer, which holds no mutex; both fields are read under it, so take it briefly.
func (l *Log) advance(seq uint64, synced bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.writtenSeq = seq
	if synced {
		l.syncedSeq = seq
	}
}

// encodeBatch lays a chunk's records end to end.
func encodeBatch(chunk []Record) ([]byte, error) {
	size := 0
	for _, record := range chunk {
		size += headerSize + len(record.Body)
	}
	data := make([]byte, 0, size)
	var err error
	for _, record := range chunk {
		if data, err = encodeRecord(data, record); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// ship hands each record of a written batch to the hook, in order.
func (l *Log) ship(batch []Record) error {
	for _, record := range batch {
		if err := l.hook.Appended(record); err != nil {
			return fmt.Errorf("sync hook refused record %d: %w", record.Seq, err)
		}
	}
	return nil
}

// retire closes the current segment so the next append opens a new one.
func (l *Log) retire() error {
	if l.current == nil {
		return nil
	}
	err := l.current.close()
	l.current = nil
	return err
}

// RollAfter asks that every record past seq go to a new segment, so the segments holding records
// up to seq are whole files a state file written at seq makes deletable.
func (l *Log) RollAfter(seq uint64) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.rollAt = seq + 1
}

// Trim deletes every segment whose records are all at or below seq — the ones a durable state
// file written at seq wholly covers. A segment still open for appending is closed first if it is
// covered and nothing is queued for it.
func (l *Log) Trim(seq uint64) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.quiesce()
	kept := l.segments[:0]
	var firstErr error
	for _, s := range l.segments {
		if s.last > seq || (s == l.current && len(l.queue) > 0) {
			kept = append(kept, s)
			continue
		}
		if s == l.current {
			if err := l.retire(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	l.segments = kept
	if err := syncDir(filepath.Dir(l.statePath)); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Sync makes everything written so far durable, whatever hot_sync says. It is what the interval
// syncer calls, and what Close calls last.
func (l *Log) Sync() error {
	l.mutex.Lock()
	l.quiesce()
	current, written, synced := l.current, l.writtenSeq, l.syncedSeq
	if current == nil || written <= synced || current.file == nil {
		l.mutex.Unlock()
		return nil
	}
	l.writing = true
	l.mutex.Unlock()

	err := current.sync(current.size)

	l.mutex.Lock()
	l.writing = false
	if err == nil && l.syncedSeq < written {
		l.syncedSeq = written
	}
	l.settled.Broadcast()
	l.mutex.Unlock()
	return err
}

// Close writes whatever is still queued, syncs it, closes the segment and the hook. The log takes
// nothing further.
func (l *Log) Close() error {
	l.stopSyncer()
	l.mutex.Lock()
	l.quiesce()
	if l.closed {
		l.mutex.Unlock()
		return nil
	}
	var err error
	if len(l.queue) > 0 {
		l.flush()
		err = l.failedErr
	}
	l.closed = true
	l.settled.Broadcast()
	l.mutex.Unlock()

	if syncErr := l.Sync(); err == nil {
		err = syncErr
	}
	l.mutex.Lock()
	if closeErr := l.retire(); err == nil {
		err = closeErr
	}
	l.mutex.Unlock()
	if hookErr := l.hook.Close(); err == nil {
		err = hookErr
	}
	return err
}

// Abandon drops the log the way a killed process would: whatever reached the file stays there,
// nothing is synced or snapshotted, and the goroutines stop. It is for tests of recovery.
func (l *Log) Abandon() {
	l.stopSyncer()
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.quiesce()
	l.closed = true
	if l.current != nil && l.current.file != nil {
		_ = l.current.file.Close()
		l.current.file = nil
	}
	l.settled.Broadcast()
}

// startSyncer runs the interval fsync.
func (l *Log) startSyncer(interval time.Duration) {
	l.syncStop, l.syncDone = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(l.syncDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = l.Sync()
			case <-l.syncStop:
				return
			}
		}
	}()
}

func (l *Log) stopSyncer() {
	if l.syncStop == nil {
		return
	}
	close(l.syncStop)
	<-l.syncDone
	l.syncStop = nil
}

// Segments lists the segment files the log currently holds, in order. For tests and operators.
func (l *Log) Segments() []string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.quiesce()
	paths := make([]string, 0, len(l.segments))
	for _, s := range l.segments {
		paths = append(paths, s.path)
	}
	return paths
}
