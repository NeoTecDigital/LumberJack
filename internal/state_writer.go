package internal

import (
	"fmt"
	"sync"
)

// The writer that makes the forest durable WITHOUT the forest held.
//
// THE DEFECT THIS EXISTS TO CLOSE: every mutating route flushed the state file to disk inside the
// exclusive forest hold, so an fsync that took nineteen seconds under host congestion held off
// every other request for nineteen seconds — reads included. The engine answered /health in 25ms
// the whole time, because health takes no lock, so the relay in front of it reported the datastore
// as UNREACHABLE while it was merely stalled.
//
// The forest hold now covers the mutation and the SERIALIZATION of the forest, and stops there.
// What comes out is an immutable snapshot: a byte slice nothing else can reach, so the write and
// the two fsyncs behind it happen with the forest free. That keeps the guarantee c95ef33 was for —
// a marshal and a mutation still cannot overlap, because the marshal is still inside the exclusive
// hold — while taking the disk out of it.
//
// ORDERING is what a snapshot-per-write needs and a log does not. Two snapshots are two whole
// states of the same forest, so writing an older one after a newer one silently rolls the database
// back. The sequence number is assigned under the exclusive hold, in the same critical section as
// the encode, which makes seq order the same order as forest state. This writer then guarantees:
// one flush at a time, always the newest staged snapshot, and never one older than what is already
// on disk.

// stateSnapshot is one serialization of the WHOLE forest, together with the sequence number that
// says which serialization it is.
//
// It is IMMUTABLE once built, and nothing that shares memory with the forest is in it. That is what
// makes it safe to write with the forest unlocked.
type stateSnapshot struct {
	seq  uint64
	hash []byte
	data []byte
	path string
}

// stateWriter serialises the disk side of persistence and coalesces what it can.
//
// Coalescing is sound HERE and would not be over a log: a snapshot is the whole state, so a newer
// snapshot subsumes every older one. Writers that pile up behind an in-flight flush are all
// satisfied by one subsequent write of the newest of them, which is why a congested disk now costs
// a queue of writers two flushes rather than one flush each.
type stateWriter struct {
	mutex   sync.Mutex
	settled *sync.Cond

	// write publishes a snapshot durably and answers only once it is on the disk. It is a field
	// so a test can hold the disk busy under a real handler; production wiring is publishSnapshot.
	write func(stateSnapshot) error

	// pending is the newest snapshot staged and not yet attempted. It is a single slot on
	// purpose: an older snapshot that a newer one replaced must never reach the disk.
	pending  *stateSnapshot
	flushing bool

	// durableSeq and durableHash describe the file as it actually is. durableHash is what the
	// unchanged-content skip is decided against, and it is cleared whenever a flush fails, so a
	// failed write is never mistaken for bytes already on disk.
	durableSeq  uint64
	durableHash []byte

	// failedSeq and failedErr carry a flush failure back to every caller whose snapshot that
	// flush was going to satisfy.
	failedSeq uint64
	failedErr error
}

// newStateWriter builds the writer behind a server's state file.
func newStateWriter(write func(stateSnapshot) error) *stateWriter {
	writer := &stateWriter{write: write}
	writer.settled = sync.NewCond(&writer.mutex)
	return writer
}

// markDurable records the hash of a state file that was just READ, so the first persist after a
// load skips a write it does not need — exactly as it did when the skip lived in persistLocked.
//
// The sequence stays at zero: nothing this process wrote is on the disk yet, and zero is below
// every sequence it will assign.
func (writer *stateWriter) markDurable(hash []byte) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	writer.durableHash = hash
}

// commit answers once the snapshot's contents are on the disk, and MUST be called with no lock on
// the forest held.
//
// The caller may be satisfied by another caller's flush. That is not a weakening: a newer snapshot
// is a later state of the same forest, so it contains this snapshot's change by construction.
func (writer *stateWriter) commit(snapshot stateSnapshot) error {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	target := writer.stage(snapshot)
	for {
		if writer.durableSeq >= target {
			return nil
		}
		if writer.failedSeq >= target {
			return writer.failedErr
		}
		if writer.flushing {
			writer.settled.Wait()
			continue
		}
		if writer.pending == nil {
			// Neither durable, nor failed, nor staged, nor in flight. The bookkeeping above is
			// wrong, and waiting here would hang the request for ever; a caller is told its write
			// did not happen rather than told nothing.
			return fmt.Errorf("state writer lost snapshot %d", target)
		}
		writer.flush()
	}
}

// stage records a snapshot as the next thing to write, and answers the sequence that has to become
// durable before the change in it may be acknowledged.
//
// The caller holds writer.mutex.
func (writer *stateWriter) stage(snapshot stateSnapshot) uint64 {
	// The unchanged-content skip is an ACKNOWLEDGMENT that the caller's change is already on
	// disk, so it is only honest while the file it went to is still there. An install whose data
	// directory was cleared underneath it was otherwise told every write succeeded while nothing
	// was ever written.
	if writer.durableHash != nil && compareHashes(writer.durableHash, snapshot.hash) && stateFileExists(snapshot.path) {
		return writer.durableSeq
	}

	// NEWEST WINS. A snapshot that a later one has already replaced must not be written after it:
	// both are whole states, so that is a rollback, not a redundant write.
	if writer.pending == nil || snapshot.seq > writer.pending.seq {
		staged := snapshot
		writer.pending = &staged
	}
	return snapshot.seq
}

// flush writes the newest staged snapshot, with writer.mutex RELEASED across the disk.
//
// Releasing it is the whole point: other callers stage and wait while the flush is in flight, and
// the forest is not held by any of them. The caller holds writer.mutex, has established that no
// other flush is in flight, and has established that pending is not nil.
func (writer *stateWriter) flush() {
	job := *writer.pending
	writer.pending = nil
	writer.flushing = true

	writer.mutex.Unlock()
	err := writer.write(job)
	writer.mutex.Lock()

	writer.flushing = false
	if err == nil {
		writer.durableSeq = job.seq
		writer.durableHash = job.hash
	} else {
		writer.failedSeq = job.seq
		writer.failedErr = err
		// The file is no longer vouched for. Clearing the hash makes the next persist WRITE even
		// if the forest still serializes to the bytes this attempt failed to publish.
		writer.durableHash = nil
	}
	writer.settled.Broadcast()
}
