// Written by Richard Christopher, Copyright 2026 Richard Christopher
package internal

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/NeoTecDigital/LumberJack/types"
	"lukechampine.com/blake3"
)

// The object log: immutable bytes, addressed by what they are.
//
// THE GAP THIS CLOSES: everything the engine holds lives in `<name>.dat`, one document rewritten
// whole on every mutation under the exclusive forest hold. That is the right shape for the working
// set and the wrong shape for history — api_node_delete.go says it in so many words: "the history
// belongs where history is appended, not in the file that is rewritten whole". Attachments live
// inline in that document with a 10 MiB cap, so every byte of every file is re-serialized on every
// write to anything.
//
// An object is a byte string. Its id is the BLAKE3-256 of those bytes — the same hash ffi/canon
// derives identities with — so the same content put twice is one object, and an id names bytes and
// not a place. Objects are APPENDED to segment files beside the state file, never rewritten, never
// deleted. The in-memory index is derived from the segments on every open; the segments are the
// truth. Nothing here touches the forest or its lock, and nothing here rewrites `.dat`.
//
// ON-DISK FORMAT. `<name>.objects/` holds `00000001.seg`, `00000002.seg`, ... Each segment begins
// with objectSegmentMagic. Each record after it is:
//
//	[32] id        BLAKE3-256 of the PLAINTEXT
//	[1]  flag      objectPlain or objectSealed
//	[8]  length    little-endian, bytes of payload that follow
//	[n]  payload   the bytes, or their AES-GCM sealing (object_store_seal.go)
//	[4]  crc32c    little-endian, over id || flag || length || payload
//
// The CRC is what tells a torn tail from a whole record on open (object_store_scan.go). The id is
// what a read is verified against: a record whose payload no longer hashes to its id is reported as
// corrupt, never served.
//
// FSYNC DISCIPLINE follows state_writer.go: a put is not acknowledged until the record is on the
// disk. A new segment is synced, and the directory that names it is synced, before the first record
// goes into it; each record is followed by a Sync of the segment.
const (
	objectSegmentMagic = "LUMBERJACK-OBJECTS-1\n"
	objectIDSize       = 32
	objectHeaderSize   = objectIDSize + 1 + 8
	objectTrailerSize  = 4
	objectSegmentExt   = ".seg"
	objectFileMode     = stateFileMode

	objectPlain  byte = 0
	objectSealed byte = 1
)

// objectSegmentLimit is where a segment stops growing and the next one begins. A record is never
// split: a segment holding anything rolls over when the next record would carry it past this, and
// an empty segment takes a record of any permitted size.
const objectSegmentLimit int64 = 256 << 20

// DefaultMaxObjectBytes is the per-object cap when the configuration names none. It is EXPORTED
// because the refusal names it and a test has to be able to sit exactly on it. It is deliberately
// far above core.MaxAttachmentSize: the object log exists for file contents, trees and commits, and
// 10 MiB is the cap of the thing it replaces.
const DefaultMaxObjectBytes int64 = 64 << 20

var (
	ErrObjectNotFound  = errors.New("object not found")
	ErrObjectCorrupt   = errors.New("object is corrupt: the stored bytes do not hash to their id")
	ErrObjectTooLarge  = errors.New("object is larger than the limit")
	ErrInvalidObjectID = errors.New("object id must be 64 lowercase hex characters")
)

var objectCRCTable = crc32.MakeTable(crc32.Castagnoli)

type objectID [objectIDSize]byte

func (id objectID) hex() string { return hex.EncodeToString(id[:]) }

// parseObjectID reads the hex form a route carries. Uppercase is refused: one id, one spelling.
func parseObjectID(text string) (objectID, error) {
	var id objectID
	if len(text) != 2*objectIDSize {
		return id, ErrInvalidObjectID
	}
	for _, c := range text {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return id, ErrInvalidObjectID
		}
	}
	if _, err := hex.Decode(id[:], []byte(text)); err != nil {
		return id, ErrInvalidObjectID
	}
	return id, nil
}

// objectLocation is where one object's payload sits. The index holds these and nothing else.
type objectLocation struct {
	segment uint32
	offset  int64 // of the payload, past the header
	length  int64 // of the stored payload
	corrupt bool  // the record failed its CRC on open; a read answers ErrObjectCorrupt
}

// objectReceipt is what a put answers: the id, the size of the PLAINTEXT, and whether the bytes were
// already there.
type objectReceipt struct {
	ID      string `json:"id"`
	Size    int64  `json:"size"`
	Existed bool   `json:"existed"`
}

type objectStore struct {
	dir          string
	maxBytes     int64
	segmentLimit int64         // objectSegmentLimit, a field so a test can roll segments without 256 MiB
	sealer       *objectSealer // nil in plaintext mode

	// appendMu serializes puts end to end: the dedup check, the write, the fsync and the index
	// insert happen under it, so two puts of the same bytes cannot both append.
	appendMu sync.Mutex
	// mutex guards the index and the segment handles. Reads hold it shared and read the segment
	// with ReadAt, so they do not wait on an in-flight append.
	mutex    sync.RWMutex
	index    map[objectID]objectLocation
	segments map[uint32]*os.File
	tailID   uint32
	tailSize int64
	// repairs says what open had to do to the segments it found, for the caller to log.
	repairs []string
}

// ObjectsPath is the directory a config's objects are kept in, beside its state file. One definition,
// as StatePath is, so nothing can disagree about where a config's objects are.
func ObjectsPath(config types.ServerConfig) string {
	return filepath.Join(config.Process.DatabasePath, config.Process.Name+".objects")
}

// openObjectStore opens the segments under dir, rebuilds the index from them, and repairs a torn
// tail. storage is the server's encryption, or nil for plaintext; which mode the store on disk is in
// has to agree with it — see openObjectSealer.
func openObjectStore(dir string, maxBytes int64, storage *secureStorage) (*objectStore, error) {
	if err := os.MkdirAll(dir, types.DataDirMode); err != nil {
		return nil, fmt.Errorf("object store directory: %w", err)
	}
	names, err := segmentNames(dir)
	if err != nil {
		return nil, err
	}
	sealer, err := openObjectSealer(dir, storage, len(names) > 0)
	if err != nil {
		return nil, err
	}
	store := &objectStore{
		dir:          dir,
		maxBytes:     maxBytes,
		segmentLimit: objectSegmentLimit,
		sealer:       sealer,
		index:        map[objectID]objectLocation{},
		segments:     map[uint32]*os.File{},
	}
	if err := store.loadSegments(names); err != nil {
		store.close()
		return nil, err
	}
	if len(names) == 0 {
		if err := store.newSegment(1); err != nil {
			store.close()
			return nil, err
		}
	}
	return store, nil
}

// segmentNames lists the segments under dir in number order. A file that does not parse as a
// segment name is somebody else's and is left alone.
func segmentNames(dir string) ([]uint32, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []uint32
	for _, entry := range entries {
		var number uint32
		if _, err := fmt.Sscanf(entry.Name(), "%08d"+objectSegmentExt, &number); err == nil && number > 0 {
			names = append(names, number)
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names, nil
}

func (store *objectStore) segmentPath(number uint32) string {
	return filepath.Join(store.dir, fmt.Sprintf("%08d%s", number, objectSegmentExt))
}

// loadSegments opens every segment and rebuilds the index from it. The last one becomes the tail.
func (store *objectStore) loadSegments(names []uint32) error {
	for i, number := range names {
		file, err := os.OpenFile(store.segmentPath(number), os.O_RDWR, objectFileMode)
		if err != nil {
			return err
		}
		store.segments[number] = file
		end, err := store.scanSegment(file, number)
		if err != nil {
			return fmt.Errorf("object segment %08d: %w", number, err)
		}
		if i == len(names)-1 {
			store.tailID, store.tailSize = number, end
		}
	}
	return nil
}

// newSegment creates the next segment, writes its banner, and makes BOTH the file and its directory
// entry durable before any record is allowed into it.
func (store *objectStore) newSegment(number uint32) error {
	path := store.segmentPath(number)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, objectFileMode)
	if err != nil {
		return fmt.Errorf("object segment %08d: %w", number, err)
	}
	if _, err := file.WriteString(objectSegmentMagic); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := syncDir(store.dir); err != nil {
		file.Close()
		return err
	}
	store.mutex.Lock()
	store.segments[number] = file
	store.tailID, store.tailSize = number, int64(len(objectSegmentMagic))
	store.mutex.Unlock()
	return nil
}

// put appends data unless its bytes are already held, and answers once the record is on the disk.
func (store *objectStore) put(data []byte) (objectReceipt, error) {
	if int64(len(data)) > store.maxBytes {
		return objectReceipt{}, fmt.Errorf("%w: %d bytes, the limit is %d", ErrObjectTooLarge, len(data), store.maxBytes)
	}
	id := objectID(blake3.Sum256(data))
	receipt := objectReceipt{ID: id.hex(), Size: int64(len(data))}

	store.appendMu.Lock()
	defer store.appendMu.Unlock()

	store.mutex.RLock()
	_, existed := store.index[id]
	store.mutex.RUnlock()
	if existed {
		receipt.Existed = true
		return receipt, nil
	}

	payload, flag, err := store.encode(id, data)
	if err != nil {
		return objectReceipt{}, err
	}
	location, err := store.appendRecord(id, flag, payload)
	if err != nil {
		return objectReceipt{}, err
	}
	store.mutex.Lock()
	store.index[id] = location
	store.mutex.Unlock()
	return receipt, nil
}

// encode is the payload a record carries for data: the bytes themselves, or their sealing.
func (store *objectStore) encode(id objectID, data []byte) ([]byte, byte, error) {
	if store.sealer == nil {
		return data, objectPlain, nil
	}
	sealed, err := store.sealer.seal(id, data)
	if err != nil {
		return nil, 0, fmt.Errorf("object sealing refused: %w", err)
	}
	return sealed, objectSealed, nil
}

// appendRecord writes one record to the tail and syncs it. A write that fails part-way is cut back
// to where the tail was, so a live process never leaves a half-record for the next open to find.
func (store *objectStore) appendRecord(id objectID, flag byte, payload []byte) (objectLocation, error) {
	recordLen := int64(objectHeaderSize) + int64(len(payload)) + objectTrailerSize
	if store.tailSize > int64(len(objectSegmentMagic)) && store.tailSize+recordLen > store.segmentLimit {
		if err := store.newSegment(store.tailID + 1); err != nil {
			return objectLocation{}, err
		}
	}
	tail := store.segments[store.tailID]
	start := store.tailSize

	header := encodeObjectHeader(id, flag, int64(len(payload)))
	crc := crc32.Update(crc32.Checksum(header, objectCRCTable), objectCRCTable, payload)
	trailer := binary.LittleEndian.AppendUint32(nil, crc)

	if err := writeAllAt(tail, start, header, payload, trailer); err != nil {
		_ = tail.Truncate(start)
		return objectLocation{}, fmt.Errorf("object append: %w", err)
	}
	if err := tail.Sync(); err != nil {
		_ = tail.Truncate(start)
		return objectLocation{}, fmt.Errorf("object append: %w", err)
	}
	store.tailSize = start + recordLen
	return objectLocation{segment: store.tailID, offset: start + objectHeaderSize, length: int64(len(payload))}, nil
}

func encodeObjectHeader(id objectID, flag byte, length int64) []byte {
	header := make([]byte, 0, objectHeaderSize)
	header = append(header, id[:]...)
	header = append(header, flag)
	return binary.LittleEndian.AppendUint64(header, uint64(length))
}

// writeAllAt writes the parts back to back from offset, with WriteAt rather than Write so the position
// is the one the index will record and not whatever the descriptor's cursor happens to be.
func writeAllAt(file *os.File, offset int64, parts ...[]byte) error {
	for _, part := range parts {
		if _, err := file.WriteAt(part, offset); err != nil {
			return err
		}
		offset += int64(len(part))
	}
	return nil
}

// get answers the bytes an id names, VERIFIED: the payload is re-hashed and must match the id.
func (store *objectStore) get(id objectID) ([]byte, error) {
	location, file, err := store.locate(id)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, location.length)
	if _, err := file.ReadAt(payload, location.offset); err != nil {
		return nil, fmt.Errorf("object %s: %w", id.hex(), err)
	}
	data := payload
	if store.sealer != nil {
		if data, err = store.sealer.open(id, payload); err != nil {
			return nil, fmt.Errorf("object %s: %w", id.hex(), ErrObjectCorrupt)
		}
	}
	if blake3.Sum256(data) != [objectIDSize]byte(id) {
		return nil, fmt.Errorf("object %s: %w", id.hex(), ErrObjectCorrupt)
	}
	return data, nil
}

// stat answers the PLAINTEXT size of an object without reading it. It is for HEAD, which asks whether
// the object is there and how big it is; integrity is a question for get.
func (store *objectStore) stat(id objectID) (int64, error) {
	location, _, err := store.locate(id)
	if err != nil {
		return 0, err
	}
	if store.sealer != nil {
		return location.length - objectSealedOverhead, nil
	}
	return location.length, nil
}

// locate finds a record in the index and the segment it is in, under the shared hold.
func (store *objectStore) locate(id objectID) (objectLocation, *os.File, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	location, ok := store.index[id]
	if !ok {
		return objectLocation{}, nil, fmt.Errorf("object %s: %w", id.hex(), ErrObjectNotFound)
	}
	if location.corrupt {
		return objectLocation{}, nil, fmt.Errorf("object %s: %w", id.hex(), ErrObjectCorrupt)
	}
	return location, store.segments[location.segment], nil
}

// count is how many readable objects the index holds.
func (store *objectStore) count() int {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	return len(store.index)
}

// close releases every segment handle. The log needs nothing written at close: every acknowledged
// record is already on the disk.
func (store *objectStore) close() {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for number, file := range store.segments {
		_ = file.Close()
		delete(store.segments, number)
	}
	if store.sealer != nil {
		clear(store.sealer.master)
	}
}
