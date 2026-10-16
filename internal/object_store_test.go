// Written by Richard Christopher, Copyright 2026 Richard Christopher
package internal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lukechampine.com/blake3"
)

// The object log on its own: what it keeps, what it refuses, and what it does with a disk that a
// crash or rot has touched. Nothing here involves a server or the forest.

func openTestStore(t *testing.T, dir string, maxBytes int64) *objectStore {
	t.Helper()
	store, err := openObjectStore(dir, maxBytes, nil)
	if err != nil {
		t.Fatalf("openObjectStore: %v", err)
	}
	t.Cleanup(store.close)
	return store
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func mustPut(t *testing.T, store *objectStore, data []byte) objectReceipt {
	t.Helper()
	receipt, err := store.put(data)
	if err != nil {
		t.Fatalf("put %d bytes: %v", len(data), err)
	}
	return receipt
}

func mustGet(t *testing.T, store *objectStore, id string, want []byte) {
	t.Helper()
	parsed, err := parseObjectID(id)
	if err != nil {
		t.Fatalf("parseObjectID(%q): %v", id, err)
	}
	got, err := store.get(parsed)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("get %s: %d bytes back, want %d and the same bytes", id, len(got), len(want))
	}
}

// The id is the BLAKE3 of the bytes, a second put of the same bytes is a no-op that says so, an
// object past the attachment cap is ordinary here, and a reopen rebuilds the index from the segments.
func TestObjectStoreRoundTripDedupAndReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "stock.objects")
	store := openTestStore(t, dir, DefaultMaxObjectBytes)

	small := []byte("the history belongs where history is appended")
	large := randomBytes(t, 11<<20) // past core.MaxAttachmentSize on purpose
	empty := []byte{}

	first := mustPut(t, store, small)
	if sum := blake3.Sum256(small); first.ID != objectID(sum).hex() {
		t.Fatalf("id %s is not the BLAKE3 of the bytes", first.ID)
	}
	if first.Existed || first.Size != int64(len(small)) {
		t.Fatalf("first put: %+v", first)
	}
	again := mustPut(t, store, small)
	if !again.Existed || again.ID != first.ID {
		t.Fatalf("second put of the same bytes: %+v, want existed with id %s", again, first.ID)
	}
	big := mustPut(t, store, large)
	nothing := mustPut(t, store, empty)
	if store.count() != 3 {
		t.Fatalf("count = %d, want 3", store.count())
	}
	mustGet(t, store, first.ID, small)
	mustGet(t, store, big.ID, large)
	mustGet(t, store, nothing.ID, empty)

	store.close()
	reopened := openTestStore(t, dir, DefaultMaxObjectBytes)
	if reopened.count() != 3 || len(reopened.repairs) != 0 {
		t.Fatalf("after reopen: count %d, repairs %v", reopened.count(), reopened.repairs)
	}
	mustGet(t, reopened, first.ID, small)
	mustGet(t, reopened, big.ID, large)
	mustGet(t, reopened, nothing.ID, empty)
	if dup := mustPut(t, reopened, large); !dup.Existed {
		t.Fatalf("the reopened store appended bytes it already held")
	}
}

// A torn tail — a record the crash did not finish — is cut off on open, and every record before it
// is intact. Both shapes of tear: a short record, and a tail of zeros.
func TestObjectStoreCutsATornTail(t *testing.T) {
	for name, tear := range map[string][]byte{
		"short record": append(encodeObjectHeader(objectID{1, 2, 3}, objectPlain, 4096), make([]byte, 100)...),
		"zero fill":    make([]byte, 8192),
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "stock.objects")
			store := openTestStore(t, dir, DefaultMaxObjectBytes)
			one := mustPut(t, store, []byte("one"))
			two := mustPut(t, store, randomBytes(t, 70000))
			segment := store.segmentPath(store.tailID)
			whole := store.tailSize
			store.close()

			file, err := os.OpenFile(segment, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(tear); err != nil {
				t.Fatal(err)
			}
			file.Close()

			reopened := openTestStore(t, dir, DefaultMaxObjectBytes)
			if len(reopened.repairs) != 1 {
				t.Fatalf("repairs = %v, want exactly the tail cut", reopened.repairs)
			}
			if info, _ := os.Stat(segment); info.Size() != whole {
				t.Fatalf("segment is %d bytes after repair, want %d", info.Size(), whole)
			}
			if reopened.count() != 2 {
				t.Fatalf("count = %d after repair, want 2", reopened.count())
			}
			mustGet(t, reopened, one.ID, []byte("one"))
			if _, err := reopened.stat(mustParse(t, two.ID)); err != nil {
				t.Fatalf("stat two: %v", err)
			}
			three := mustPut(t, reopened, []byte("three"))
			mustGet(t, reopened, three.ID, []byte("three"))
		})
	}
}

func mustParse(t *testing.T, id string) objectID {
	t.Helper()
	parsed, err := parseObjectID(id)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// A record that was acknowledged and has since changed is served as CORRUPT, by name — and the
// records around it are served as before. One case is caught on open by the CRC; the other is a
// payload altered under a live store, caught on read by the hash.
func TestObjectStoreReportsCorruptionAndServesTheRest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "stock.objects")
	store := openTestStore(t, dir, DefaultMaxObjectBytes)
	first := mustPut(t, store, []byte("first object"))
	second := mustPut(t, store, randomBytes(t, 5000))
	third := mustPut(t, store, []byte("third object"))
	firstAt := store.index[mustParse(t, first.ID)]
	secondAt := store.index[mustParse(t, second.ID)]
	segment := store.segmentPath(store.tailID)

	// Flip a byte in the second record's payload with the store live: the index still says it is
	// whole, so only the read's re-hash can refuse it.
	flipByte(t, segment, secondAt.offset+10)
	if _, err := store.get(mustParse(t, second.ID)); !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("get of an altered object: %v, want ErrObjectCorrupt", err)
	}
	mustGet(t, store, third.ID, []byte("third object"))
	store.close()

	// Flip a byte in the first record too, then reopen: the CRC catches both, and neither is the
	// tail, so nothing is cut and the third object is still served.
	flipByte(t, segment, firstAt.offset+3)
	reopened := openTestStore(t, dir, DefaultMaxObjectBytes)
	if len(reopened.repairs) != 2 {
		t.Fatalf("repairs = %v, want two corrupt records named", reopened.repairs)
	}
	for _, id := range []string{first.ID, second.ID} {
		if _, err := reopened.get(mustParse(t, id)); !errors.Is(err, ErrObjectCorrupt) {
			t.Fatalf("get %s after reopen: %v, want ErrObjectCorrupt", id, err)
		}
		if _, err := reopened.stat(mustParse(t, id)); !errors.Is(err, ErrObjectCorrupt) {
			t.Fatalf("stat %s after reopen: %v, want ErrObjectCorrupt", id, err)
		}
	}
	mustGet(t, reopened, third.ID, []byte("third object"))
	if _, err := reopened.get(objectID{0xff}); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("get of an unknown id: %v, want ErrObjectNotFound", err)
	}
}

func flipByte(t *testing.T, path string, offset int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	one := make([]byte, 1)
	if _, err := file.ReadAt(one, offset); err != nil {
		t.Fatal(err)
	}
	one[0] ^= 0xff
	if _, err := file.WriteAt(one, offset); err != nil {
		t.Fatal(err)
	}
}

// The cap is the store's, it is named in the refusal, and an object exactly at it is accepted. A
// segment rolls over when the next record would carry it past the segment limit, and the objects
// on both sides of the roll are found after a reopen.
func TestObjectStoreCapAndSegmentRollover(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "stock.objects")
	store := openTestStore(t, dir, 1024)
	store.segmentLimit = 2048

	if _, err := store.put(randomBytes(t, 1025)); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("put over the cap: %v, want ErrObjectTooLarge", err)
	}
	var ids []objectReceipt
	for i := 0; i < 5; i++ {
		ids = append(ids, mustPut(t, store, randomBytes(t, 1024)))
	}
	names, err := segmentNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 3 {
		t.Fatalf("segments = %v, want the log to have rolled over at least twice", names)
	}
	store.close()

	reopened := openTestStore(t, dir, 1024)
	if reopened.count() != 5 || reopened.tailID != names[len(names)-1] {
		t.Fatalf("after reopen: count %d, tail %d, want 5 and %d", reopened.count(), reopened.tailID, names[len(names)-1])
	}
	for i, receipt := range ids {
		if _, err := reopened.stat(mustParse(t, receipt.ID)); err != nil {
			t.Fatalf("object %d after rollover and reopen: %v", i, err)
		}
	}
}

// An id arrives as text, and only one spelling of it is an id.
func TestParseObjectIDAcceptsOneSpelling(t *testing.T) {
	good := objectID(blake3.Sum256([]byte("x"))).hex()
	if _, err := parseObjectID(good); err != nil {
		t.Fatalf("a lowercase hex id was refused: %v", err)
	}
	for _, bad := range []string{"", good[:63], good + "0", "G" + good[1:], "0X" + good[2:]} {
		if _, err := parseObjectID(bad); !errors.Is(err, ErrInvalidObjectID) {
			t.Fatalf("parseObjectID(%q): %v, want ErrInvalidObjectID", bad, err)
		}
	}
}
